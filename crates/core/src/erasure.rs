//! A thin systematic wrapper around [`reed_solomon_simd`] for
//! [`crate::ratchet`]'s incremental step: split a payload into `data_shards`
//! chunks plus `parity_shards` redundant ones, so that *any* `data_shards`
//! of the total (any combination, not just the first to arrive) rebuild the
//! original bytes exactly.
//!
//! # Why a crate, not hand-rolled GF(256)
//! This module used to hand-roll a Cauchy-matrix Reed-Solomon code over
//! GF(256) (log tables, Gauss-Jordan elimination). The algorithm is
//! textbook, but hand-written code still has its own bug surface (matrix
//! inversion, field arithmetic) that a maintained implementation has
//! already retired. [`reed_solomon_simd`] implements Leopard-RS (FFT-based,
//! O(n log n), widely used in loss-tolerant data distribution) and, per this
//! workspace's `cargo audit` gate, adds two small dependencies with no
//! advisories. The first candidate, `reed-solomon-erasure`, is mature but
//! hard-pins an `lru` version flagged as RUSTSEC-2026-0253.
//!
//! # Untrusted input
//! [`reed_solomon_simd`] `assert!`-panics on an odd `shard_bytes` instead of
//! returning an error. [`encode`] picks the length itself, but `decode` sees
//! lengths implied by peer data, so [`decode`] rejects odd lengths as
//! `Malformed` before calling the crate: a malformed message fails cleanly
//! instead of panicking.
//!
//! # What this is not
//! This reconstructs *missing* shards (erasure); it does not detect or fix
//! *corrupted* ones (error correction, a different problem). Corruption is
//! caught by `crate::ratchet`'s checksum over the reconstructed payload, and
//! beneath that by every chunk being an AEAD-sealed ratchet record.

use crate::error::{Error, Result};

fn check_shard_counts(data_shards: usize, parity_shards: usize) -> Result<()> {
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 255 {
        Err(Error::Malformed("invalid erasure-coding shard counts"))
    } else {
        Ok(())
    }
}

/// Splits `payload` into `data_shards` equal chunks (zero-padded to a common
/// length) plus `parity_shards` redundant chunks, returning all shards in
/// order and the shard length.
pub fn encode(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Vec<Vec<u8>>, usize)> {
    check_shard_counts(data_shards, parity_shards)?;
    // Rounded up to even, since reed_solomon_simd requires it and this module
    // chooses the length.
    let mut shard_len = payload.len().div_ceil(data_shards).max(1);
    if !shard_len.is_multiple_of(2) {
        shard_len += 1;
    }

    let mut data: Vec<Vec<u8>> = Vec::with_capacity(data_shards);
    for i in 0..data_shards {
        let start = i * shard_len;
        let mut shard = vec![0u8; shard_len];
        if start < payload.len() {
            let end = (start + shard_len).min(payload.len());
            shard[..end - start].copy_from_slice(&payload[start..end]);
        }
        data.push(shard);
    }

    let parity = reed_solomon_simd::encode(data_shards, parity_shards, &data)
        .map_err(|_| Error::Malformed("erasure encoding failed"))?;

    let mut shards = data;
    shards.extend(parity);
    Ok((shards, shard_len))
}

/// Reconstructs the payload (still zero-padded to `shard_len`; the caller
/// truncates) from the shards present. Needs at least `data_shards` of the
/// `data_shards + parity_shards` entries to be `Some`, all equal length.
pub fn decode(
    shards: &[Option<Vec<u8>>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>> {
    check_shard_counts(data_shards, parity_shards)?;
    if shards.len() != data_shards + parity_shards {
        return Err(Error::Malformed("wrong number of erasure-coded shards"));
    }

    let present_count = shards.iter().filter(|s| s.is_some()).count();
    if present_count < data_shards {
        return Err(Error::Malformed("too few shards to reconstruct"));
    }

    let mut shard_len = None;
    for shard in shards.iter().flatten() {
        match shard_len {
            None => shard_len = Some(shard.len()),
            Some(len) if len != shard.len() => {
                return Err(Error::Malformed(
                    "erasure-coded shards have inconsistent length",
                ));
            }
            _ => {}
        }
    }
    let shard_len = shard_len.expect("present_count >= data_shards >= 1");
    // A peer-supplied shard length, not one this module picked -- reject
    // rather than let reed_solomon_simd's internal `assert!` panic on it.
    if !shard_len.is_multiple_of(2) {
        return Err(Error::Malformed("erasure-coded shard length must be even"));
    }

    if shards[..data_shards].iter().all(Option::is_some) {
        // The common case (no losses at all): every data shard is
        // present, no FFT work needed.
        let mut out = Vec::with_capacity(data_shards * shard_len);
        for shard in &shards[..data_shards] {
            out.extend_from_slice(shard.as_ref().expect("checked all Some above"));
        }
        return Ok(out);
    }

    let original_present = shards[..data_shards]
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|shard| (i, shard)));
    let recovery_present = shards[data_shards..]
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|shard| (i, shard)));

    let restored = reed_solomon_simd::decode(
        data_shards,
        parity_shards,
        original_present,
        recovery_present,
    )
    .map_err(|_| Error::Malformed("erasure reconstruction failed"))?;

    let mut out = Vec::with_capacity(data_shards * shard_len);
    for (i, shard) in shards[..data_shards].iter().enumerate() {
        match shard {
            Some(shard) => out.extend_from_slice(shard),
            None => out.extend_from_slice(restored.get(&i).ok_or(Error::Malformed(
                "erasure reconstruction did not restore shard",
            ))?),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_losses_round_trips_exactly() {
        let payload = b"a message that needs several shards to carry it end to end";
        let (shards, _len) = encode(payload, 5, 2).unwrap();
        let present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let recovered = decode(&present, 5, 2).unwrap();
        assert_eq!(&recovered[..payload.len()], payload);
    }

    #[test]
    fn any_k_of_n_shards_reconstruct_exactly() {
        let payload = b"exercise every combination of surviving shards, not just one";
        let (data_shards, parity_shards) = (4, 3);
        let (shards, _len) = encode(payload, data_shards, parity_shards).unwrap();
        let total = data_shards + parity_shards;

        // Every combination of exactly `data_shards` surviving indices out of
        // `total`, not just one fixed loss pattern.
        for mask in 0u32..(1 << total) {
            if (mask.count_ones() as usize) != data_shards {
                continue;
            }
            let present: Vec<Option<Vec<u8>>> = (0..total)
                .map(|i| {
                    if mask & (1 << i) != 0 {
                        Some(shards[i].clone())
                    } else {
                        None
                    }
                })
                .collect();
            let recovered = decode(&present, data_shards, parity_shards).unwrap();
            assert_eq!(&recovered[..payload.len()], payload, "mask={mask:#x}");
        }
    }

    #[test]
    fn fewer_than_data_shards_present_fails_cleanly() {
        let (shards, _len) = encode(b"short", 5, 2).unwrap();
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        // Drop 3 of 7 -- only 4 remain, one short of the 5 needed.
        present[0] = None;
        present[1] = None;
        present[2] = None;
        assert!(matches!(
            decode(&present, 5, 2),
            Err(Error::Malformed("too few shards to reconstruct"))
        ));
    }

    #[test]
    fn inconsistent_shard_lengths_are_rejected() {
        let (mut shards, _len) = encode(b"abcdef", 3, 1).unwrap();
        shards[0].push(0xFF);
        shards[0].push(0xFF); // keep it even, so the length check (not the parity check) is what fires
        let present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        assert!(matches!(
            decode(&present, 3, 1),
            Err(Error::Malformed(
                "erasure-coded shards have inconsistent length"
            ))
        ));
    }

    #[test]
    fn odd_shard_length_is_rejected_without_panicking() {
        let (mut shards, _len) = encode(b"abcdef", 3, 1).unwrap();
        for shard in &mut shards {
            shard.push(0xFF); // now every shard is odd-length
        }
        let present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        assert!(matches!(
            decode(&present, 3, 1),
            Err(Error::Malformed("erasure-coded shard length must be even"))
        ));
    }

    #[test]
    fn zero_data_or_parity_shards_is_rejected() {
        assert!(encode(b"x", 0, 1).is_err());
        assert!(encode(b"x", 1, 0).is_err());
    }

    #[test]
    fn wrong_shard_count_passed_to_decode_is_rejected() {
        let (shards, _len) = encode(b"x", 3, 1).unwrap();
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        present.push(None); // now 5 entries for a (3,1) config that expects 4
        assert!(matches!(
            decode(&present, 3, 1),
            Err(Error::Malformed("wrong number of erasure-coded shards"))
        ));
    }
}
