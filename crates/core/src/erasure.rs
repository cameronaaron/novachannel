//! A thin, systematic wrapper around [`reed_solomon_simd`] for
//! [`crate::ratchet`]'s incremental ratchet step: split one payload into
//! `data_shards` chunks plus `parity_shards` redundant chunks, such that
//! *any* `data_shards` of the resulting `data_shards + parity_shards`
//! chunks (in any combination, not just "the first N to arrive") are
//! enough to reconstruct the original bytes exactly.
//!
//! # Why a crate, not a from-scratch GF(256) implementation
//! This module used to hand-roll its own Cauchy-matrix Reed-Solomon code
//! over GF(256) (log/antilog tables, Gauss-Jordan elimination). That's
//! fine as an *algorithm* — Reed-Solomon is decades-old, textbook math
//! with no novelty to get wrong in a way that matters here the way, say,
//! [`crate::rln`]'s from-scratch permutation would — but it is still
//! hand-written code with its own correctness surface (matrix inversion
//! bugs, GF arithmetic bugs) that a maintained implementation already
//! retired. [`reed_solomon_simd`] implements Leopard-RS (an
//! FFT-based, O(n log n) construction with a much larger track record of
//! production use in loss-tolerant data-distribution systems than a
//! module-local Cauchy matrix could ever get) and, checked against this
//! workspace's own `cargo audit` gate, pulls in only two small,
//! cleanly-audited dependencies — no transitive advisories at all, unlike
//! the alternative `reed-solomon-erasure` crate this module considered
//! first (mature and widely used, but its `Cargo.toml` hard-pins a
//! `lru` version cargo audit flags for RUSTSEC-2026-0253).
//!
//! # Untrusted-input handling
//! [`reed_solomon_simd`]'s encoder/decoder `assert!`-panics if handed an
//! odd `shard_bytes` length rather than returning a `Result` — fine for
//! `encode` below, where this module picks the shard length itself, but
//! `decode` runs on shard lengths implied by whatever a peer sent over
//! the network. [`decode`] therefore rejects an odd shard length itself,
//! as a `Malformed` error, before ever calling into the crate — a
//! malformed peer message must fail cleanly here, not panic the process.
//!
//! # What this is not
//! This module does not detect or correct *corruption* of a present
//! shard, only reconstructs from *known-missing* ones — the two are
//! different problems ("erasure" vs. "error") with different solutions;
//! corruption of a shard that *arrives* is instead caught by
//! `crate::ratchet`'s checksum over the reconstructed payload, and,
//! beneath that, by the fact that every chunk is itself an AEAD-sealed
//! ratchet record before it ever reaches this module.

use crate::error::{Error, Result};

fn check_shard_counts(data_shards: usize, parity_shards: usize) -> Result<()> {
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 255 {
        Err(Error::Malformed("invalid erasure-coding shard counts"))
    } else {
        Ok(())
    }
}

/// Splits `payload` into `data_shards` equal-length chunks (zero-padded
/// to a common length if needed) plus `parity_shards` redundant chunks,
/// returning all `data_shards + parity_shards` shards in order and the
/// per-shard length used.
pub fn encode(
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Vec<Vec<u8>>, usize)> {
    check_shard_counts(data_shards, parity_shards)?;
    // Rounded up to even: reed_solomon_simd requires an even shard length,
    // and this module picks the length itself here, so it satisfies that
    // up front rather than working around it.
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

/// Reconstructs the original (still zero-padded-to-`shard_len`, caller
/// truncates to the real length) payload from whichever shards are
/// present. Requires at least `data_shards` of `shards`' `data_shards +
/// parity_shards` entries to be `Some`, all the same length.
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

        // Every combination of exactly `data_shards` surviving indices out
        // of `total` -- not just "drop the first parity_shards", which
        // would only ever exercise the fast (no-losses) path or a single
        // fixed pattern of losses.
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
