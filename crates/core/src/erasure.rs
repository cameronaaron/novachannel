//! A small, from-scratch systematic Reed–Solomon-style erasure code over
//! GF(2^8), built specifically for [`crate::ratchet`]'s incremental
//! ratchet step: split one payload into `data_shards` chunks plus
//! `parity_shards` redundant chunks, such that *any* `data_shards` of the
//! resulting `data_shards + parity_shards` chunks (in any combination, not
//! just "the first N to arrive") are enough to reconstruct the original
//! bytes exactly.
//!
//! # Why Cauchy, not a generic Vandermonde matrix
//! The parity rows are built from a Cauchy matrix
//! (`entry[i][j] = 1 / (x_i XOR y_j)` over GF(256), with `{x_i}` and
//! `{y_j}` disjoint) rather than the more commonly seen Vandermonde
//! construction — the same choice, for the same reason, this workspace
//! already made for `novachannel-rln`'s MDS matrix
//! (`crates/rln/src/permutation.rs`): a Cauchy matrix's *every* square
//! submatrix is invertible by a direct algebraic argument, so "any
//! `data_shards` of the shards suffice" follows from the construction
//! itself rather than needing to be checked case by case. It's still
//! checked directly anyway (§0.5's "validate the instrument" standard) —
//! `tests::any_k_of_n_shards_reconstruct_exactly` tries every combination
//! for a small `(data_shards, parity_shards)` pair, not just one.
//!
//! # What this is not
//! This is a correctness-focused, unoptimized implementation (GF(256)
//! multiplication via log/antilog tables rebuilt on every call, Gauss–
//! Jordan elimination on a `data_shards`×`data_shards` matrix) sized for
//! the tiny payloads (~1-2 KB) a KEX handshake message needs — not a
//! general-purpose or performance-competitive erasure-coding library.
//! This module does not detect or correct *corruption* of a present
//! shard, only reconstructs from *known-missing* ones — the two are
//! different problems ("erasure" vs. "error") with different solutions;
//! corruption of a shard that *arrives* is instead caught by
//! `crate::ratchet`'s checksum over the reconstructed payload, and,
//! beneath that, by the fact that every chunk is itself an AEAD-sealed
//! ratchet record before it ever reaches this module.

use crate::error::{Error, Result};

/// log/antilog tables for GF(2^8) under the primitive polynomial
/// `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`) and generator `2` — the same
/// field and generator used by, e.g., QR codes' Reed–Solomon coding.
/// Rebuilt fresh per call rather than cached: 256 iterations is a
/// negligible cost next to the ML-KEM-1024 handshake material this module
/// exists to chunk, and it avoids reaching for `std::sync::OnceLock` for
/// a workspace-wide singleton to save microseconds nothing here is
/// sensitive to.
struct Gf256 {
    exp: [u8; 512],
    log: [u8; 256],
}

const GF256_POLY: u16 = 0x11D;

impl Gf256 {
    fn build() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF256_POLY;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        Gf256 { exp, log }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let sum = self.log[a as usize] as usize + self.log[b as usize] as usize;
        self.exp[sum]
    }

    /// `a` must be nonzero — every caller in this module only ever
    /// inverts a Cauchy-matrix entry (nonzero by construction, since its
    /// two index sets are disjoint) or a Gauss-Jordan pivot (selected
    /// specifically for being nonzero).
    fn inv(&self, a: u8) -> u8 {
        debug_assert_ne!(a, 0, "inv(0) is undefined in GF(256)");
        self.exp[255 - self.log[a as usize] as usize]
    }
}

/// Row `shard_idx` of the (`data_shards+parity_shards`) x `data_shards`
/// systematic generator matrix: the identity for `shard_idx <
/// data_shards`, a Cauchy row otherwise. `y`-set is `1..=data_shards`,
/// `x`-set is `data_shards+1..=data_shards+parity_shards` — disjoint by
/// construction (every `x` exceeds every `y`), which is exactly what
/// makes every entry `1/(x XOR y)` well-defined and every square
/// submatrix of the resulting generator invertible.
fn generator_row(gf: &Gf256, data_shards: usize, shard_idx: usize) -> Vec<u8> {
    let mut row = vec![0u8; data_shards];
    if shard_idx < data_shards {
        row[shard_idx] = 1;
    } else {
        let parity_index = shard_idx - data_shards;
        let x = (data_shards + parity_index + 1) as u8;
        for (j, slot) in row.iter_mut().enumerate() {
            let y = (j + 1) as u8;
            *slot = gf.inv(x ^ y);
        }
    }
    row
}

fn check_shard_counts(data_shards: usize, parity_shards: usize) -> Result<()> {
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > 255 {
        Err(Error::Malformed("invalid erasure-coding shard counts"))
    } else {
        Ok(())
    }
}

/// A `k`x`k` matrix over GF(256), row-major.
struct Matrix {
    k: usize,
    data: Vec<u8>,
}

impl Matrix {
    fn get(&self, r: usize, c: usize) -> u8 {
        self.data[r * self.k + c]
    }
    fn set(&mut self, r: usize, c: usize, v: u8) {
        self.data[r * self.k + c] = v;
    }
}

/// Gauss-Jordan elimination over GF(256). Every matrix this module
/// inverts is a submatrix of a Cauchy-based generator matrix, which is
/// invertible by construction (module docs) — a `Malformed` here would
/// mean a caller passed a shard-index combination that isn't actually a
/// submatrix of that generator, which the callers in this module never
/// do, but the check stays a real `Result` rather than an `.expect()`
/// since inversion has a genuine failure mode (a singular matrix) that a
/// pure GF(256) construction argument doesn't fully rule out for
/// hand-written, non-formally-verified code — the same "don't trust an
/// algebraic argument over its own test" instinct
/// `ENGINEERING-STANDARDS.md` §0.5 already applies elsewhere.
fn invert(gf: &Gf256, m: &Matrix) -> Result<Matrix> {
    let k = m.k;
    let mut a = m.data.clone();
    let mut inv = vec![0u8; k * k];
    for (i, slot) in inv.iter_mut().enumerate().take(k * k) {
        if i % k == i / k {
            *slot = 1;
        }
    }

    for col in 0..k {
        let pivot_row = (col..k)
            .find(|&r| a[r * k + col] != 0)
            .ok_or(Error::Malformed("erasure matrix is singular"))?;
        if pivot_row != col {
            for c in 0..k {
                a.swap(col * k + c, pivot_row * k + c);
                inv.swap(col * k + c, pivot_row * k + c);
            }
        }
        let pivot_inv = gf.inv(a[col * k + col]);
        for c in 0..k {
            a[col * k + c] = gf.mul(a[col * k + c], pivot_inv);
            inv[col * k + c] = gf.mul(inv[col * k + c], pivot_inv);
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = a[r * k + col];
            if factor == 0 {
                continue;
            }
            for c in 0..k {
                a[r * k + c] ^= gf.mul(factor, a[col * k + c]);
                inv[r * k + c] ^= gf.mul(factor, inv[col * k + c]);
            }
        }
    }
    Ok(Matrix { k, data: inv })
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
    let shard_len = payload.len().div_ceil(data_shards).max(1);

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

    let gf = Gf256::build();
    let mut shards = data.clone();
    for p in 0..parity_shards {
        let row = generator_row(&gf, data_shards, data_shards + p);
        let mut parity_shard = vec![0u8; shard_len];
        for (byte_pos, out_byte) in parity_shard.iter_mut().enumerate() {
            let mut acc = 0u8;
            for (j, coeff) in row.iter().enumerate() {
                acc ^= gf.mul(*coeff, data[j][byte_pos]);
            }
            *out_byte = acc;
        }
        shards.push(parity_shard);
    }
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

    let present: Vec<usize> = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|_| i))
        .collect();
    if present.len() < data_shards {
        return Err(Error::Malformed("too few shards to reconstruct"));
    }

    let shard_len = shards[present[0]]
        .as_ref()
        .expect("index came from a Some entry")
        .len();
    for &i in &present {
        let len = shards[i]
            .as_ref()
            .expect("index came from a Some entry")
            .len();
        if len != shard_len {
            return Err(Error::Malformed(
                "erasure-coded shards have inconsistent length",
            ));
        }
    }

    let chosen: Vec<usize> = present.into_iter().take(data_shards).collect();
    if chosen.iter().enumerate().all(|(i, &c)| i == c) {
        // The common case (no losses at all): the first `data_shards`
        // shards received are exactly the original data shards in order,
        // no matrix work needed.
        let mut out = Vec::with_capacity(data_shards * shard_len);
        for &i in &chosen {
            out.extend_from_slice(shards[i].as_ref().expect("index came from a Some entry"));
        }
        return Ok(out);
    }

    let gf = Gf256::build();
    let mut m = Matrix {
        k: data_shards,
        data: vec![0u8; data_shards * data_shards],
    };
    for (row_idx, &shard_idx) in chosen.iter().enumerate() {
        let row = generator_row(&gf, data_shards, shard_idx);
        for (c, coeff) in row.into_iter().enumerate() {
            m.set(row_idx, c, coeff);
        }
    }
    let inv = invert(&gf, &m)?;

    let mut out = vec![0u8; data_shards * shard_len];
    for byte_pos in 0..shard_len {
        let received: Vec<u8> = chosen
            .iter()
            .map(|&i| shards[i].as_ref().expect("index came from a Some entry")[byte_pos])
            .collect();
        for j in 0..data_shards {
            let mut acc = 0u8;
            for (i, &r) in received.iter().enumerate() {
                acc ^= gf.mul(inv.get(j, i), r);
            }
            out[j * shard_len + byte_pos] = acc;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_cycles_through_all_255_nonzero_elements() {
        let gf = Gf256::build();
        // exp[0..255] must be a permutation of 1..=255 (every nonzero
        // element reached exactly once) -- if the primitive polynomial or
        // generator were wrong, the cycle would be shorter and some
        // elements would repeat before index 255.
        let mut seen = [false; 256];
        for i in 0..255 {
            let v = gf.exp[i] as usize;
            assert!(v != 0);
            assert!(!seen[v], "element {v} repeated before a full cycle");
            seen[v] = true;
        }
        assert_eq!(gf.exp[255], gf.exp[0], "table must repeat after index 255");
    }

    #[test]
    fn every_nonzero_element_times_its_inverse_is_one() {
        let gf = Gf256::build();
        for a in 1..=255u8 {
            assert_eq!(gf.mul(a, gf.inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn multiplication_is_commutative_and_distributes_over_xor() {
        let gf = Gf256::build();
        for a in [1u8, 3, 7, 200, 255] {
            for b in [1u8, 3, 7, 200, 255] {
                assert_eq!(gf.mul(a, b), gf.mul(b, a));
            }
        }
        let (a, b, c) = (5u8, 9u8, 200u8);
        assert_eq!(gf.mul(a, b ^ c), gf.mul(a, b) ^ gf.mul(a, c));
    }

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
        let present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        assert!(matches!(
            decode(&present, 3, 1),
            Err(Error::Malformed(
                "erasure-coded shards have inconsistent length"
            ))
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
