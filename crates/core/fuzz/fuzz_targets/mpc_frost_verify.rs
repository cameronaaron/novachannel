//! Fuzzes `novachannel_mpc::frost::verify` against attacker-controlled
//! byte encodings of a group public key, a signature's `R`/`z` components,
//! and the signed message — the actual untrusted-input boundary for this
//! crate. `novachannel-mpc` deliberately does no networking or wire
//! framing of its own (see its module docs), so a real deployment's own
//! transport layer is what decodes bytes off the wire into
//! `RistrettoPoint`/`Scalar` before ever calling `verify` — this fuzzes
//! exactly that decode-then-verify pipeline, the shape any such transport
//! layer would actually have.
#![no_main]

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use libfuzzer_sys::fuzz_target;
use novachannel_mpc::frost::{verify, Signature};

fn decode_point(bytes: &[u8]) -> Option<curve25519_dalek::ristretto::RistrettoPoint> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto(arr).decompress()
}

fn decode_scalar(bytes: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Scalar::from_canonical_bytes(arr).into_option()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let (gpk_bytes, rest) = data.split_at(32);
    let (r_bytes, rest) = rest.split_at(32);
    let (z_bytes, message) = rest.split_at(32);

    let Some(group_public_key) = decode_point(gpk_bytes) else {
        return;
    };
    let Some(r) = decode_point(r_bytes) else {
        return;
    };
    let Some(z) = decode_scalar(z_bytes) else {
        return;
    };

    let signature = Signature { r, z };
    let _ = verify(&signature, &group_public_key, message);
});
