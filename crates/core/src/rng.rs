//! One explicit CSPRNG source for every key generation in this crate.
//!
//! `ed25519-dalek`, `x25519-dalek`, `ml-kem` and `ml-dsa` moved to
//! `rand_core` 0.10, which no longer ships `OsRng`. Its replacement is
//! `getrandom`'s `SysRng` in `UnwrapErr`, presenting the infallible
//! `CryptoRng` those APIs expect. If the OS source fails, `UnwrapErr`
//! panics rather than falling back to anything weaker: for key generation,
//! crashing beats proceeding on bad randomness.

use getrandom::{rand_core::UnwrapErr, SysRng};

pub type Csprng = UnwrapErr<SysRng>;

pub fn csprng() -> Csprng {
    UnwrapErr(SysRng)
}
