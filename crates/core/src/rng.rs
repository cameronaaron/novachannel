//! A single, explicit CSPRNG source shared by every key-generation call in
//! this crate, rather than each caller reaching for its own default.
//!
//! `ed25519-dalek`, `x25519-dalek`, `ml-kem`, and `ml-dsa` all migrated to
//! `rand_core` 0.10 together, which no longer ships an `OsRng` type directly
//! — the ecosystem's replacement is `getrandom`'s own `SysRng`, wrapped in
//! `UnwrapErr` to present it as the infallible `CryptoRng` these APIs
//! expect (the OS random source can fail in principle; `UnwrapErr` panics
//! rather than silently falling back to a weaker source, which is the
//! correct failure mode for key generation — proceeding on bad randomness
//! is far worse than crashing).

use getrandom::{rand_core::UnwrapErr, SysRng};

pub type Csprng = UnwrapErr<SysRng>;

pub fn csprng() -> Csprng {
    UnwrapErr(SysRng)
}
