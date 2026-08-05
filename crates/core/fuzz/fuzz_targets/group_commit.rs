//! Fuzzes `Commit`/`Welcome` byte parsing and, when a `Commit` happens to
//! parse successfully, feeds it into `Group::apply_commit` against a
//! real, freshly created single-member group — covering not just the
//! wire format but the tree/resolution logic a well-formed-but-bogus
//! commit could still reach.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::group::{Commit, Group, Welcome};
use novachannel::identity::Identity;

fuzz_target!(|data: &[u8]| {
    let _ = Welcome::from_bytes(data);

    let Ok(commit) = Commit::from_bytes(data) else {
        return;
    };

    let founder_id = Identity::generate();
    let Ok(mut group) = Group::create(&founder_id, 4) else {
        return;
    };
    let _ = group.apply_commit(&commit);
});
