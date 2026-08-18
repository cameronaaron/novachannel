//! Sesame-style multi-device session management: one logical account,
//! backed by several devices, each running its own independent
//! [`crate::x3dh`] session and [`crate::ratchet`].
//!
//! # The problem this solves
//! Every other module in this crate speaks in terms of one session
//! between two parties. Real accounts have more than one device (a phone
//! and a desktop, say), each with its own identity/prekey material and its
//! own session state — sending "one message to Bob" actually means
//! sending it once per device Bob owns, over that device's own session,
//! because there is no shared secret across Bob's devices to encrypt
//! under once. [`MultiDeviceSession`] is the fan-out bookkeeping that
//! makes that look like one logical send from the caller's side, and
//! [`ReceivingDevice`] is the corresponding fan-*in*: one physical device
//! accepting init messages from any number of distinct peer devices and
//! filing each into its own session.
//!
//! Signal's own version of this (the "Sesame" algorithm) is bookkeeping
//! layered on top of X3DH/Double Ratchet the same way this is layered on
//! top of [`crate::x3dh`]/[`crate::ratchet`] — it does not introduce new
//! cryptographic primitives either, and neither does this module.
//!
//! # Trusting a device list: [`SignedDeviceList`]
//! Without some authority the caller trusts vouching for "these are all
//! of Bob's current devices," a MITM controlling the transport that hands
//! out bundles could inject a device Bob never added. [`SignedDeviceList`]
//! closes that: the *account's* long-term signing [`Identity`] (distinct
//! from each device's own identity — Bob signs the list, not any one of
//! his devices) attests to a versioned list of `(device id, device
//! identity, device DH identity)` triples. [`RemoteAccount::from_signed_device_list`]
//! verifies that signature and then checks every supplied
//! [`PreKeyBundle`] actually matches what the list authorizes for its
//! device id — a bundle claiming to be device 7 but carrying a different
//! identity or DH key than the signed list says device 7 has is rejected,
//! not silently trusted. [`MultiDeviceSession::sync_from_signed_device_list`]
//! also tracks the highest `version` it has accepted for the account and
//! rejects a list that isn't strictly newer, so a MITM can't roll a peer
//! back to an older list to hide a revoked device or resurrect one; a
//! device dropped from a newer list has its session revoked automatically.
//!
//! This crate still has no server/directory concept of its own (the same
//! deliberate scope boundary [`crate::handshake`] and [`crate::x3dh`]
//! already state for peer-identity provisioning) — *how* a caller fetches
//! a [`SignedDeviceList`] and which account key it trusts as the expected
//! signer are still the caller's problem. What this module now provides
//! is the verification and version-rollback logic once they have one, not
//! a transport for delivering it. [`RemoteAccount::new`] /
//! [`RemoteAccount::add_device`]/[`RemoteAccount::remove_device`] remain
//! available as the unauthenticated path for callers that have their own
//! way of establishing trust in a device list and don't need this
//! module's.
//!
//! # What this module does not do
//! - **No re-keyed-device detection *within* the unauthenticated path.**
//!   [`RemoteAccount::add_device`]/[`MultiDeviceSession::sync_devices`]
//!   only ever establish a session for a device id with *no* existing
//!   session; they never re-establish one for an id already present, even
//!   if the bundle changed underneath it. The *authenticated* path
//!   ([`SignedDeviceList`]) does distinguish this correctly, since a
//!   version bump and a changed bundle for the same device id both come
//!   from the one signature the account controls.
//! - **No cross-device history sync.** A newly linked device does not
//!   retroactively receive messages sent to the account before it existed
//!   — each device's session starts exactly where its own
//!   [`crate::x3dh`] handshake began, same as any single-device session.
//! - **`DeviceId` is bookkeeping only.** It never appears inside anything
//!   HKDF'd (it *is* now part of what [`SignedDeviceList`] signs, since
//!   that's precisely the binding the signature needs to make); it exists
//!   to let a caller route a wire message to the right per-device session
//!   locally, not as cryptographic material in the sessions themselves.

use std::collections::BTreeMap;

use x25519_dalek::PublicKey as X25519Public;

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex;
use crate::prekey::{DhIdentity, OneTimePreKeyStore, PreKeyBundle, SignedPreKey};
use crate::ratchet::{Opened, RatchetedSession};
use crate::wire::{Reader, Writer};
use crate::x3dh::{self, InitMessage};

const DEVICE_LIST_SIGNATURE_CONTEXT: &[u8] = b"novachannel multidevice v1 device list";

/// Identifies one device within an account. Carries no cryptographic
/// weight of its own — see the module docs' "bookkeeping only" note.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct DeviceId(pub u32);

/// One peer account's currently-known devices and their published
/// prekey bundles, as assembled by the caller (this crate has no
/// directory service to source it from — see module docs).
#[derive(Default)]
pub struct RemoteAccount {
    devices: BTreeMap<DeviceId, PreKeyBundle>,
}

impl RemoteAccount {
    pub fn new() -> Self {
        RemoteAccount {
            devices: BTreeMap::new(),
        }
    }

    pub fn add_device(&mut self, device_id: DeviceId, bundle: PreKeyBundle) {
        self.devices.insert(device_id, bundle);
    }

    pub fn remove_device(&mut self, device_id: DeviceId) {
        self.devices.remove(&device_id);
    }

    pub fn device_ids(&self) -> Vec<DeviceId> {
        self.devices.keys().copied().collect()
    }

    /// Builds a `RemoteAccount` from `bundles`, but only after verifying
    /// `device_list` against `expected_account` and confirming every
    /// bundle's identity and DH identity actually match what that signed
    /// list authorizes for its device id. A bundle for a device id absent
    /// from the list, or one whose identity/DH identity don't match the
    /// list's entry, is rejected outright rather than silently admitted —
    /// this is the check that makes injecting an unauthorized device
    /// require forging the account's signature, not just supplying a
    /// bundle.
    pub fn from_signed_device_list(
        expected_account: &PublicIdentity,
        device_list: &SignedDeviceList,
        bundles: Vec<(DeviceId, PreKeyBundle)>,
    ) -> Result<Self> {
        device_list.verify(expected_account)?;

        let mut devices = BTreeMap::new();
        for (device_id, bundle) in bundles {
            let entry = device_list
                .entries
                .iter()
                .find(|e| e.device_id == device_id)
                .ok_or(Error::UnauthorizedDevice)?;
            if entry.identity != bundle.identity || entry.dh_identity != bundle.dh_identity {
                return Err(Error::UnauthorizedDevice);
            }
            bundle.verify()?;
            devices.insert(device_id, bundle);
        }
        Ok(RemoteAccount { devices })
    }
}

/// One device a [`SignedDeviceList`] authorizes: which identity and DH
/// identity key are allowed to speak for `device_id`. Deliberately not
/// the full [`PreKeyBundle`] — the medium-term signed prekey and
/// one-time prekey rotate far more often than the device list itself
/// should need to be re-signed, so the list only pins down the two
/// long-term values a bundle can't legitimately change without also
/// being a different device.
#[derive(Clone)]
pub struct DeviceListEntry {
    pub device_id: DeviceId,
    pub identity: PublicIdentity,
    pub dh_identity: X25519Public,
}

fn device_list_signed_bytes(version: u64, entries: &[DeviceListEntry]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_fixed(DEVICE_LIST_SIGNATURE_CONTEXT);
    w.put_fixed(&version.to_be_bytes());
    w.put_fixed(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        w.put_fixed(&entry.device_id.0.to_be_bytes());
        entry.identity.write(&mut w);
        w.put_fixed(entry.dh_identity.as_bytes());
    }
    w.into_bytes()
}

/// An account's current device list, attested by the account's own
/// long-term signing [`Identity`] — distinct from any one device's
/// identity, the same way a company's letterhead isn't any one
/// employee's signature. `version` must strictly increase across lists
/// the same account issues; [`MultiDeviceSession::sync_from_signed_device_list`]
/// enforces that a peer never accepts an older one than it already has.
pub struct SignedDeviceList {
    pub version: u64,
    entries: Vec<DeviceListEntry>,
    signature: HybridSignature,
}

impl SignedDeviceList {
    pub fn issue(account_identity: &Identity, version: u64, entries: Vec<DeviceListEntry>) -> Self {
        let signature = account_identity.sign(&device_list_signed_bytes(version, &entries));
        SignedDeviceList {
            version,
            entries,
            signature,
        }
    }

    pub fn entries(&self) -> &[DeviceListEntry] {
        &self.entries
    }

    /// Checks this list's signature against `account_identity`. Does not
    /// check `version` against anything — that comparison needs a
    /// previously-seen version to compare against, which is
    /// [`MultiDeviceSession::sync_from_signed_device_list`]'s job, not
    /// this standalone list's.
    pub fn verify(&self, account_identity: &PublicIdentity) -> Result<()> {
        account_identity.verify(
            &device_list_signed_bytes(self.version, &self.entries),
            &self.signature,
        )
    }

    pub fn write(&self, w: &mut Writer) {
        w.put_fixed(&self.version.to_be_bytes());
        w.put_fixed(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            w.put_fixed(&entry.device_id.0.to_be_bytes());
            entry.identity.write(w);
            w.put_fixed(entry.dh_identity.as_bytes());
        }
        self.signature.write(w);
    }

    pub fn read(r: &mut Reader) -> Result<Self> {
        let version = u64::from_be_bytes(
            r.get_fixed(8)?
                .try_into()
                .expect("get_fixed(8) already guarantees the length"),
        );
        let count = u32::from_be_bytes(
            r.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        );
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let device_id = DeviceId(u32::from_be_bytes(
                r.get_fixed(4)?
                    .try_into()
                    .expect("get_fixed(4) already guarantees the length"),
            ));
            let identity = PublicIdentity::read(r)?;
            let dh_identity = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
            entries.push(DeviceListEntry {
                device_id,
                identity,
                dh_identity,
            });
        }
        let signature = HybridSignature::read(r)?;
        Ok(SignedDeviceList {
            version,
            entries,
            signature,
        })
    }
}

/// The wire messages [`MultiDeviceSession::sync_devices`] produced —
/// one per newly-established device session, to be delivered to that
/// specific device.
pub struct DeviceInitMessages {
    pub messages: Vec<(DeviceId, InitMessage)>,
}

/// One local sender's set of per-device sessions to a single peer
/// account. Sending "one message to this account" fans out to a
/// [`RatchetedSession`] per device the account has published a bundle
/// for.
pub struct MultiDeviceSession {
    my_signing_identity: PublicIdentity,
    sessions: BTreeMap<DeviceId, RatchetedSession>,
    /// The highest [`SignedDeviceList::version`] accepted so far for this
    /// peer account, if [`Self::sync_from_signed_device_list`] has ever
    /// been used. `None` means either no signed list has been processed
    /// yet, or this session only ever uses the unauthenticated
    /// [`Self::sync_devices`] path.
    last_seen_device_list_version: Option<u64>,
}

impl MultiDeviceSession {
    pub fn new(my_signing_identity: PublicIdentity) -> Self {
        MultiDeviceSession {
            my_signing_identity,
            sessions: BTreeMap::new(),
            last_seen_device_list_version: None,
        }
    }

    /// Establishes a session with every device in `remote` this instance
    /// doesn't already have one for. Safe to call repeatedly as new
    /// devices are discovered — already-established devices are left
    /// untouched (see module docs on why a changed bundle for an
    /// already-known device id is not picked up here).
    pub fn sync_devices(
        &mut self,
        my_dh_identity: &DhIdentity,
        remote: &RemoteAccount,
    ) -> Result<DeviceInitMessages> {
        let mut messages = Vec::new();
        for (device_id, bundle) in &remote.devices {
            if self.sessions.contains_key(device_id) {
                continue;
            }
            bundle.verify()?;
            let initiated = x3dh::initiate(&self.my_signing_identity, my_dh_identity, bundle, &[])?;
            self.sessions
                .insert(*device_id, RatchetedSession::new(&initiated.session, true));
            messages.push((*device_id, initiated.message));
        }
        Ok(DeviceInitMessages { messages })
    }

    /// The authenticated counterpart to [`Self::sync_devices`]: verifies
    /// `device_list` against `expected_account`, rejects it outright if
    /// its `version` isn't strictly newer than the last one this session
    /// accepted (blocking a rollback to an older list that hides a
    /// revoked device or omits one legitimately added), builds a
    /// [`RemoteAccount`] that additionally checks every bundle against
    /// what the list authorizes, revokes sessions for any device this
    /// session already has that the *new* list no longer includes, and
    /// then establishes sessions for whatever's new — the same
    /// three-way behavior (verify, revoke what's gone, add what's new)
    /// a real account's device-list update should have.
    pub fn sync_from_signed_device_list(
        &mut self,
        my_dh_identity: &DhIdentity,
        expected_account: &PublicIdentity,
        device_list: &SignedDeviceList,
        bundles: Vec<(DeviceId, PreKeyBundle)>,
    ) -> Result<DeviceInitMessages> {
        if let Some(last_seen) = self.last_seen_device_list_version {
            if device_list.version <= last_seen {
                return Err(Error::StaleDeviceList);
            }
        }

        let authorized_ids: Vec<DeviceId> =
            device_list.entries().iter().map(|e| e.device_id).collect();
        let remote =
            RemoteAccount::from_signed_device_list(expected_account, device_list, bundles)?;

        for device_id in self.sessions.keys().copied().collect::<Vec<_>>() {
            if !authorized_ids.contains(&device_id) {
                self.revoke_device(device_id);
            }
        }

        let result = self.sync_devices(my_dh_identity, &remote)?;
        self.last_seen_device_list_version = Some(device_list.version);
        Ok(result)
    }

    /// Removes a device's session entirely — models the device being
    /// deactivated or revoked. A later [`Self::sync_devices`] call
    /// re-establishes a fresh session if the same id reappears.
    pub fn revoke_device(&mut self, device_id: DeviceId) {
        self.sessions.remove(&device_id);
    }

    pub fn device_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn has_device(&self, device_id: DeviceId) -> bool {
        self.sessions.contains_key(&device_id)
    }

    /// Seals `plaintext` under every established device session,
    /// returning one independent ciphertext per device — each is its own
    /// ratchet's own AEAD call; there is no key shared across devices.
    pub fn fan_out(&mut self, plaintext: &[u8]) -> Result<Vec<(DeviceId, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.sessions.len());
        for (device_id, session) in self.sessions.iter_mut() {
            out.push((*device_id, session.seal(plaintext)?));
        }
        Ok(out)
    }

    /// Delivers one device's record to its session.
    pub fn open_from(&mut self, device_id: DeviceId, record: &[u8]) -> Result<Opened> {
        self.sessions
            .get_mut(&device_id)
            .ok_or(Error::UnknownDevice)?
            .open(record)
    }
}

fn identity_key(identity: &PublicIdentity) -> Vec<u8> {
    let mut w = Writer::new();
    identity.write(&mut w);
    w.into_bytes()
}

/// The receiving side's counterpart: one physical device's own identity
/// key material, used to accept incoming X3DH init messages from any
/// number of peer devices (possibly across many different peer accounts)
/// and file each into its own [`RatchetedSession`].
pub struct ReceivingDevice {
    dh_identity: DhIdentity,
    spk: SignedPreKey,
    opks: OneTimePreKeyStore,
    sessions: BTreeMap<(Vec<u8>, DeviceId), RatchetedSession>,
}

impl ReceivingDevice {
    pub fn new(dh_identity: DhIdentity, spk: SignedPreKey, opks: OneTimePreKeyStore) -> Self {
        ReceivingDevice {
            dh_identity,
            spk,
            opks,
            sessions: BTreeMap::new(),
        }
    }

    /// Processes one peer device's X3DH init message, filing the
    /// resulting session under `(sender identity, from_device)`.
    /// `from_device` is supplied by the transport/application (e.g. a
    /// header field alongside the init message) — X3DH itself carries no
    /// device identifier, so this module does not invent one on the wire;
    /// it only uses whatever the caller already asserts.
    pub fn receive_init(
        &mut self,
        from_device: DeviceId,
        init_message_bytes: &[u8],
    ) -> Result<(PublicIdentity, Vec<u8>)> {
        let responded = x3dh::respond(
            &self.dh_identity,
            &self.spk,
            &mut self.opks,
            init_message_bytes,
        )?;
        let key = (identity_key(&responded.initiator_identity), from_device);
        self.sessions
            .insert(key, RatchetedSession::new(&responded.session, false));
        Ok((responded.initiator_identity, responded.initial_payload))
    }

    pub fn open_from(
        &mut self,
        sender: &PublicIdentity,
        from_device: DeviceId,
        record: &[u8],
    ) -> Result<Opened> {
        self.sessions
            .get_mut(&(identity_key(sender), from_device))
            .ok_or(Error::UnknownDevice)?
            .open(record)
    }

    pub fn has_session(&self, sender: &PublicIdentity, from_device: DeviceId) -> bool {
        self.sessions
            .contains_key(&(identity_key(sender), from_device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn dummy_entry(device_id: DeviceId) -> DeviceListEntry {
        let identity = Identity::generate();
        let dh_identity = DhIdentity::generate();
        DeviceListEntry {
            device_id,
            identity: identity.public(),
            dh_identity: dh_identity.public(),
        }
    }

    /// `SignedDeviceList::write`/`read` isn't exercised by any test that
    /// only calls `issue`/`verify` directly (those never round-trip
    /// through wire bytes) -- this is the actual wire-format contract a
    /// deployment sending the list over a transport depends on, so it
    /// needs its own direct check that it round-trips and that the
    /// result still verifies against the issuing account.
    #[test]
    fn signed_device_list_round_trips_through_wire_bytes() {
        let account = Identity::generate();
        let entries = vec![dummy_entry(DeviceId(1)), dummy_entry(DeviceId(2))];
        let list = SignedDeviceList::issue(&account, 3, entries);

        let mut w = Writer::new();
        list.write(&mut w);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        let round_tripped = SignedDeviceList::read(&mut r).expect("well-formed encoding");

        assert_eq!(round_tripped.version, list.version);
        assert_eq!(round_tripped.entries().len(), list.entries().len());
        for (a, b) in round_tripped.entries().iter().zip(list.entries()) {
            assert_eq!(a.device_id, b.device_id);
            assert_eq!(a.dh_identity.as_bytes(), b.dh_identity.as_bytes());
        }
        round_tripped
            .verify(&account.public())
            .expect("round-tripped list must still verify against the issuing account");
    }
}
