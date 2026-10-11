//! Sesame-style multi-device sessions: one logical account backed by
//! several devices, each with its own [`crate::x3dh`] session and
//! [`crate::ratchet`].
//!
//! # The problem
//! The rest of this crate deals in one session between two parties. Real
//! accounts have several devices, each with its own identity, prekeys and
//! session state, and there is no secret shared across a peer's devices,
//! so "send to Bob" means sending once per device over that device's
//! session. [`MultiDeviceSession`] is the fan-out that makes that one
//! logical send, and [`ReceivingDevice`] the fan-in: one device accepting
//! init messages from many peer devices, each filed into its own session.
//!
//! Signal's Sesame is likewise bookkeeping on top of X3DH/Double Ratchet;
//! neither adds cryptographic primitives.
//!
//! # Trusting a device list: [`SignedDeviceList`]
//! Without an authority vouching for "these are all of Bob's devices", a
//! MITM controlling bundle delivery could inject a device. In a
//! [`SignedDeviceList`], the *account's* long-term signing [`Identity`]
//! (Bob's, not any device's) signs a versioned list of `(device id,
//! device identity, device DH identity)`.
//! [`RemoteAccount::from_signed_device_list`] verifies the signature and
//! checks every [`PreKeyBundle`] against the list's entry for its device
//! id; a bundle claiming device 7 with a different identity or DH key is
//! rejected. [`MultiDeviceSession::sync_from_signed_device_list`] also
//! rejects any list not strictly newer than the last accepted, so a MITM
//! can't roll back to hide a revocation or resurrect a device, and a device
//! dropped from a newer list has its session revoked.
//!
//! There is still no server or directory here (the same boundary
//! [`crate::handshake`] and [`crate::x3dh`] draw for identity
//! provisioning): fetching a [`SignedDeviceList`] and choosing which account
//! key to trust are the caller's job. This module verifies and enforces
//! version order once you have one. [`RemoteAccount::new`],
//! [`RemoteAccount::add_device`] and [`RemoteAccount::remove_device`] remain
//! the unauthenticated path for callers who establish trust another way.
//!
//! # What this module does not do
//! - **Detect re-keyed devices on the unauthenticated path.**
//!   [`RemoteAccount::add_device`]/[`MultiDeviceSession::sync_devices`] only
//!   create sessions for device ids without one, even if the bundle
//!   changed. The signed path handles this, since a version bump and a
//!   changed bundle come from the same account signature.
//! - **Sync history across devices.** A newly linked device doesn't receive
//!   earlier messages; each session starts at its own [`crate::x3dh`]
//!   handshake.
//! - **Use `DeviceId` cryptographically.** It is signed in
//!   [`SignedDeviceList`] (that binding is the point) but never fed into
//!   HKDF; it routes wire messages to the right local session.

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

/// One peer account's known devices and their published prekey bundles, as
/// assembled by the caller (no directory service here).
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

    /// Builds a `RemoteAccount` from `bundles` after verifying `device_list`
    /// against `expected_account` and checking every bundle's identity and DH
    /// identity against the list's entry for its device id. A bundle for an
    /// unlisted id, or one that doesn't match, is rejected, so injecting a
    /// device requires forging the account's signature.
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

/// One device a [`SignedDeviceList`] authorizes: the identity and DH
/// identity allowed to speak for `device_id`. Not the full
/// [`PreKeyBundle`]: signed and one-time prekeys rotate far more often than
/// the list should be re-signed, so it pins only the two long-term values a
/// device can't change without becoming a different device.
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

/// An account's current device list, signed by the account's long-term
/// [`Identity`] (not any device's, as a company letterhead isn't one
/// employee's signature). `version` must strictly increase;
/// [`MultiDeviceSession::sync_from_signed_device_list`] never accepts an
/// older list than it has.
pub struct SignedDeviceList {
    pub version: u64,
    entries: Vec<DeviceListEntry>,
    signature: HybridSignature,
}

/// The largest device list this module will issue.
///
/// Sesame deployments run to single digits; the bound keeps the `u32`
/// entry count, signed and written by [`SignedDeviceList::write`], from
/// silently truncating an absurd `Vec`.
pub const MAX_DEVICES: usize = 1024;

impl SignedDeviceList {
    /// # Panics
    /// Panics if `entries` exceeds [`MAX_DEVICES`], a caller configuration error
    /// (an account describing its own devices, not adversary input).
    pub fn issue(account_identity: &Identity, version: u64, entries: Vec<DeviceListEntry>) -> Self {
        assert!(
            entries.len() <= MAX_DEVICES,
            "a device list may name at most {MAX_DEVICES} devices"
        );
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

    /// Checks the signature against `account_identity`. `version` isn't
    /// checked: that needs the previously seen version, which
    /// [`MultiDeviceSession::sync_from_signed_device_list`] tracks.
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
        // Each entry is far more than one byte (device id, hybrid
        // `PublicIdentity`, DH key), so a count larger than the bytes left is
        // unsatisfiable; reject before reserving. See `Reader::remaining` for the
        // unbounded allocation this closes.
        let count = count as usize;
        if count > r.remaining() {
            return Err(Error::Malformed(
                "device list declares more entries than its message can hold",
            ));
        }
        let mut entries = Vec::with_capacity(count);
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

    /// Serializes the list for publishing. [`Self::write`]/[`Self::read`] use
    /// the crate's private `Writer`/`Reader`, so there was no public way to
    /// publish a list; same fix as [`crate::prekey::PreKeyBundle::to_bytes`] and
    /// [`crate::group::Commit::to_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Inverse of [`Self::to_bytes`]. Does **not** verify the signature: call
    /// [`Self::verify`] (or [`MultiDeviceSession::sync_from_signed_device_list`])
    /// against the account identity you trust.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let list = Self::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in signed device list"));
        }
        Ok(list)
    }
}

/// The wire messages [`MultiDeviceSession::sync_devices`] produced, one per
/// new device session, each for that device.
pub struct DeviceInitMessages {
    pub messages: Vec<(DeviceId, InitMessage)>,
}

/// One sender's per-device sessions to a single peer account: sending to
/// the account fans out to a [`RatchetedSession`] per published device.
pub struct MultiDeviceSession {
    my_signing_identity: PublicIdentity,
    sessions: BTreeMap<DeviceId, RatchetedSession>,
    /// The highest [`SignedDeviceList::version`] accepted for this account, or
    /// `None` if no signed list has been processed (or only
    /// [`Self::sync_devices`] is used).
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

    /// Establishes sessions with devices in `remote` that don't have one yet.
    /// Safe to repeat as devices are discovered; existing sessions are left
    /// alone (a changed bundle for a known id isn't picked up; see module
    /// docs).
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

    /// The authenticated [`Self::sync_devices`]: verifies `device_list` against
    /// `expected_account`, rejects it unless its `version` is strictly newer
    /// than the last accepted (blocking rollback to a list that hides a
    /// revocation or omits a legitimate addition), checks every bundle against
    /// the list, revokes sessions for devices the new list drops, and
    /// establishes sessions for new ones.
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

    /// Removes a device's session (deactivated or revoked). A later
    /// [`Self::sync_devices`] creates a fresh one if the id reappears.
    pub fn revoke_device(&mut self, device_id: DeviceId) {
        self.sessions.remove(&device_id);
    }

    pub fn device_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn has_device(&self, device_id: DeviceId) -> bool {
        self.sessions.contains_key(&device_id)
    }

    /// Seals `plaintext` under every device session, one independent
    /// ciphertext per device; no key is shared across devices.
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

/// The receiving side: one device's identity key material, accepting X3DH
/// init messages from any number of peer devices (across accounts) and
/// filing each into its own [`RatchetedSession`].
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

    /// Processes one peer device's X3DH init message, filing the session under
    /// `(sender identity, from_device)`. X3DH carries no device id, so
    /// `from_device` comes from the transport or application (e.g. a header
    /// field); this module only uses what the caller asserts.
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

    /// The `issue`/`verify` tests never round-trip through bytes; this checks
    /// the wire format a deployment depends on: `SignedDeviceList::write`/`read`
    /// round-trip and the result still verifies against the issuer.
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
