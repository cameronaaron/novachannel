//! Signed prekey bundles: the published key material [`crate::x3dh`]'s
//! asynchronous handshake DHs and encapsulates against.
//!
//! X3DH's two defining properties both come from what's published *here*,
//! ahead of time, rather than negotiated live:
//!
//! - **Asynchronous**: a session can start the moment an initiator has a
//!   responder's bundle, with no requirement that the responder be online.
//! - **Deniable**: the only signature anywhere in this scheme is
//!   [`SignedPreKey`]'s, over the medium-term prekey pair — rotated
//!   periodically by the application, reused across every session
//!   established against it, never over anything session-specific (no
//!   ephemeral key, no transcript, no peer identity). A signature that
//!   attributable evidence would need to single out *one* conversation;
//!   this one covers many, so it proves "this application controls this
//!   prekey," not "this application talked to this specific peer at this
//!   specific time" — which is exactly the distinction that makes a
//!   completed [`crate::x3dh`] session deniable even though the bundle
//!   backing it is attributably signed.
//!
//! One-time prekeys ([`OneTimePreKey`]) are optional, unsigned, and meant
//! to be consumed by at most one session each: including one in the
//! exchange (via [`OneTimePreKeyStore::take`]) adds a fourth DH term an
//! attacker who later steals the long-term and signed-prekey secrets still
//! can't reproduce, since the one-time secret is deleted the moment it's
//! used (see `crate::x3dh` module docs for why that matters).

use kem::{Kem, KeyExport};
use ml_kem::MlKem1024;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex::{self, MlKemDecapsulationKey, MlKemEncapsulationKey};
use crate::rng::csprng;
use crate::wire::{Reader, Writer};

const SPK_SIGNATURE_CONTEXT: &[u8] = b"novachannel x3dh v1 signed-prekey";

/// A long-term, Diffie-Hellman-capable identity key — distinct from
/// [`Identity`]'s Ed25519+ML-DSA *signing* keys. `Identity` signs the
/// [`SignedPreKey`] below; this key is what X3DH actually DHs against a
/// peer's prekeys.
pub struct DhIdentity {
    secret: StaticSecret,
    public: X25519Public,
}

impl DhIdentity {
    pub fn generate() -> Self {
        let mut rng = csprng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = X25519Public::from(&secret);
        DhIdentity { secret, public }
    }

    pub fn public(&self) -> X25519Public {
        self.public
    }

    pub(crate) fn diffie_hellman(&self, their: &X25519Public) -> x25519_dalek::SharedSecret {
        self.secret.diffie_hellman(their)
    }
}

/// One unsigned, single-use prekey. `id` is transport-level bookkeeping
/// only (which key a peer's init message referenced) — it carries no
/// cryptographic weight itself.
///
/// Carries its own ML-KEM-1024 leg alongside the DH one, distinct from the
/// [`SignedPreKey`]'s: the SPK's KEM keypair is reused across every session
/// established against it, so a later compromise of its secret plus a
/// recorded transcript recovers the PQ contribution to `SK` for any session
/// that didn't also consume an OPK. This one is deleted the moment it's
/// used (same as the OPK's DH half always was), so it gives the *quantum*
/// leg of the handshake the same single-use forward secrecy the DH leg
/// already had — a quantum adversary who later breaks the SPK's ML-KEM
/// keypair still can't recover `SK` for a session that consumed an OPK.
pub struct OneTimePreKey {
    pub id: u32,
    secret: StaticSecret,
    public: X25519Public,
    kem_secret: MlKemDecapsulationKey,
    kem_public: MlKemEncapsulationKey,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Self {
        let mut rng = csprng();
        let secret = StaticSecret::random_from_rng(&mut rng);
        let public = X25519Public::from(&secret);
        let (kem_secret, kem_public) = MlKem1024::generate_keypair_from_rng(&mut rng);
        OneTimePreKey {
            id,
            secret,
            public,
            kem_secret,
            kem_public,
        }
    }

    pub fn public(&self) -> (u32, X25519Public, MlKemEncapsulationKey) {
        (self.id, self.public, self.kem_public.clone())
    }

    pub(crate) fn diffie_hellman(&self, their: &X25519Public) -> x25519_dalek::SharedSecret {
        self.secret.diffie_hellman(their)
    }

    pub(crate) fn decapsulate(
        &self,
        ciphertext: &kex::MlKemCiphertext,
    ) -> kem::SharedKey<MlKem1024> {
        use kem::Decapsulate;
        self.kem_secret.decapsulate(ciphertext)
    }
}

/// A responder's supply of published one-time prekeys. `take` removes and
/// returns the matching key so it can never be reused across two sessions
/// — the entire point of a *one-time* prekey.
#[derive(Default)]
pub struct OneTimePreKeyStore {
    keys: Vec<OneTimePreKey>,
}

impl OneTimePreKeyStore {
    pub fn new() -> Self {
        OneTimePreKeyStore { keys: Vec::new() }
    }

    pub fn add(&mut self, key: OneTimePreKey) {
        self.keys.push(key);
    }

    /// The public halves to publish in a [`PreKeyBundle`].
    pub fn public_keys(&self) -> Vec<(u32, X25519Public, MlKemEncapsulationKey)> {
        self.keys.iter().map(OneTimePreKey::public).collect()
    }

    pub(crate) fn take(&mut self, id: u32) -> Result<OneTimePreKey> {
        let idx = self
            .keys
            .iter()
            .position(|k| k.id == id)
            .ok_or(Error::UnknownOneTimePreKey)?;
        Ok(self.keys.remove(idx))
    }
}

/// A medium-term, hybrid (DH + ML-KEM) prekey, rotated periodically by the
/// application and signed once by the owner's long-term [`Identity`] — see
/// the module docs for why that one signature, and not a per-session one,
/// is what keeps X3DH deniable.
pub struct SignedPreKey {
    dh_secret: StaticSecret,
    dh_public: X25519Public,
    kem_secret: MlKemDecapsulationKey,
    kem_public: MlKemEncapsulationKey,
    signature: HybridSignature,
}

fn spk_signed_bytes(dh_public: &X25519Public, kem_public: &MlKemEncapsulationKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_fixed(SPK_SIGNATURE_CONTEXT);
    w.put_fixed(dh_public.as_bytes());
    w.put_var(&kem_public.to_bytes());
    w.into_bytes()
}

impl SignedPreKey {
    pub fn generate(signing_identity: &Identity) -> Self {
        let mut rng = csprng();
        let dh_secret = StaticSecret::random_from_rng(&mut rng);
        let dh_public = X25519Public::from(&dh_secret);
        let (kem_secret, kem_public) = MlKem1024::generate_keypair_from_rng(&mut rng);
        let signature = signing_identity.sign(&spk_signed_bytes(&dh_public, &kem_public));
        SignedPreKey {
            dh_secret,
            dh_public,
            kem_secret,
            kem_public,
            signature,
        }
    }

    pub(crate) fn diffie_hellman(&self, their: &X25519Public) -> x25519_dalek::SharedSecret {
        self.dh_secret.diffie_hellman(their)
    }

    pub(crate) fn decapsulate(
        &self,
        ciphertext: &kex::MlKemCiphertext,
    ) -> kem::SharedKey<MlKem1024> {
        use kem::Decapsulate;
        self.kem_secret.decapsulate(ciphertext)
    }

    fn public(&self) -> PublicSignedPreKey {
        PublicSignedPreKey {
            dh_public: self.dh_public,
            kem_public: self.kem_public.clone(),
            signature: self.signature.clone(),
        }
    }

    /// The public half usable as a one-shot hybrid encryption target by
    /// `crate::sealed_sender`, without the signature `crate::x3dh` checks —
    /// sealed sender authenticates via its own certificate instead (see
    /// that module's docs), so this deliberately carries less than
    /// [`SignedPreKey::public`]'s [`PublicSignedPreKey`].
    ///
    /// Applications should generate a *separate* `SignedPreKey` instance
    /// for sealed-sender receiving rather than reusing one already
    /// published for X3DH — nothing here requires it, but keeping the two
    /// roles on distinct key material avoids the two protocols ever
    /// sharing a static secret.
    pub fn sealing_public_key(&self) -> SealingPublicKey {
        SealingPublicKey {
            dh_public: self.dh_public,
            kem_public: self.kem_public.clone(),
        }
    }
}

/// The public half of a [`SignedPreKey`], stripped down to just what
/// [`crate::sealed_sender::seal`] needs to encrypt to this key's owner.
#[derive(Clone)]
pub struct SealingPublicKey {
    pub(crate) dh_public: X25519Public,
    pub(crate) kem_public: MlKemEncapsulationKey,
}

struct PublicSignedPreKey {
    dh_public: X25519Public,
    kem_public: MlKemEncapsulationKey,
    signature: HybridSignature,
}

impl PublicSignedPreKey {
    fn verify(&self, identity: &PublicIdentity) -> Result<()> {
        identity.verify(
            &spk_signed_bytes(&self.dh_public, &self.kem_public),
            &self.signature,
        )
    }

    fn write(&self, w: &mut Writer) {
        w.put_fixed(self.dh_public.as_bytes());
        w.put_var(&self.kem_public.to_bytes());
        self.signature.write(w);
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let dh_public = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let kem_public = kex::ml_kem_public_from_bytes(r.get_var()?)?;
        let signature = HybridSignature::read(r)?;
        Ok(PublicSignedPreKey {
            dh_public,
            kem_public,
            signature,
        })
    }
}

/// Everything an initiator needs to start an [`crate::x3dh`] session with
/// this bundle's owner, without them being online: their signing identity
/// (to attribute the bundle and, later, verify who signed it — not used to
/// verify anything session-specific), their DH identity key, one signed
/// prekey, and optionally one one-time prekey.
pub struct PreKeyBundle {
    pub identity: PublicIdentity,
    pub dh_identity: X25519Public,
    spk: PublicSignedPreKey,
    pub one_time_prekey: Option<(u32, X25519Public, MlKemEncapsulationKey)>,
}

impl PreKeyBundle {
    pub fn build(
        identity: PublicIdentity,
        dh_identity: &DhIdentity,
        spk: &SignedPreKey,
        one_time_prekey: Option<(u32, X25519Public, MlKemEncapsulationKey)>,
    ) -> Self {
        PreKeyBundle {
            identity,
            dh_identity: dh_identity.public(),
            spk: spk.public(),
            one_time_prekey,
        }
    }

    /// Checks the signed prekey's signature against the embedded identity.
    /// Callers must call this (or otherwise already trust the bundle's
    /// transport) before using it — nothing else in this module verifies
    /// it implicitly, the same way [`crate::handshake`] leaves peer-identity
    /// pinning to the caller.
    pub fn verify(&self) -> Result<()> {
        self.spk.verify(&self.identity)
    }

    pub(crate) fn spk_dh_public(&self) -> &X25519Public {
        &self.spk.dh_public
    }

    pub(crate) fn spk_kem_public(&self) -> &MlKemEncapsulationKey {
        &self.spk.kem_public
    }

    pub fn write(&self, w: &mut Writer) {
        self.identity.write(w);
        w.put_fixed(self.dh_identity.as_bytes());
        self.spk.write(w);
        match &self.one_time_prekey {
            Some((id, public, kem_public)) => {
                w.put_fixed(&[1]);
                w.put_fixed(&id.to_be_bytes());
                w.put_fixed(public.as_bytes());
                w.put_var(&kem_public.to_bytes());
            }
            None => w.put_fixed(&[0]),
        }
    }

    pub fn read(r: &mut Reader) -> Result<Self> {
        let identity = PublicIdentity::read(r)?;
        let dh_identity = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let spk = PublicSignedPreKey::read(r)?;
        let has_opk = r.get_fixed(1)?[0];
        let one_time_prekey = match has_opk {
            0 => None,
            1 => {
                let id = u32::from_be_bytes(
                    r.get_fixed(4)?
                        .try_into()
                        .expect("get_fixed(4) already guarantees the length"),
                );
                let public = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
                let kem_public = kex::ml_kem_public_from_bytes(r.get_var()?)?;
                Some((id, public, kem_public))
            }
            _ => return Err(Error::Malformed("invalid one-time-prekey presence flag")),
        };
        Ok(PreKeyBundle {
            identity,
            dh_identity,
            spk,
            one_time_prekey,
        })
    }

    /// Serializes this bundle to bytes — the actual "publish this
    /// somewhere fetchable" step X3DH's asynchrony depends on
    /// (this module's own doc: the bundle "is published key material").
    /// [`Self::write`]/[`Self::read`] exist but take this crate's own
    /// private [`Writer`]/[`Reader`], so nothing outside the crate could
    /// previously call them — the bundle had a documented purpose and no
    /// public way to fulfil it. Same shape as `winterfell::Proof::to_bytes`,
    /// which this workspace's own `novachannel-rln` integration already
    /// relies on for the equivalent problem.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Inverse of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        Self::read(&mut r)
    }
}
