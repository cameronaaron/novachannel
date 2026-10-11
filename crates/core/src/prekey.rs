//! Signed prekey bundles: the published key material [`crate::x3dh`]'s
//! asynchronous handshake runs against.
//!
//! X3DH's two defining properties come from what is published here ahead
//! of time:
//!
//! - **Asynchronous**: a session can start once the initiator has the
//!   responder's bundle, whether or not the responder is online.
//! - **Deniable**: the only signature is [`SignedPreKey`]'s, over a
//!   medium-term prekey rotated by the application and reused by every
//!   session made against it; never over anything session-specific
//!   (ephemeral key, transcript, peer). It proves "this application
//!   controls this prekey", not "this application talked to this peer",
//!   which is why a [`crate::x3dh`] session is deniable even though its
//!   bundle is attributably signed.
//!
//! One-time prekeys ([`OneTimePreKey`]) are optional, unsigned and used by
//! at most one session. Including one (`OneTimePreKeyStore::take`) adds a
//! fourth DH term that a later thief of the long-term and signed-prekey
//! secrets can't reproduce, because the one-time secret is deleted on use
//! (see the `crate::x3dh` docs).

use kem::{Kem, KeyExport};
use ml_kem::MlKem1024;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex::{self, MlKemDecapsulationKey, MlKemEncapsulationKey};
use crate::rng::csprng;
use crate::wire::{Reader, Writer};

const SPK_SIGNATURE_CONTEXT: &[u8] = b"novachannel x3dh v1 signed-prekey";

/// A long-term Diffie-Hellman identity key, distinct from [`Identity`]'s
/// Ed25519+ML-DSA *signing* keys. `Identity` signs the [`SignedPreKey`];
/// this key is what X3DH DHs against a peer's prekeys.
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

    pub(crate) fn diffie_hellman(
        &self,
        their: &X25519Public,
    ) -> Result<x25519_dalek::SharedSecret> {
        kex::checked_dh(self.secret.diffie_hellman(their))
    }
}

/// One unsigned, single-use prekey. `id` is bookkeeping (which key an init
/// message referenced) with no cryptographic weight.
///
/// It has its own ML-KEM-1024 leg besides the DH one. The
/// [`SignedPreKey`]'s KEM keypair is reused across sessions, so a later
/// compromise of it plus a recorded transcript recovers the PQ part of
/// `SK` for any session without an OPK. This one is deleted on use (as the
/// DH half always was), giving the handshake's quantum leg the same
/// single-use forward secrecy: a quantum adversary who later breaks the
/// SPK's ML-KEM keypair still can't recover `SK` for sessions that used an
/// OPK.
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

    pub(crate) fn diffie_hellman(
        &self,
        their: &X25519Public,
    ) -> Result<x25519_dalek::SharedSecret> {
        kex::checked_dh(self.secret.diffie_hellman(their))
    }

    pub(crate) fn decapsulate(
        &self,
        ciphertext: &kex::MlKemCiphertext,
    ) -> kem::SharedKey<MlKem1024> {
        use kem::Decapsulate;
        self.kem_secret.decapsulate(ciphertext)
    }
}

/// A responder's published one-time prekeys. `take` removes the matching
/// key so it can never serve two sessions.
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

    /// Borrows the prekey `id` names *without* consuming it, to run the
    /// exchange before the init message is proven genuine. [`Self::consume`]
    /// removes it once the AEAD tag verifies.
    ///
    /// The one-time secret is needed to derive the key that authenticates the
    /// message, so it can't wait for verification, but deleting it beforehand
    /// let anyone burn a responder's whole prekey supply with garbage. Each
    /// deletion strips an honest session's fourth DH term and single-use ML-KEM
    /// leg (see [`OneTimePreKey`]): a forward-secrecy downgrade an
    /// unauthenticated attacker could force at will.
    pub(crate) fn peek(&self, id: u32) -> Result<&OneTimePreKey> {
        self.keys
            .iter()
            .find(|k| k.id == id)
            .ok_or(Error::UnknownOneTimePreKey)
    }

    /// Permanently removes the prekey `id` names. Call only after the init
    /// message referencing it is authenticated; see [`Self::peek`].
    pub(crate) fn consume(&mut self, id: u32) {
        self.keys.retain(|k| k.id != id);
    }
}

/// A medium-term hybrid (DH + ML-KEM) prekey, rotated by the application
/// and signed once by the owner's long-term [`Identity`]. That single
/// signature, not a per-session one, is what keeps X3DH deniable (module
/// docs).
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

    pub(crate) fn diffie_hellman(
        &self,
        their: &X25519Public,
    ) -> Result<x25519_dalek::SharedSecret> {
        kex::checked_dh(self.dh_secret.diffie_hellman(their))
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

    /// The public half as a one-shot hybrid encryption target for
    /// `crate::sealed_sender`, without the signature `crate::x3dh` checks
    /// (sealed sender authenticates with its own certificate), so it carries
    /// less than `SignedPreKey::public`'s `PublicSignedPreKey`.
    ///
    /// Generate a *separate* `SignedPreKey` for sealed-sender receiving rather
    /// than reusing an X3DH one; nothing enforces it, but distinct keys keep
    /// the two protocols from sharing a static secret.
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

/// Everything needed to start an [`crate::x3dh`] session with this bundle's
/// owner while they're offline: their signing identity (attributes the
/// bundle and checks its signature; not used for anything session-specific),
/// DH identity key, one signed prekey, and optionally one one-time prekey.
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
    /// Call this (or otherwise trust the bundle's transport) before use;
    /// nothing else here verifies it, just as [`crate::handshake`] leaves
    /// identity pinning to the caller.
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

    /// Serializes the bundle for publishing, the step X3DH's asynchrony depends
    /// on. [`Self::write`]/[`Self::read`] use the crate's private
    /// `Writer`/`Reader`, so before this there was no public way to publish a
    /// bundle. Same shape as `winterfell::Proof::to_bytes`, which
    /// `novachannel-rln` relies on for the same problem.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Inverse of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let bundle = Self::read(&mut r)?;
        // One bundle, one byte encoding: the canonicality check every other
        // deserializer in this crate already had.
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in prekey bundle"));
        }
        Ok(bundle)
    }
}
