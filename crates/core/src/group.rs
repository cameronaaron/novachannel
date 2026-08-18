//! A TreeKEM-inspired group ratchet: `O(log n)` member add/remove/update
//! rekeying for a group of any size, instead of the `O(n)` cost of running
//! [`crate::x3dh`]/[`crate::ratchet`] pairwise with every other member.
//!
//! # Honest scope, relative to real MLS (RFC 9420)
//! This module borrows MLS's central idea — a ratchet tree ("TreeKEM")
//! where committing a change means re-keying just the path from one leaf to
//! the root, encrypting each step to the resolution of its sibling subtree
//! so only current members can decrypt it — and reuses this crate's own
//! primitives (X25519 + ML-KEM-1024 hybrid encryption, HKDF, the hybrid
//! Ed25519 + ML-DSA-87 [`crate::identity::Identity`] for signing commits).
//! It is **not** RFC 9420: there is no TLS presentation-language wire
//! encoding, no HPKE per RFC 9180 specifically (this crate's own hybrid
//! combiner is used instead, same as everywhere else in this workspace),
//! no X.509/credential machinery, and no interoperability with any other
//! MLS implementation. Getting *that* right — matching the spec's exact
//! encodings and passing its published test vectors — is a materially
//! larger, separate effort; this module gets the same asymptotic scaling
//! property using primitives this crate already trusts.
//!
//! Simplifications relative to RFC 9420's actual TreeKEM, beyond wire
//! format:
//! - **Fixed capacity, no tree resizing.** A group's leaf capacity (a power
//!   of two) is chosen once at [`Group::create`] and never grows — adding
//!   past it fails with [`Error::GroupFull`]. RFC 9420's array-based
//!   left-balanced binary tree supports resizing via a specific indexing
//!   scheme (RFC 9420 §7) that keeps existing leaves' positions stable
//!   across a resize; implementing that scheme correctly is its own
//!   undertaking, so this module sidesteps it entirely rather than get it
//!   subtly wrong.
//! - **No "unmerged leaves" optimization.** Real MLS lets a `Commit`
//!   contain proposals without a full path update in some cases, tracking
//!   which leaves haven't yet been cryptographically "merged" into their
//!   ancestors' secrets. This module always sends a full path update with
//!   every commit (add, remove, *and* update alike), which is simpler and
//!   avoids needing that bookkeeping, at the cost of one more full path's
//!   worth of hybrid ciphertexts per commit than the optimized protocol
//!   would use.
//! - **One proposal per commit.** Real MLS batches multiple adds/removes
//!   into a single commit. This module always commits exactly one
//!   structural change ([`GroupOp::Add`], [`GroupOp::Remove`], or
//!   [`GroupOp::Update`]) at a time.
//! - **No concurrent-commit resolution.** Like [`crate::ratchet`]'s stance
//!   on racing ratchet initiations, this module assumes commits are applied
//!   in a single agreed order (e.g. via a sequencing server or a
//!   total-order broadcast layer) — it does not itself detect or resolve
//!   two members committing from the same epoch concurrently.
//! - **Current-epoch-only message decryption**, no MLS "secret tree" with
//!   per-generation, out-of-order-tolerant sender ratchets. Each member's
//!   send chain for the current epoch is a single forward hash chain
//!   (mirroring [`crate::ratchet`]'s `ChainKey`); in-order delivery within
//!   an epoch is required, and a message from a since-ended epoch cannot be
//!   opened.
//!
//! # What's preserved
//! The properties that actually justify TreeKEM over pairwise ratchets are
//! real here: committing any single change costs each participant
//! `O(log n)` hybrid-encrypted values (not one per other member), every
//! commit gives forward secrecy and post-compromise security for the whole
//! group (a fresh, hybrid PQ/classical secret is mixed into the epoch on
//! every commit), and a removed member is cryptographically excluded going
//! forward — not just told to stop, but structurally unable to decrypt
//! anything from a later epoch, because the removed leaf's entire ancestor
//! path is blanked and never re-sent to them.

use std::collections::HashMap;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use kem::{Encapsulate, Kem, KeyExport};
use ml_kem::MlKem1024;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex::{self, MlKemCiphertext, MlKemDecapsulationKey, MlKemEncapsulationKey};
use crate::rng::csprng;
use crate::wire::{Reader, Writer};

type HmacSha256 = Hmac<Sha256>;

const LABEL_NODE_KEYGEN: &[u8] = b"novachannel group v1 node keygen";
const LABEL_PATH_STEP: &[u8] = b"novachannel group v1 path secret step";
const LABEL_SEAL_KEY: &[u8] = b"novachannel group v1 seal key";
const LABEL_EPOCH_SECRET: &[u8] = b"novachannel group v1 epoch secret";
const LABEL_APPLICATION_SECRET: &[u8] = b"novachannel group v1 application secret";
const LABEL_SENDER_CHAIN: &[u8] = b"novachannel group v1 sender chain";
const LABEL_MESSAGE_KEY: &[u8] = &[0x01];
const LABEL_NEXT_CHAIN: &[u8] = &[0x02];
const COMMIT_SIGNATURE_CONTEXT: &[u8] = b"novachannel group v1 commit";
const LEAF_KEY_PACKAGE_POP_CONTEXT: &[u8] = b"novachannel group v1 leaf key package";
const PATH_SECRET_AAD_CONTEXT: &[u8] = b"novachannel group v1 path secret";
const WELCOME_AAD_CONTEXT: &[u8] = b"novachannel group v1 welcome";

// ---------------------------------------------------------------------
// Tree indexing over a fixed-capacity, array-based complete binary tree.
// Root is index 0; leaves occupy the last `capacity` array slots. Unlike
// RFC 9420's left-balanced tree, this indexing is not resize-stable, which
// is exactly why capacity is fixed for a group's lifetime (module docs).
// ---------------------------------------------------------------------

fn leaf_to_node(capacity: usize, leaf: usize) -> usize {
    capacity - 1 + leaf
}

fn is_leaf(capacity: usize, node: usize) -> bool {
    node >= capacity - 1
}

fn parent(node: usize) -> Option<usize> {
    if node == 0 {
        None
    } else {
        Some((node - 1) / 2)
    }
}

fn left_child(node: usize) -> usize {
    2 * node + 1
}

fn right_child(node: usize) -> usize {
    2 * node + 2
}

/// The sibling of `node` — the other child of `node`'s parent. `None` only
/// for the root, which has no parent.
fn sibling(node: usize) -> Option<usize> {
    let p = parent(node)?;
    Some(if left_child(p) == node {
        right_child(p)
    } else {
        left_child(p)
    })
}

/// Ancestors of `leaf`, nearest first, ending at the root (index 0).
fn direct_path(capacity: usize, leaf: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut n = leaf_to_node(capacity, leaf);
    while let Some(p) = parent(n) {
        out.push(p);
        n = p;
    }
    out
}

/// The minimal set of node indices covering `node`'s subtree such that
/// every current leaf beneath it is reachable via exactly one of them: a
/// non-blank node is its own one-element resolution (whoever populated it
/// distributed its secret to everyone beneath already); a blank internal
/// node recurses into both children; a blank leaf contributes nothing.
fn resolution(nodes: &[TreeNode], capacity: usize, node: usize) -> Vec<usize> {
    match &nodes[node] {
        TreeNode::Blank => {
            if is_leaf(capacity, node) {
                Vec::new()
            } else {
                let mut out = resolution(nodes, capacity, left_child(node));
                out.extend(resolution(nodes, capacity, right_child(node)));
                out
            }
        }
        TreeNode::Leaf(_) | TreeNode::Parent(_) => vec![node],
    }
}

fn node_public_key(nodes: &[TreeNode], node: usize) -> &NodePublicKey {
    match &nodes[node] {
        TreeNode::Leaf(lp) => &lp.public_key,
        TreeNode::Parent(pk) => pk,
        TreeNode::Blank => unreachable!("resolution() never returns a blank node's index"),
    }
}

// ---------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------

/// A hybrid X25519 + ML-KEM-1024 public key attached to one tree node —
/// either a member's leaf or an internal node populated by some past
/// commit's path update.
#[derive(Clone)]
pub struct NodePublicKey {
    dh_public: X25519Public,
    kem_public: MlKemEncapsulationKey,
}

impl NodePublicKey {
    fn write(&self, w: &mut Writer) {
        w.put_fixed(self.dh_public.as_bytes());
        w.put_var(&self.kem_public.to_bytes());
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let dh_public = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let kem_public = kex::ml_kem_public_from_bytes(r.get_var()?)?;
        Ok(NodePublicKey {
            dh_public,
            kem_public,
        })
    }
}

impl PartialEq for NodePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.dh_public.as_bytes() == other.dh_public.as_bytes()
            && self.kem_public.to_bytes() == other.kem_public.to_bytes()
    }
}

/// The message a [`LeafKeyPackage`]'s proof-of-possession signature covers:
/// binds `identity` to this specific `public_key` so a package can't be
/// forged by pairing a victim's real, published `PublicIdentity` with an
/// attacker-chosen `NodePublicKey` — the same signed-binding pattern
/// `crate::prekey::SignedPreKey` and `crate::multidevice::SignedDeviceList`
/// already use for the same reason. Without it, whoever calls
/// [`Group::propose_add`] on an unverified `LeafKeyPackage` has no way to
/// tell "the real Bob asked to join" from "someone published Bob's public
/// identity next to their own key material," and the tree would then
/// record the attacker's key under Bob's name.
fn leaf_key_package_pop_message(identity: &PublicIdentity, public_key: &NodePublicKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_fixed(LEAF_KEY_PACKAGE_POP_CONTEXT);
    identity.write(&mut w);
    public_key.write(&mut w);
    w.into_bytes()
}

/// A prospective or current member's leaf: their signing identity plus the
/// public half of their leaf's hybrid key, published so an existing member
/// can [`Group::propose_add`] them. `pop` is a proof-of-possession
/// signature over `identity`+`public_key` from `identity`'s own long-term
/// signing key, checked by [`Self::read`] (and so by every deserialization
/// path — [`Self::from_bytes`], a [`GroupOp::Add`] inside a received
/// [`Commit`], and a [`Welcome`] snapshot's tree) before the package is
/// ever trusted.
#[derive(Clone)]
pub struct LeafKeyPackage {
    pub identity: PublicIdentity,
    public_key: NodePublicKey,
    pop: HybridSignature,
}

impl LeafKeyPackage {
    fn write(&self, w: &mut Writer) {
        self.identity.write(w);
        self.public_key.write(w);
        self.pop.write(w);
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let identity = PublicIdentity::read(r)?;
        let public_key = NodePublicKey::read(r)?;
        let pop = HybridSignature::read(r)?;
        identity.verify(&leaf_key_package_pop_message(&identity, &public_key), &pop)?;
        Ok(LeafKeyPackage {
            identity,
            public_key,
            pop,
        })
    }

    /// Same gap, same fix as [`Commit::to_bytes`]/[`Commit::from_bytes`]:
    /// a prospective member has to publish this to whoever will call
    /// [`Group::propose_add`] on their behalf, which needs public bytes,
    /// not this crate's private [`Writer`]/[`Reader`]. `write`/`read`
    /// stay private — every other call site reaches them through a
    /// `Group` method that already holds a `LeafKeyPackage` value, not
    /// through wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// Inverse of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let package = Self::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in leaf key package"));
        }
        Ok(package)
    }
}

/// The private counterpart of a [`LeafKeyPackage`] — generated by a
/// prospective member before anyone adds them, or by a group's founder for
/// their own leaf. Needed only to decrypt the one commit that establishes
/// this leaf's place in the tree (via [`Group::create`] or
/// [`Group::join`]); once a member has derived at least one internal node's
/// secret, later commits are decrypted through that instead.
pub struct MyLeafKeyPackage {
    identity: PublicIdentity,
    dh_secret: StaticSecret,
    dh_public: X25519Public,
    kem_secret: MlKemDecapsulationKey,
    kem_public: MlKemEncapsulationKey,
    pop: HybridSignature,
}

impl MyLeafKeyPackage {
    /// `signing_identity` must be this prospective member's own long-term
    /// [`Identity`] — its secret key signs the freshly generated leaf key
    /// pair's proof-of-possession (see [`leaf_key_package_pop_message`]),
    /// which is what lets [`Group::propose_add`]'s caller (and every peer
    /// who later reads this package off the wire) trust that `identity`
    /// and this leaf's key material actually belong together.
    pub fn generate(signing_identity: &Identity) -> Self {
        let mut rng = csprng();
        let dh_secret = StaticSecret::random_from_rng(&mut rng);
        let dh_public = X25519Public::from(&dh_secret);
        let (kem_secret, kem_public) = MlKem1024::generate_keypair_from_rng(&mut rng);
        let identity = signing_identity.public();
        let public_key = NodePublicKey {
            dh_public,
            kem_public: kem_public.clone(),
        };
        let pop = signing_identity.sign(&leaf_key_package_pop_message(&identity, &public_key));
        MyLeafKeyPackage {
            identity,
            dh_secret,
            dh_public,
            kem_secret,
            kem_public,
            pop,
        }
    }

    pub fn public(&self) -> LeafKeyPackage {
        LeafKeyPackage {
            identity: self.identity.clone(),
            public_key: NodePublicKey {
                dh_public: self.dh_public,
                kem_public: self.kem_public.clone(),
            },
            pop: self.pop.clone(),
        }
    }
}

enum TreeNode {
    Blank,
    Leaf(Box<LeafKeyPackage>),
    Parent(Box<NodePublicKey>),
}

impl Clone for TreeNode {
    fn clone(&self) -> Self {
        match self {
            TreeNode::Blank => TreeNode::Blank,
            TreeNode::Leaf(lp) => TreeNode::Leaf(lp.clone()),
            TreeNode::Parent(pk) => TreeNode::Parent(pk.clone()),
        }
    }
}

// ---------------------------------------------------------------------
// Hybrid one-shot sealing of small payloads to a `NodePublicKey` — the
// same shape as `crate::sealed_sender`'s envelope, reused here for both
// per-node path-secret ciphertexts and `Welcome` snapshots.
// ---------------------------------------------------------------------

struct SealedToNode {
    eph_dh_public: X25519Public,
    kem_ct: MlKemCiphertext,
    ciphertext: Vec<u8>,
}

impl SealedToNode {
    fn write(&self, w: &mut Writer) {
        w.put_fixed(self.eph_dh_public.as_bytes());
        w.put_var(&self.kem_ct);
        w.put_var(&self.ciphertext);
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let eph_dh_public = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
        let ciphertext = r.get_var()?.to_vec();
        Ok(SealedToNode {
            eph_dh_public,
            kem_ct,
            ciphertext,
        })
    }
}

fn derive_seal_key(dh: &x25519_dalek::SharedSecret, kem_ss: &[u8]) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(32 + kem_ss.len());
    ikm.extend_from_slice(dh.as_bytes());
    ikm.extend_from_slice(kem_ss);
    let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
    ikm.zeroize();
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut key = [0u8; 32];
    hk.expand(LABEL_SEAL_KEY, &mut key)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(key)
}

fn seal_to_node(target: &NodePublicKey, aad: &[u8], plaintext: &[u8]) -> Result<SealedToNode> {
    let mut rng = csprng();
    let eph_secret = EphemeralSecret::random_from_rng(&mut rng);
    let eph_dh_public = X25519Public::from(&eph_secret);
    let dh = eph_secret.diffie_hellman(&target.dh_public);
    let (kem_ct, kem_ss) = target.kem_public.encapsulate_with_rng(&mut rng);
    let key = derive_seal_key(&dh, &kem_ss)?;
    let ciphertext = aead_seal(&key, aad, plaintext)?;
    Ok(SealedToNode {
        eph_dh_public,
        kem_ct,
        ciphertext,
    })
}

fn open_from_node(
    dh_secret: &StaticSecret,
    kem_secret: &MlKemDecapsulationKey,
    aad: &[u8],
    sealed: &SealedToNode,
) -> Result<Vec<u8>> {
    use kem::Decapsulate;
    let dh = dh_secret.diffie_hellman(&sealed.eph_dh_public);
    let kem_ss = kem_secret.decapsulate(&sealed.kem_ct);
    let key = derive_seal_key(&dh, &kem_ss)?;
    aead_seal_open(&key, aad, &sealed.ciphertext)
}

/// Single-use key, all-zero nonce — safe for the reason every other
/// module's `seal_with_*_key` helper documents: each `key` here comes from
/// a fresh ephemeral exchange or a fresh chain step and is used exactly
/// once.
fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn aead_seal_open(key: &[u8; 32], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}

/// Derives a fresh, deterministic hybrid keypair from a 32-byte path
/// secret: both sides of a successfully decrypted path secret must arrive
/// at the identical keypair the committer generated, so this is expansion,
/// not fresh randomness. The ML-KEM half uses `DecapsulationKey::from_seed`
/// (FIPS 203's `d`/`z` internal seed), which is exactly what that API is
/// for; the X25519 half uses a raw 32-byte `StaticSecret`, clamped the same
/// way any other construction of one is.
fn derive_node_keypair(
    secret: &[u8; 32],
) -> Result<(
    StaticSecret,
    X25519Public,
    MlKemDecapsulationKey,
    MlKemEncapsulationKey,
)> {
    let (prk, _) = Hkdf::<Sha256>::extract(None, secret);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut seed_bytes = [0u8; 96];
    hk.expand(LABEL_NODE_KEYGEN, &mut seed_bytes)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;

    let dh_secret = StaticSecret::from(<[u8; 32]>::try_from(&seed_bytes[..32]).expect("32 bytes"));
    let dh_public = X25519Public::from(&dh_secret);

    let kem_seed_bytes: [u8; 64] = seed_bytes[32..96].try_into().expect("64 bytes");
    let kem_secret = MlKemDecapsulationKey::from_seed(ml_kem::Seed::from(kem_seed_bytes));
    let kem_public = kem_secret.encapsulation_key().clone();

    Ok((dh_secret, dh_public, kem_secret, kem_public))
}

fn hkdf_expand32(secret: &[u8; 32], label: &[u8]) -> Result<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(None, secret);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut out = [0u8; 32];
    hk.expand(label, &mut out)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Commits
// ---------------------------------------------------------------------

pub enum GroupOp {
    Add {
        leaf_index: u32,
        key_package: Box<LeafKeyPackage>,
    },
    Remove {
        leaf_index: u32,
    },
    Update,
}

impl GroupOp {
    fn write(&self, w: &mut Writer) {
        match self {
            GroupOp::Add {
                leaf_index,
                key_package,
            } => {
                w.put_fixed(&[0]);
                w.put_fixed(&leaf_index.to_be_bytes());
                key_package.write(w);
            }
            GroupOp::Remove { leaf_index } => {
                w.put_fixed(&[1]);
                w.put_fixed(&leaf_index.to_be_bytes());
            }
            GroupOp::Update => w.put_fixed(&[2]),
        }
    }

    fn read(r: &mut Reader) -> Result<Self> {
        match r.get_fixed(1)?[0] {
            0 => {
                let leaf_index = u32::from_be_bytes(
                    r.get_fixed(4)?
                        .try_into()
                        .expect("get_fixed(4) already guarantees the length"),
                );
                let key_package = Box::new(LeafKeyPackage::read(r)?);
                Ok(GroupOp::Add {
                    leaf_index,
                    key_package,
                })
            }
            1 => {
                let leaf_index = u32::from_be_bytes(
                    r.get_fixed(4)?
                        .try_into()
                        .expect("get_fixed(4) already guarantees the length"),
                );
                Ok(GroupOp::Remove { leaf_index })
            }
            2 => Ok(GroupOp::Update),
            _ => Err(Error::Malformed("unknown group op tag")),
        }
    }
}

struct UpdatePathNode {
    public_key: NodePublicKey,
    ciphertexts: Vec<SealedToNode>,
}

impl UpdatePathNode {
    fn write(&self, w: &mut Writer) {
        self.public_key.write(w);
        w.put_fixed(&(self.ciphertexts.len() as u32).to_be_bytes());
        for ct in &self.ciphertexts {
            ct.write(w);
        }
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let public_key = NodePublicKey::read(r)?;
        let count = u32::from_be_bytes(
            r.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        ) as usize;
        let mut ciphertexts = Vec::with_capacity(count);
        for _ in 0..count {
            ciphertexts.push(SealedToNode::read(r)?);
        }
        Ok(UpdatePathNode {
            public_key,
            ciphertexts,
        })
    }
}

/// One committed group change: a structural op ([`GroupOp`]) plus a fresh
/// path update from the committer's leaf to the root, signed by the
/// committer's [`Identity`]. Self-contained — applying it (via
/// [`Group::apply_commit`]) needs nothing else but the group's current
/// state.
pub struct Commit {
    group_id: [u8; 16],
    from_epoch: u64,
    sender_leaf: u32,
    op: GroupOp,
    path: Vec<UpdatePathNode>,
    signature: HybridSignature,
}

fn commit_signed_bytes(
    group_id: &[u8; 16],
    from_epoch: u64,
    sender_leaf: u32,
    op: &GroupOp,
    path: &[UpdatePathNode],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_fixed(COMMIT_SIGNATURE_CONTEXT);
    w.put_fixed(group_id);
    w.put_fixed(&from_epoch.to_be_bytes());
    w.put_fixed(&sender_leaf.to_be_bytes());
    op.write(&mut w);
    w.put_fixed(&(path.len() as u32).to_be_bytes());
    for node in path {
        node.write(&mut w);
    }
    w.into_bytes()
}

impl Commit {
    pub fn write(&self, w: &mut Writer) {
        let signed = commit_signed_bytes(
            &self.group_id,
            self.from_epoch,
            self.sender_leaf,
            &self.op,
            &self.path,
        );
        w.put_var(&signed);
        self.signature.write(w);
    }

    pub fn read(r: &mut Reader) -> Result<Self> {
        let signed = r.get_var()?;
        let signature = HybridSignature::read(r)?;

        let mut sr = Reader::new(signed);
        sr.get_fixed(COMMIT_SIGNATURE_CONTEXT.len())?;
        let group_id: [u8; 16] = sr
            .get_fixed(16)?
            .try_into()
            .expect("get_fixed(16) already guarantees the length");
        let from_epoch = u64::from_be_bytes(
            sr.get_fixed(8)?
                .try_into()
                .expect("get_fixed(8) already guarantees the length"),
        );
        let sender_leaf = u32::from_be_bytes(
            sr.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        );
        let op = GroupOp::read(&mut sr)?;
        let path_len = u32::from_be_bytes(
            sr.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        ) as usize;
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            path.push(UpdatePathNode::read(&mut sr)?);
        }
        if !sr.finished() {
            return Err(Error::Malformed(
                "trailing bytes in commit's signed section",
            ));
        }

        Ok(Commit {
            group_id,
            from_epoch,
            sender_leaf,
            op,
            path,
            signature,
        })
    }

    /// [`Self::write`]/[`Self::read`] take this crate's own private
    /// [`Writer`]/[`Reader`], so nothing outside the crate could
    /// previously call them — a `Commit` had a documented purpose
    /// (broadcast to every other group member) and no public way to
    /// fulfil it, the same gap [`crate::prekey::PreKeyBundle`] once had.
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

/// Delivered to a prospective member alongside the [`Commit`] that adds
/// them: a snapshot of the group's pre-commit public state, sealed to
/// their [`LeafKeyPackage`] so only they can read it. Mirrors real MLS's
/// `Welcome` message, minus the wire format and PSK/ratchet-tree-extension
/// machinery.
pub struct Welcome {
    sealed: SealedToNode,
}

impl Welcome {
    /// Same gap, same fix as [`Commit::to_bytes`]/[`Commit::from_bytes`]:
    /// a `Welcome` must reach the joining member over some transport
    /// (typically alongside the accompanying [`Commit`]), which needs
    /// public bytes, not this crate's private [`Writer`]/[`Reader`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.sealed.write(&mut w);
        w.into_bytes()
    }

    /// Inverse of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let sealed = SealedToNode::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in welcome"));
        }
        Ok(Welcome { sealed })
    }
}

struct WelcomeSnapshot {
    group_id: [u8; 16],
    capacity: u32,
    epoch: u64,
    epoch_secret: [u8; 32],
    transcript_hash: [u8; 32],
    nodes: Vec<TreeNode>,
    target_leaf: u32,
}

impl Drop for WelcomeSnapshot {
    fn drop(&mut self) {
        self.epoch_secret.zeroize();
    }
}

impl WelcomeSnapshot {
    fn write(&self, w: &mut Writer) {
        w.put_fixed(&self.group_id);
        w.put_fixed(&self.capacity.to_be_bytes());
        w.put_fixed(&self.epoch.to_be_bytes());
        w.put_fixed(&self.epoch_secret);
        w.put_fixed(&self.transcript_hash);
        w.put_fixed(&self.target_leaf.to_be_bytes());
        for node in &self.nodes {
            match node {
                TreeNode::Blank => w.put_fixed(&[0]),
                TreeNode::Leaf(lp) => {
                    w.put_fixed(&[1]);
                    lp.write(w);
                }
                TreeNode::Parent(pk) => {
                    w.put_fixed(&[2]);
                    pk.write(w);
                }
            }
        }
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let group_id: [u8; 16] = r
            .get_fixed(16)?
            .try_into()
            .expect("get_fixed(16) already guarantees the length");
        let capacity = u32::from_be_bytes(
            r.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        );
        let epoch = u64::from_be_bytes(
            r.get_fixed(8)?
                .try_into()
                .expect("get_fixed(8) already guarantees the length"),
        );
        let epoch_secret: [u8; 32] = r
            .get_fixed(32)?
            .try_into()
            .expect("get_fixed(32) already guarantees the length");
        let transcript_hash: [u8; 32] = r
            .get_fixed(32)?
            .try_into()
            .expect("get_fixed(32) already guarantees the length");
        let target_leaf = u32::from_be_bytes(
            r.get_fixed(4)?
                .try_into()
                .expect("get_fixed(4) already guarantees the length"),
        );
        // `capacity`/`target_leaf` arrive inside an AEAD-authenticated
        // plaintext, but the sender who *produced* that plaintext is
        // unauthenticated at this layer (`seal_to_node` is a one-shot,
        // sender-anonymous envelope, the same shape as
        // `crate::sealed_sender` — see its module docs): anyone who knows
        // the joining member's published `LeafKeyPackage` can construct a
        // `Welcome` that decrypts cleanly under that member's own keys,
        // with arbitrary contents. `capacity` must therefore be checked
        // against exactly the same invariant `Group::create` enforces
        // before it drives a subtraction/allocation, not trusted as
        // already valid.
        if capacity < 2 || !capacity.is_power_of_two() {
            return Err(Error::Malformed(
                "welcome snapshot capacity must be a power of two of at least 2",
            ));
        }
        if capacity > (1 << 20) {
            return Err(Error::Malformed(
                "welcome snapshot capacity exceeds this implementation's sanity bound",
            ));
        }
        if target_leaf >= capacity {
            return Err(Error::Malformed(
                "welcome snapshot target leaf is not within its own capacity",
            ));
        }
        let node_count = 2 * (capacity as usize) - 1;
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            match r.get_fixed(1)?[0] {
                0 => nodes.push(TreeNode::Blank),
                1 => nodes.push(TreeNode::Leaf(Box::new(LeafKeyPackage::read(r)?))),
                2 => nodes.push(TreeNode::Parent(Box::new(NodePublicKey::read(r)?))),
                _ => {
                    return Err(Error::Malformed(
                        "unknown tree node tag in welcome snapshot",
                    ))
                }
            }
        }
        Ok(WelcomeSnapshot {
            group_id,
            capacity,
            epoch,
            epoch_secret,
            transcript_hash,
            nodes,
            target_leaf,
        })
    }
}

// ---------------------------------------------------------------------
// Per-sender application-data chain (module docs: a single forward hash
// chain per sender per epoch, not MLS's full secret tree).
// ---------------------------------------------------------------------

#[derive(Clone)]
struct ChainKey([u8; 32]);

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ChainKey {
    fn advance(&self) -> (ChainKey, [u8; 32]) {
        (
            ChainKey(hmac32(&self.0, LABEL_NEXT_CHAIN)),
            hmac32(&self.0, LABEL_MESSAGE_KEY),
        )
    }
}

fn hmac32(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn derive_sender_chain(application_secret: &[u8; 32], leaf: u32) -> Result<ChainKey> {
    let (prk, _) = Hkdf::<Sha256>::extract(None, application_secret);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut info = Vec::with_capacity(LABEL_SENDER_CHAIN.len() + 4);
    info.extend_from_slice(LABEL_SENDER_CHAIN);
    info.extend_from_slice(&leaf.to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(ChainKey(out))
}

// ---------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------

/// A TreeKEM-inspired group's current state, as seen by one member.
pub struct Group {
    group_id: [u8; 16],
    capacity: usize,
    nodes: Vec<TreeNode>,
    epoch: u64,
    epoch_secret: [u8; 32],
    application_secret: [u8; 32],
    transcript_hash: [u8; 32],
    my_leaf: usize,
    my_leaf_keys: Option<(StaticSecret, MlKemDecapsulationKey)>,
    /// Secrets this member currently holds for internal nodes — a subset
    /// of `nodes` bounded by tree depth (`O(log n)` entries at any time in
    /// practice, since only ancestors of `my_leaf` are ever populated
    /// here).
    known_secrets: HashMap<usize, [u8; 32]>,
    send_seq: u64,
    send_chain: ChainKey,
    recv_chains: HashMap<u32, (ChainKey, u64)>,
}

impl Drop for Group {
    fn drop(&mut self) {
        self.epoch_secret.zeroize();
        self.application_secret.zeroize();
        for secret in self.known_secrets.values_mut() {
            secret.zeroize();
        }
    }
}

fn initial_epoch_secret(group_id: &[u8; 16]) -> [u8; 32] {
    let mut init = [0u8; 32];
    getrandom::fill(&mut init).expect("OS randomness source failed");
    let mut ikm = Vec::with_capacity(32 + 16);
    ikm.extend_from_slice(&init);
    ikm.extend_from_slice(group_id);
    let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
    let hk = Hkdf::<Sha256>::from_prk(&prk).expect("HKDF PRK is always the SHA-256 output length");
    let mut out = [0u8; 32];
    hk.expand(LABEL_EPOCH_SECRET, &mut out)
        .expect("32-byte output is within HKDF-SHA256's expand limit");
    out
}

fn genesis_transcript_hash(group_id: &[u8; 16]) -> [u8; 32] {
    Sha256::digest(group_id).into()
}

fn derive_application_secret(epoch_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(None, epoch_secret);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut out = [0u8; 32];
    hk.expand(LABEL_APPLICATION_SECRET, &mut out)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(out)
}

impl Group {
    /// Starts a brand-new group with `my_leaf_key_package` as its sole,
    /// founding member, at leaf 0 of a tree with room for `capacity`
    /// leaves (must be a power of two, at least 2 — module docs on why
    /// capacity is fixed for the group's lifetime).
    pub fn create(my_identity: &Identity, capacity: usize) -> Result<Self> {
        if capacity < 2 || !capacity.is_power_of_two() {
            return Err(Error::Malformed(
                "group capacity must be a power of two of at least 2",
            ));
        }
        let my_key_package = MyLeafKeyPackage::generate(my_identity);
        let mut nodes = vec![TreeNode::Blank; 2 * capacity - 1];
        nodes[leaf_to_node(capacity, 0)] = TreeNode::Leaf(Box::new(my_key_package.public()));

        let group_id = {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).expect("OS randomness source failed");
            id
        };
        let epoch_secret = initial_epoch_secret(&group_id);
        let application_secret = derive_application_secret(&epoch_secret)?;
        let send_chain = derive_sender_chain(&application_secret, 0)?;

        Ok(Group {
            group_id,
            capacity,
            nodes,
            epoch: 0,
            epoch_secret,
            application_secret,
            transcript_hash: genesis_transcript_hash(&group_id),
            my_leaf: 0,
            my_leaf_keys: Some((my_key_package.dh_secret, my_key_package.kem_secret)),
            known_secrets: HashMap::new(),
            send_seq: 0,
            send_chain,
            recv_chains: HashMap::new(),
        })
    }

    pub fn group_id(&self) -> [u8; 16] {
        self.group_id
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn my_leaf_index(&self) -> usize {
        self.my_leaf
    }

    pub fn is_member(&self, leaf: usize) -> bool {
        leaf < self.capacity
            && matches!(
                self.nodes[leaf_to_node(self.capacity, leaf)],
                TreeNode::Leaf(_)
            )
    }

    fn first_blank_leaf(&self) -> Option<usize> {
        (0..self.capacity).find(|&leaf| !self.is_member(leaf))
    }

    /// Proposes adding `new_member`, committing it immediately: generates a
    /// fresh path update from this member's own leaf, encrypts it to the
    /// current tree's resolutions (and the new member directly, for the
    /// levels only they need), advances this member's own state to the new
    /// epoch, and returns both the [`Commit`] to broadcast to existing
    /// members and the [`Welcome`] to send the new member out of band.
    pub fn propose_add(
        &mut self,
        signer: &Identity,
        new_member: LeafKeyPackage,
    ) -> Result<(Commit, Welcome)> {
        let target_leaf = self.first_blank_leaf().ok_or(Error::GroupFull)?;

        // Snapshot the group *before* this commit's path update, for the
        // welcome: the joining member decrypts the accompanying Commit
        // against exactly this state.
        let snapshot = WelcomeSnapshot {
            group_id: self.group_id,
            capacity: self.capacity as u32,
            epoch: self.epoch,
            epoch_secret: self.epoch_secret,
            transcript_hash: self.transcript_hash,
            nodes: self.nodes.clone(),
            target_leaf: target_leaf as u32,
        };
        let mut w = Writer::new();
        snapshot.write(&mut w);
        let sealed = seal_to_node(&new_member.public_key, WELCOME_AAD_CONTEXT, &w.into_bytes())?;
        let welcome = Welcome { sealed };

        let op = GroupOp::Add {
            leaf_index: target_leaf as u32,
            key_package: Box::new(new_member),
        };
        let commit = self.commit(signer, op)?;
        Ok((commit, welcome))
    }

    /// Removes `leaf_index`, committing immediately. The removed member's
    /// entire ancestor path is blanked (module docs on why that, not just
    /// blanking their leaf, is what actually excludes them going forward)
    /// before this member's own fresh path update is layered on top.
    pub fn propose_remove(&mut self, signer: &Identity, leaf_index: usize) -> Result<Commit> {
        if !self.is_member(leaf_index) {
            return Err(Error::NotAGroupMember);
        }
        self.commit(
            signer,
            GroupOp::Remove {
                leaf_index: leaf_index as u32,
            },
        )
    }

    /// Refreshes this member's own path with no structural change — pure
    /// post-compromise security, the group-scale equivalent of
    /// [`crate::ratchet::RatchetedSession::initiate_ratchet`].
    pub fn propose_update(&mut self, signer: &Identity) -> Result<Commit> {
        self.commit(signer, GroupOp::Update)
    }

    /// Applies `op`'s structural change to a tree snapshot and returns it,
    /// without touching `self` — used both to build the pre-commit view a
    /// path update is encrypted against and, identically, by every
    /// receiver of a [`Commit`] to reproduce that same view.
    fn spliced(&self, op: &GroupOp) -> Result<Vec<TreeNode>> {
        let mut nodes = self.nodes.clone();
        match op {
            GroupOp::Add {
                leaf_index,
                key_package,
            } => {
                let node = leaf_to_node(self.capacity, *leaf_index as usize);
                if *leaf_index as usize >= self.capacity || !matches!(nodes[node], TreeNode::Blank)
                {
                    return Err(Error::Malformed(
                        "add targets a non-blank or out-of-range leaf",
                    ));
                }
                nodes[node] = TreeNode::Leaf(key_package.clone());
            }
            GroupOp::Remove { leaf_index } => {
                let leaf = *leaf_index as usize;
                if leaf >= self.capacity {
                    return Err(Error::Malformed("remove targets an out-of-range leaf"));
                }
                let leaf_node = leaf_to_node(self.capacity, leaf);
                if matches!(nodes[leaf_node], TreeNode::Blank) {
                    return Err(Error::NotAGroupMember);
                }
                nodes[leaf_node] = TreeNode::Blank;
                for ancestor in direct_path(self.capacity, leaf) {
                    nodes[ancestor] = TreeNode::Blank;
                }
            }
            GroupOp::Update => {}
        }
        Ok(nodes)
    }

    fn commit(&mut self, signer: &Identity, op: GroupOp) -> Result<Commit> {
        let pre_commit_nodes = self.spliced(&op)?;
        let my_leaf_node = leaf_to_node(self.capacity, self.my_leaf);
        let path = direct_path(self.capacity, self.my_leaf);

        let mut secret = {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).expect("OS randomness source failed");
            s
        };
        let mut path_nodes = Vec::with_capacity(path.len());
        let mut new_known = HashMap::new();
        let mut prev = my_leaf_node;

        for &d in &path {
            let (_, dh_public, _, kem_public) = derive_node_keypair(&secret)?;
            new_known.insert(d, secret);

            let target = sibling(prev).expect("every direct-path predecessor has a sibling");
            let targets = resolution(&pre_commit_nodes, self.capacity, target);
            let mut ciphertexts = Vec::with_capacity(targets.len());
            for t in targets {
                let pk = node_public_key(&pre_commit_nodes, t);
                ciphertexts.push(seal_to_node(pk, PATH_SECRET_AAD_CONTEXT, &secret)?);
            }
            path_nodes.push(UpdatePathNode {
                public_key: NodePublicKey {
                    dh_public,
                    kem_public,
                },
                ciphertexts,
            });

            prev = d;
            secret = hkdf_expand32(&secret, LABEL_PATH_STEP)?;
        }

        let commit_secret = *new_known
            .get(
                path.last()
                    .expect("a group of >=2 capacity always has a nonempty direct path"),
            )
            .expect("just inserted");

        let signed = commit_signed_bytes(
            &self.group_id,
            self.epoch,
            self.my_leaf as u32,
            &op,
            &path_nodes,
        );
        let signature = signer.sign(&signed);

        self.apply(
            &pre_commit_nodes,
            &path,
            &path_nodes,
            commit_secret,
            &signed,
        )?;
        for (node, secret) in new_known {
            self.known_secrets.insert(node, secret);
        }

        Ok(Commit {
            group_id: self.group_id,
            from_epoch: self.epoch - 1, // `apply` above already advanced `self.epoch`
            sender_leaf: self.my_leaf as u32,
            op,
            path: path_nodes,
            signature,
        })
    }

    /// Applies a received [`Commit`] from another member: verifies its
    /// signature, reproduces the pre-commit tree, locates and decrypts
    /// this member's own entry in the path update, and advances to the new
    /// epoch. Every current member (other than the committer) reaches
    /// exactly one matching entry, by construction (module docs).
    pub fn apply_commit(&mut self, commit: &Commit) -> Result<()> {
        if commit.group_id != self.group_id {
            return Err(Error::Malformed("commit is for a different group"));
        }
        if commit.from_epoch != self.epoch {
            return Err(Error::WrongState);
        }
        let sender_leaf = commit.sender_leaf as usize;
        if !self.is_member(sender_leaf) {
            return Err(Error::NotAGroupMember);
        }
        let sender_identity = match &self.nodes[leaf_to_node(self.capacity, sender_leaf)] {
            TreeNode::Leaf(lp) => lp.identity.clone(),
            _ => unreachable!("is_member just confirmed this leaf is populated"),
        };
        let signed = commit_signed_bytes(
            &commit.group_id,
            commit.from_epoch,
            commit.sender_leaf,
            &commit.op,
            &commit.path,
        );
        sender_identity.verify(&signed, &commit.signature)?;

        let pre_commit_nodes = self.spliced(&commit.op)?;
        let path = direct_path(self.capacity, sender_leaf);
        if path.len() != commit.path.len() {
            return Err(Error::Malformed(
                "commit path length does not match tree depth",
            ));
        }

        let (found_level, mut secret) =
            self.find_and_decrypt(&pre_commit_nodes, sender_leaf, &path, &commit.path)?;

        let mut new_known = HashMap::new();
        for i in found_level..path.len() {
            let (_, dh_public, _, kem_public) = derive_node_keypair(&secret)?;
            if (NodePublicKey {
                dh_public,
                kem_public: kem_public.clone(),
            }) != commit.path[i].public_key
            {
                return Err(Error::PathKeyMismatch);
            }
            new_known.insert(path[i], secret);
            if i + 1 < path.len() {
                secret = hkdf_expand32(&secret, LABEL_PATH_STEP)?;
            }
        }
        let commit_secret = *new_known
            .get(path.last().expect("nonempty path"))
            .expect("inserted above");

        self.apply(
            &pre_commit_nodes,
            &path,
            &commit.path,
            commit_secret,
            &signed,
        )?;
        for (node, secret) in new_known {
            self.known_secrets.insert(node, secret);
        }
        Ok(())
    }

    /// Finds the one path level whose sibling resolution this member can
    /// decrypt from — either their own leaf key (a newly added member) or
    /// an internal node secret already in `known_secrets` — and returns
    /// that level's index together with the decrypted path secret.
    fn find_and_decrypt(
        &self,
        pre_commit_nodes: &[TreeNode],
        sender_leaf: usize,
        path: &[usize],
        commit_path: &[UpdatePathNode],
    ) -> Result<(usize, [u8; 32])> {
        let mut prev = leaf_to_node(self.capacity, sender_leaf);
        for (i, &d) in path.iter().enumerate() {
            let target = sibling(prev).expect("every direct-path predecessor has a sibling");
            let targets = resolution(pre_commit_nodes, self.capacity, target);
            for t in targets {
                if t == leaf_to_node(self.capacity, self.my_leaf) {
                    if let Some((dh_secret, kem_secret)) = &self.my_leaf_keys {
                        for ct in &commit_path[i].ciphertexts {
                            if let Ok(bytes) =
                                open_from_node(dh_secret, kem_secret, PATH_SECRET_AAD_CONTEXT, ct)
                            {
                                let secret: [u8; 32] =
                                    bytes.as_slice().try_into().map_err(|_| {
                                        Error::Malformed(
                                            "decrypted path secret has the wrong length",
                                        )
                                    })?;
                                return Ok((i, secret));
                            }
                        }
                    }
                } else if let Some(known) = self.known_secrets.get(&t) {
                    let (dh_secret, _, kem_secret, _) = derive_node_keypair(known)?;
                    for ct in &commit_path[i].ciphertexts {
                        if let Ok(bytes) =
                            open_from_node(&dh_secret, &kem_secret, PATH_SECRET_AAD_CONTEXT, ct)
                        {
                            let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                                Error::Malformed("decrypted path secret has the wrong length")
                            })?;
                            return Ok((i, secret));
                        }
                    }
                }
            }
            prev = d;
        }
        Err(Error::CommitNotDecryptable)
    }

    /// Common tail of building and receiving a commit: install the
    /// post-commit tree, mix `commit_secret` into a fresh epoch, and reset
    /// this epoch's sender chains.
    fn apply(
        &mut self,
        pre_commit_nodes: &[TreeNode],
        path: &[usize],
        path_nodes: &[UpdatePathNode],
        commit_secret: [u8; 32],
        signed_commit_bytes: &[u8],
    ) -> Result<()> {
        self.nodes = pre_commit_nodes.to_vec();
        for (&d, node) in path.iter().zip(path_nodes) {
            self.nodes[d] = TreeNode::Parent(Box::new(node.public_key.clone()));
        }

        let mut transcript_ikm = Vec::with_capacity(64 + signed_commit_bytes.len());
        transcript_ikm.extend_from_slice(&self.transcript_hash);
        transcript_ikm.extend_from_slice(signed_commit_bytes);
        self.transcript_hash = Sha256::digest(&transcript_ikm).into();

        let (prk, _) = Hkdf::<Sha256>::extract(Some(self.epoch_secret.as_slice()), &commit_secret);
        let hk =
            Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
        let mut info = Vec::with_capacity(LABEL_EPOCH_SECRET.len() + 32);
        info.extend_from_slice(LABEL_EPOCH_SECRET);
        info.extend_from_slice(&self.transcript_hash);
        let mut new_epoch_secret = [0u8; 32];
        hk.expand(&info, &mut new_epoch_secret)
            .map_err(|_| Error::Malformed("HKDF expand failed"))?;

        self.epoch_secret.zeroize();
        self.epoch_secret = new_epoch_secret;
        self.application_secret.zeroize();
        self.application_secret = derive_application_secret(&self.epoch_secret)?;
        self.epoch += 1;
        self.send_chain = derive_sender_chain(&self.application_secret, self.my_leaf as u32)?;
        self.send_seq = 0;
        self.recv_chains.clear();
        Ok(())
    }

    /// Seals one application record for this epoch's group members.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (next_chain, message_key) = self.send_chain.advance();
        let header = app_header(self.epoch, self.my_leaf as u32, self.send_seq);
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        let ciphertext = aead_seal(&message_key, &header, plaintext)?;
        self.send_chain = next_chain;

        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens one application record. Only the current epoch is accepted
    /// (module docs); a message from an ended epoch returns
    /// [`Error::UnknownEpoch`].
    pub fn open(&mut self, record: &[u8]) -> Result<(usize, Vec<u8>)> {
        if record.len() < 20 {
            return Err(Error::Malformed("group record shorter than its header"));
        }
        let epoch = u64::from_be_bytes(record[..8].try_into().expect("checked length"));
        let sender_leaf = u32::from_be_bytes(record[8..12].try_into().expect("checked length"));
        let seq = u64::from_be_bytes(record[12..20].try_into().expect("checked length"));
        if epoch != self.epoch {
            return Err(Error::UnknownEpoch);
        }
        if sender_leaf as usize == self.my_leaf {
            return Err(Error::Malformed(
                "received a record from our own sender leaf",
            ));
        }
        if !self.is_member(sender_leaf as usize) {
            return Err(Error::NotAGroupMember);
        }

        let header = &record[..20];
        let ciphertext = &record[20..];

        let needs_init = !self.recv_chains.contains_key(&sender_leaf);
        if needs_init {
            let chain = derive_sender_chain(&self.application_secret, sender_leaf)?;
            self.recv_chains.insert(sender_leaf, (chain, 0));
        }
        let (chain, expected_seq) = self
            .recv_chains
            .get(&sender_leaf)
            .expect("just ensured present");
        if seq != *expected_seq {
            return Err(Error::Replay);
        }
        let (next_chain, message_key) = chain.advance();
        let plaintext = aead_seal_open(&message_key, header, ciphertext)?;

        let entry = self
            .recv_chains
            .get_mut(&sender_leaf)
            .expect("just ensured present");
        entry.0 = next_chain;
        entry.1 += 1;

        Ok((sender_leaf as usize, plaintext))
    }

    /// Joins a group as the member a [`Welcome`]/[`Commit`] pair was just
    /// issued for: unseals the snapshot, then applies the accompanying
    /// commit exactly as any other member would, arriving at the same
    /// post-commit epoch.
    pub fn join(
        my_key_package: MyLeafKeyPackage,
        welcome: &Welcome,
        commit: &Commit,
    ) -> Result<Self> {
        let plaintext = open_from_node(
            &my_key_package.dh_secret,
            &my_key_package.kem_secret,
            WELCOME_AAD_CONTEXT,
            &welcome.sealed,
        )?;
        let mut r = Reader::new(&plaintext);
        let mut snapshot = WelcomeSnapshot::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in welcome snapshot"));
        }

        let application_secret = derive_application_secret(&snapshot.epoch_secret)?;
        let mut group = Group {
            group_id: snapshot.group_id,
            capacity: snapshot.capacity as usize,
            // `snapshot` has a `Drop` impl (zeroizes `epoch_secret`), which
            // forbids moving a non-`Copy` field like `nodes` out by value —
            // `mem::take` swaps in an empty `Vec` instead, which is fine
            // since `snapshot` is dropped right after this block anyway.
            nodes: std::mem::take(&mut snapshot.nodes),
            epoch: snapshot.epoch,
            epoch_secret: snapshot.epoch_secret,
            application_secret,
            transcript_hash: snapshot.transcript_hash,
            my_leaf: snapshot.target_leaf as usize,
            my_leaf_keys: Some((my_key_package.dh_secret, my_key_package.kem_secret)),
            known_secrets: HashMap::new(),
            send_seq: 0,
            send_chain: ChainKey([0u8; 32]), // overwritten by `apply_commit` below
            recv_chains: HashMap::new(),
        };
        group.apply_commit(commit)?;
        Ok(group)
    }
}

fn app_header(epoch: u64, sender_leaf: u32, seq: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(&epoch.to_be_bytes());
    out[8..12].copy_from_slice(&sender_leaf.to_be_bytes());
    out[12..20].copy_from_slice(&seq.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_member_group() -> (Group, Group, Identity, Identity) {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();
        let mut alice = Group::create(&alice_id, 4).unwrap();

        let bob_key_package = MyLeafKeyPackage::generate(&bob_id);
        let (commit, welcome) = alice
            .propose_add(&alice_id, bob_key_package.public())
            .unwrap();
        let bob = Group::join(bob_key_package, &welcome, &commit).unwrap();
        (alice, bob, alice_id, bob_id)
    }

    #[test]
    fn commit_and_welcome_round_trip_through_bytes() {
        let alice_id = Identity::generate();
        let mut alice = Group::create(&alice_id, 4).unwrap();
        let bob_key_package = MyLeafKeyPackage::generate(&Identity::generate());

        let (commit, welcome) = alice
            .propose_add(&alice_id, bob_key_package.public())
            .unwrap();

        let commit_bytes = commit.to_bytes();
        let welcome_bytes = welcome.to_bytes();
        let commit_from_bytes = Commit::from_bytes(&commit_bytes).unwrap();
        let welcome_from_bytes = Welcome::from_bytes(&welcome_bytes).unwrap();

        // The round-tripped pair works exactly like the originals: a
        // fresh member can join from them alone.
        let bob = Group::join(bob_key_package, &welcome_from_bytes, &commit_from_bytes).unwrap();
        assert_eq!(bob.epoch(), 1);
        assert_eq!(bob.my_leaf_index(), 1);
    }

    /// A prospective member's own `LeafKeyPackage` round-trips through
    /// bytes and still works to join with — this is the half of the flow
    /// that has to cross a real network before anyone can call
    /// `propose_add` on it, unlike `commit_and_welcome_round_trip_through_bytes`
    /// above where both values are already in the founder's hands.
    #[test]
    fn leaf_key_package_round_trips_through_bytes_and_still_joins() {
        let alice_id = Identity::generate();
        let mut alice = Group::create(&alice_id, 4).unwrap();
        let bob_key_package = MyLeafKeyPackage::generate(&Identity::generate());

        let sent_bytes = bob_key_package.public().to_bytes();
        let received = LeafKeyPackage::from_bytes(&sent_bytes).unwrap();

        let (commit, welcome) = alice.propose_add(&alice_id, received).unwrap();
        let bob = Group::join(bob_key_package, &welcome, &commit).unwrap();
        assert_eq!(bob.epoch(), 1);
        assert_eq!(bob.my_leaf_index(), 1);

        assert!(LeafKeyPackage::from_bytes(b"not a real leaf key package").is_err());
    }

    /// `seal_to_node`/`Welcome` are a one-shot, sender-anonymous envelope
    /// (module docs on [`leaf_key_package_pop_message`]): anyone who knows
    /// a victim's published `LeafKeyPackage` can encrypt an arbitrary
    /// plaintext that decrypts cleanly under the victim's own keys. A
    /// forged `capacity` of 0 used to reach `2 * (capacity as usize) - 1`
    /// in `WelcomeSnapshot::read` and panic on subtract-overflow (this
    /// workspace's release profile runs with `overflow-checks = true`) —
    /// a remote crash triggerable by anyone who can address a `Welcome` to
    /// a member's public key, no group membership required. It must be
    /// rejected as malformed instead.
    #[test]
    fn a_forged_zero_capacity_welcome_snapshot_is_rejected_not_panicked_on() {
        let mut w = Writer::new();
        w.put_fixed(&[0u8; 16]); // group_id
        w.put_fixed(&0u32.to_be_bytes()); // capacity = 0
        w.put_fixed(&0u64.to_be_bytes()); // epoch
        w.put_fixed(&[0u8; 32]); // epoch_secret
        w.put_fixed(&[0u8; 32]); // transcript_hash
        w.put_fixed(&0u32.to_be_bytes()); // target_leaf
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            WelcomeSnapshot::read(&mut r),
            Err(Error::Malformed(_))
        ));
    }

    /// Same forged-plaintext threat model as the zero-capacity case above,
    /// but targeting `target_leaf`: a value at or past `capacity` used to
    /// have nothing checking it, so `Group::join` would later index
    /// `nodes` out of bounds and panic instead of erroring.
    #[test]
    fn a_forged_out_of_range_target_leaf_is_rejected_not_panicked_on() {
        let mut w = Writer::new();
        w.put_fixed(&[0u8; 16]); // group_id
        w.put_fixed(&4u32.to_be_bytes()); // capacity = 4
        w.put_fixed(&0u64.to_be_bytes()); // epoch
        w.put_fixed(&[0u8; 32]); // epoch_secret
        w.put_fixed(&[0u8; 32]); // transcript_hash
        w.put_fixed(&4u32.to_be_bytes()); // target_leaf == capacity, out of range
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            WelcomeSnapshot::read(&mut r),
            Err(Error::Malformed(_))
        ));
    }

    /// A `LeafKeyPackage` whose `identity` doesn't match the key material
    /// its proof-of-possession was actually signed over (here: swapping in
    /// a *different* real identity, itself perfectly validly signed on its
    /// own package) must not deserialize — otherwise whoever calls
    /// [`Group::propose_add`] on it has no way to tell that the party
    /// publishing this package doesn't actually control the identity it
    /// claims, and the tree would record an attacker's key under a
    /// victim's name.
    #[test]
    fn a_leaf_key_package_with_a_swapped_identity_is_rejected() {
        let victim = MyLeafKeyPackage::generate(&Identity::generate());
        let attacker = MyLeafKeyPackage::generate(&Identity::generate());

        let mut forged = attacker.public();
        forged.identity = victim.public().identity;
        // `forged.pop` is still the attacker's signature over the
        // attacker's own (identity, public_key) pair, not this
        // frankensteined combination, so it must fail verification.
        let bytes = forged.to_bytes();
        assert!(matches!(
            LeafKeyPackage::from_bytes(&bytes),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicked_on() {
        assert!(Commit::from_bytes(b"not a real commit").is_err());
        assert!(Welcome::from_bytes(b"not a real welcome").is_err());
        assert!(Commit::from_bytes(&[]).is_err());
        assert!(Welcome::from_bytes(&[]).is_err());
    }

    #[test]
    fn add_brings_both_members_to_the_same_epoch() {
        let (alice, bob, _alice_id, _bob_id) = two_member_group();
        assert_eq!(alice.epoch(), 1);
        assert_eq!(bob.epoch(), 1);
        assert_eq!(alice.my_leaf_index(), 0);
        assert_eq!(bob.my_leaf_index(), 1);
        assert!(alice.is_member(1));
        assert!(bob.is_member(0));
    }

    #[test]
    fn application_messages_round_trip_after_add() {
        let (mut alice, mut bob, _alice_id, _bob_id) = two_member_group();

        let record = alice.seal(b"hi bob").unwrap();
        let (sender, plaintext) = bob.open(&record).unwrap();
        assert_eq!(sender, 0);
        assert_eq!(plaintext, b"hi bob");

        let record = bob.seal(b"hi alice").unwrap();
        let (sender, plaintext) = alice.open(&record).unwrap();
        assert_eq!(sender, 1);
        assert_eq!(plaintext, b"hi alice");
    }

    #[test]
    fn a_third_member_joins_and_everyone_converges() {
        let (mut alice, mut bob, alice_id, _bob_id) = two_member_group();
        let carol_id = Identity::generate();
        let carol_key_package = MyLeafKeyPackage::generate(&carol_id);

        let (commit, welcome) = alice
            .propose_add(&alice_id, carol_key_package.public())
            .unwrap();
        bob.apply_commit(&commit).unwrap();
        let mut carol = Group::join(carol_key_package, &welcome, &commit).unwrap();

        assert_eq!(alice.epoch(), 2);
        assert_eq!(bob.epoch(), 2);
        assert_eq!(carol.epoch(), 2);
        assert_eq!(carol.my_leaf_index(), 2);

        let record = carol.seal(b"hi from carol").unwrap();
        let (sender, plaintext) = alice.open(&record).unwrap();
        assert_eq!(sender, 2);
        assert_eq!(plaintext, b"hi from carol");
        let (sender, plaintext) = bob.open(&record).unwrap();
        assert_eq!(sender, 2);
        assert_eq!(plaintext, b"hi from carol");
    }

    #[test]
    fn update_rekeys_without_changing_membership() {
        let (mut alice, mut bob, alice_id, _bob_id) = two_member_group();
        let commit = alice.propose_update(&alice_id).unwrap();
        bob.apply_commit(&commit).unwrap();

        assert_eq!(alice.epoch(), 2);
        assert_eq!(bob.epoch(), 2);
        assert!(bob.is_member(0));
        assert!(bob.is_member(1));

        let record = alice.seal(b"post-update").unwrap();
        let (_sender, plaintext) = bob.open(&record).unwrap();
        assert_eq!(plaintext, b"post-update");
    }

    #[test]
    fn removed_member_cannot_decrypt_future_traffic() {
        let (mut alice, mut bob, alice_id, _bob_id) = two_member_group();
        let carol_id = Identity::generate();
        let carol_key_package = MyLeafKeyPackage::generate(&carol_id);
        let (commit, welcome) = alice
            .propose_add(&alice_id, carol_key_package.public())
            .unwrap();
        bob.apply_commit(&commit).unwrap();
        let mut carol = Group::join(carol_key_package, &welcome, &commit).unwrap();

        // Alice removes Carol.
        let remove_commit = alice.propose_remove(&alice_id, 2).unwrap();
        bob.apply_commit(&remove_commit).unwrap();
        assert!(!alice.is_member(2));
        assert!(!bob.is_member(2));

        // A message sealed in the post-removal epoch must not be openable
        // with Carol's last-known epoch state: her `Group` never advances
        // past the pre-removal epoch, so decrypting fails at the epoch
        // check before any key material is even tried.
        let record = alice.seal(b"carol should not see this").unwrap();
        assert_eq!(carol.epoch(), 2);
        let result = carol.open(&record);
        assert!(matches!(result, Err(Error::UnknownEpoch)));

        let (_sender, plaintext) = bob.open(&record).unwrap();
        assert_eq!(plaintext, b"carol should not see this");
    }

    #[test]
    fn adding_past_capacity_fails() {
        let alice_id = Identity::generate();
        let mut alice = Group::create(&alice_id, 2).unwrap();
        let bob_key_package = MyLeafKeyPackage::generate(&Identity::generate());
        alice
            .propose_add(&alice_id, bob_key_package.public())
            .unwrap();

        let carol_key_package = MyLeafKeyPackage::generate(&Identity::generate());
        let result = alice.propose_add(&alice_id, carol_key_package.public());
        assert!(matches!(result, Err(Error::GroupFull)));
    }

    #[test]
    fn a_commit_with_a_corrupted_signature_is_rejected() {
        let (mut alice, mut bob, alice_id, _bob_id) = two_member_group();
        let mut tampered = alice.propose_update(&alice_id).unwrap();
        tampered.signature.ed25519 = ed25519_dalek::Signature::from_bytes(&[0xFFu8; 64]);
        let result = bob.apply_commit(&tampered);
        assert!(matches!(result, Err(Error::BadSignature)));
    }

    #[test]
    fn a_commit_at_the_wrong_epoch_is_rejected() {
        let (mut alice, mut bob, alice_id, _bob_id) = two_member_group();
        let commit1 = alice.propose_update(&alice_id).unwrap();
        // Bob is still at epoch 1; skip applying commit1 and try a second
        // commit that assumes epoch 2.
        let commit2 = alice.propose_update(&alice_id).unwrap();
        let result = bob.apply_commit(&commit2);
        assert!(matches!(result, Err(Error::WrongState)));
        // Applying them in order works fine.
        bob.apply_commit(&commit1).unwrap();
        bob.apply_commit(&commit2).unwrap();
        assert_eq!(bob.epoch(), 3);
    }

    /// Builds a 4-member group (capacity 4, so the tree has real internal
    /// structure: two depth-2 subtrees under the root) and has every
    /// member commit at least once, exercising path levels beyond the
    /// trivial 2-member case — including a member decrypting via a cached
    /// *internal* node secret (`known_secrets`), not just their own raw
    /// leaf key.
    #[test]
    fn a_four_member_tree_stays_consistent_across_every_members_commits() {
        let founder_id = Identity::generate();
        let mut founder = Group::create(&founder_id, 4).unwrap();

        let member_ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
        let mut members = Vec::new();
        for id in &member_ids {
            let key_package = MyLeafKeyPackage::generate(id);
            let (commit, welcome) = founder
                .propose_add(&founder_id, key_package.public())
                .unwrap();
            for m in members.iter_mut() {
                let m: &mut Group = m;
                m.apply_commit(&commit).unwrap();
            }
            let joined = Group::join(key_package, &welcome, &commit).unwrap();
            members.push(joined);
        }
        // founder = leaf 0, members[0..2] = leaves 1..3.
        assert_eq!(founder.epoch(), 3);
        for m in &members {
            assert_eq!(m.epoch(), 3);
        }

        // Leaf 3 (members[2], under the root's right subtree) commits an
        // update. Its direct path is [right-subtree-root, root] — level 0's
        // sibling is leaf 2 (members[1]), level 1 (root)'s sibling is the
        // left subtree root, which is already populated from the earlier
        // adds, so founder/members[0] (leaves 0/1, under the left subtree)
        // must decrypt via that *cached internal-node* secret, not a raw
        // leaf key.
        let commit = members[2].propose_update(&member_ids[2]).unwrap();
        founder.apply_commit(&commit).unwrap();
        members[0].apply_commit(&commit).unwrap();
        members[1].apply_commit(&commit).unwrap();

        assert_eq!(founder.epoch(), 4);
        for m in &members {
            assert_eq!(m.epoch(), 4);
        }

        // Every pair can still exchange application data post-commit.
        let record = founder.seal(b"to everyone").unwrap();
        for m in members.iter_mut() {
            let (sender, plaintext) = m.open(&record).unwrap();
            assert_eq!(sender, 0);
            assert_eq!(plaintext, b"to everyone");
        }

        let record = members[2].seal(b"from leaf 3").unwrap();
        let (sender, plaintext) = founder.open(&record).unwrap();
        assert_eq!(sender, 3);
        assert_eq!(plaintext, b"from leaf 3");
    }
}
