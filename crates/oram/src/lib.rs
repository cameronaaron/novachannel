//! Path ORAM: oblivious storage where the sequence of physical locations
//! touched is independent of which logical block was accessed, so an
//! observer of access patterns (not contents) learns nothing about which
//! block is read or written.
//!
//! # Where this fits
//! Even with a confidential, authenticated channel (`novachannel`) and an
//! anonymous membership proof (`novachannel-rln`), a server holding
//! per-user state (rate-limit counters, nullifier sets, ...) leaks identity
//! through *which record it touched*: "record #4821 was read" narrows the
//! sender to its owner. Path ORAM closes that for server-side lookups.
//!
//! # Complexity
//! Each `PathOram::access` touches `O(log n)` buckets. That is a proven
//! lower bound (Goldreich-Ostrovsky): hiding the access pattern over `n`
//! blocks with `O(1)` client storage needs `Ω(log n)` amortized bandwidth
//! per access. `O(1)` ORAM is impossible, not an engineering gap.
//!
//! # Client/server split
//! [`Client`] holds only the secret state (position map and stash) and
//! reaches buckets only through the [`ServerStorage`] trait, so "the
//! position map and stash never sit with server storage" is enforced by the
//! types. [`InMemoryServer`] is the reference implementation; a networked
//! deployment implements the trait over RPC with no change to `Client`.
//! `examples/networked_server.rs` demonstrates it: a `TcpServerStorage`
//! sends every bucket operation over a real TCP socket to a server thread
//! backed by [`InMemoryServer`], and the same `Client::read`/`write` calls
//! round-trip through it. [`PathOram`] is `Client<V, InMemoryServer<V>>`.
//!
//! The split alone leaves [`Block`]'s `id` and `value` in the clear in
//! [`InMemoryServer`]. [`EncryptingServerStorage`] (CONFIDENTIALITY section)
//! is an opt-in decorator for opaque `Vec<u8>` values, such as serialized
//! counters or nullifier entries, needing no change to [`Client`]. It is
//! also what makes the obliviousness claim above hold against a server that
//! watches *sizes*: every bucket is written back as exactly `Z` equal-length
//! ciphertexts, padded with encrypted dummies, hiding both occupancy and
//! value length. Plaintext `V` through a bare [`InMemoryServer`] exposes
//! both, and the values.
//!
//! Key management is out of scope: the caller provisions and rotates the
//! AEAD key, the same boundary `novachannel::handshake`'s peer-identity
//! pinning draws.
//!
//! # Algorithm
//! Standard Path ORAM (Stefanov et al., CCS 2013): a binary tree of buckets
//! of up to `Z` blocks. Each block maps to a uniformly random leaf and lives
//! somewhere on the root-to-leaf path or in the client stash. Every access,
//! read or write alike, remaps the target to a new random leaf, moves every
//! bucket on the old path into the stash, updates the target, and greedily
//! evicts the stash back onto the path, deepest eligible bucket first.

#![forbid(unsafe_code)]
// Each `.unwrap()` must become an `.expect("why it can't fail")` or is a
// bug (libsignal's `protocol`/`zkgroup` crates enforce the same lint).
// Allowed in tests, on values the test just built.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::HashMap;

use rand::{Rng, RngExt};

pub type BlockId = u64;

#[derive(Clone)]
pub struct Block<V> {
    pub id: BlockId,
    pub value: V,
}

/// What an untrusted server implements: bucket storage by node index, with
/// no knowledge of which block belongs to whom (the position map lives only
/// in [`Client`]). Heap numbering: root 1, children of `i` are `2i`/`2i+1`,
/// leaves `num_leaves..2*num_leaves`.
pub trait ServerStorage<V> {
    /// Reads every block currently in bucket `node` and leaves it empty —
    /// matches Path ORAM's "read the whole path into the stash" step.
    fn read_and_clear(&mut self, node: usize) -> Vec<Block<V>>;
    /// Replaces bucket `node`'s contents (the eviction write-back step).
    fn write(&mut self, node: usize, blocks: Vec<Block<V>>);
    /// Per-bucket capacity (`Z`); [`Client`] needs this to know how many
    /// blocks it may evict into one bucket.
    fn bucket_capacity(&self) -> usize;
}

/// The reference [`ServerStorage`]: in-process `Vec` buckets, standing in
/// for a networked server (see the module docs).
pub struct InMemoryServer<V> {
    bucket_capacity: usize,
    buckets: Vec<Vec<Block<V>>>,
}

impl<V> InMemoryServer<V> {
    pub fn new(num_nodes: usize, bucket_capacity: usize) -> Self {
        InMemoryServer {
            bucket_capacity,
            buckets: (0..num_nodes)
                .map(|_| Vec::with_capacity(bucket_capacity))
                .collect(),
        }
    }
}

impl<V> ServerStorage<V> for InMemoryServer<V> {
    fn read_and_clear(&mut self, node: usize) -> Vec<Block<V>> {
        std::mem::take(&mut self.buckets[node])
    }

    fn write(&mut self, node: usize, blocks: Vec<Block<V>>) {
        self.buckets[node] = blocks;
    }

    fn bucket_capacity(&self) -> usize {
        self.bucket_capacity
    }
}

/// The largest tree depth this crate will build.
///
/// `2^40` leaves is already absurd (`2^41` bucket entries), but the reason
/// is overflow: [`depth_for_capacity`] can return 64, `1u64 << 64` panics
/// under this workspace's `overflow-checks = true` release profile, and
/// `2 * num_leaves` would wrap. Without a stated maximum,
/// `PathOram::new(u64::MAX, 4)` died with an opaque arithmetic panic.
pub const MAX_DEPTH: u32 = 40;

/// Rounds a leaf capacity up to the tree depth that holds it.
///
/// Integer arithmetic, not `f64::log2().ceil()`: a `u64` above `2^53`
/// doesn't round-trip through `f64`, so large capacities could get a depth
/// one too small. `next_power_of_two().ilog2()` is exact everywhere.
///
/// # Panics
/// Panics if `capacity_leaves` needs a depth beyond [`MAX_DEPTH`].
pub fn depth_for_capacity(capacity_leaves: u64) -> u32 {
    // Checked before `next_power_of_two`, which itself overflows near the
    // top of the `u64` range rather than saturating.
    assert!(
        capacity_leaves <= 1u64 << MAX_DEPTH,
        "capacity_leaves is beyond this crate's MAX_DEPTH of {MAX_DEPTH}"
    );
    capacity_leaves.max(1).next_power_of_two().ilog2()
}

/// The oblivious client: owns the secret state (position map and stash) and
/// drives any [`ServerStorage`] through the protocol. See the module docs.
pub struct Client<V: Clone, S: ServerStorage<V>> {
    depth: u32,
    num_leaves: u64,
    server: S,
    /// Secret: each block's current leaf. **Never exposed to `S`**, which the
    /// client only calls through a trait and never shares a struct with.
    position_map: HashMap<BlockId, u64>,
    /// Secret client-side overflow. Stays small with overwhelming probability
    /// for reasonable `Z` (Stefanov et al.), but no cap is enforced; monitor
    /// `stash_len()` if you need a hard bound.
    stash: Vec<Block<V>>,
    /// Trusted Merkle root over server-visible bucket contents, used only when
    /// `S` implements [`VerifiableServerStorage`] and the caller uses
    /// `verified_read`/`verified_write` (see INTEGRITY). Not secret: it can be
    /// handed to a third party to audit.
    root: [u8; 32],
}

impl<V: Clone, S: ServerStorage<V>> Drop for Client<V, S> {
    fn drop(&mut self) {
        // Clears `position_map` on drop like the workspace's other secrets. The
        // stash's `V` values are caller-supplied and not bound by `Zeroize`, so
        // they are not cleared: a real gap. Callers storing sensitive `V` should
        // zeroize it themselves before the `Client` drops.
        for leaf in self.position_map.values_mut() {
            *leaf = 0;
        }
        self.position_map.clear();
        self.stash.clear();
    }
}

impl<V: Clone, S: ServerStorage<V>> Client<V, S> {
    /// `depth` must match how `server` was sized (`2^depth` leaves,
    /// `2^(depth+1)` nodes); [`depth_for_capacity`] and [`PathOram::new`] build
    /// both together.
    pub fn with_server(depth: u32, server: S) -> Self {
        Client {
            depth,
            num_leaves: 1u64 << depth,
            server,
            position_map: HashMap::new(),
            stash: Vec::new(),
            root: [0u8; 32],
        }
    }

    pub fn stash_len(&self) -> usize {
        self.stash.len()
    }

    pub fn capacity(&self) -> u64 {
        self.num_leaves
    }

    fn path_nodes(&self, leaf: u64) -> Vec<usize> {
        let mut node = (self.num_leaves + leaf) as usize;
        let mut path = Vec::with_capacity(self.depth as usize + 1);
        path.push(node);
        while node > 1 {
            node /= 2;
            path.push(node);
        }
        path
    }

    fn is_ancestor_of_leaf(&self, node: usize, leaf: u64) -> bool {
        let mut n = (self.num_leaves + leaf) as usize;
        loop {
            if n == node {
                return true;
            }
            if n == 1 {
                return false;
            }
            n /= 2;
        }
    }

    fn random_leaf(&self, rng: &mut impl Rng) -> u64 {
        rng.random_range(0..self.num_leaves)
    }

    /// Reads (and clears) every bucket on `path_nodes(leaf)` into the stash.
    fn read_path_into_stash(&mut self, leaf: u64) {
        for node in self.path_nodes(leaf) {
            self.stash.append(&mut self.server.read_and_clear(node));
        }
    }

    /// Greedily evicts stash blocks onto the path, deepest eligible bucket
    /// first: the standard order, which keeps the stash small in expectation.
    fn evict_path(&mut self, leaf: u64) {
        let capacity = self.server.bucket_capacity();
        for node in self.path_nodes(leaf) {
            let mut chosen = Vec::with_capacity(capacity);
            let mut i = 0;
            while i < self.stash.len() && chosen.len() < capacity {
                let leaf_of = *self
                    .position_map
                    .get(&self.stash[i].id)
                    .expect("stashed block must have a position");
                if self.is_ancestor_of_leaf(node, leaf_of) {
                    chosen.push(self.stash.remove(i));
                } else {
                    i += 1;
                }
            }
            self.server.write(node, chosen);
        }
    }

    /// Oblivious read: the current value, or `None` if `id` was never written.
    /// The access pattern is the same as any write of equal size to any block,
    /// so an observer can't tell reads from writes or which `id` was targeted.
    pub fn read(&mut self, id: BlockId, rng: &mut impl Rng) -> Option<V> {
        self.access(id, None, rng)
    }

    /// Oblivious write: sets `id`'s value, returning the previous value if
    /// any.
    pub fn write(&mut self, id: BlockId, value: V, rng: &mut impl Rng) -> Option<V> {
        self.access(id, Some(value), rng)
    }

    fn access(&mut self, id: BlockId, new_value: Option<V>, rng: &mut impl Rng) -> Option<V> {
        let old_leaf = match self.position_map.get(&id) {
            Some(&leaf) => leaf,
            None => self.random_leaf(rng),
        };
        let new_leaf = self.random_leaf(rng);
        self.position_map.insert(id, new_leaf);

        self.read_path_into_stash(old_leaf);

        let existing = self.stash.iter().position(|b| b.id == id);
        let old_value = existing.map(|i| self.stash[i].value.clone());
        match (existing, new_value) {
            (Some(i), Some(v)) => self.stash[i].value = v,
            (Some(_), None) => {}
            (None, Some(v)) => self.stash.push(Block { id, value: v }),
            (None, None) => {}
        }

        self.evict_path(old_leaf);
        old_value
    }
}

/// A [`Client`] with the reference [`InMemoryServer`]. Use [`Client`] with
/// your own [`ServerStorage`] for a networked deployment
/// (`examples/networked_server.rs` shows one).
pub type PathOram<V> = Client<V, InMemoryServer<V>>;

impl<V: Clone> PathOram<V> {
    /// `capacity_leaves` is rounded up to a power of two; `Z` is the bucket
    /// capacity (4 is standard: negligible stash overflow at realistic sizes).
    pub fn new(capacity_leaves: u64, bucket_capacity: usize) -> Self {
        assert!(capacity_leaves >= 1);
        assert!(bucket_capacity >= 1);
        let depth = depth_for_capacity(capacity_leaves);
        let num_leaves = 1u64 << depth;
        let server = InMemoryServer::new((2 * num_leaves) as usize, bucket_capacity);
        Client::with_server(depth, server)
    }
}

// INTEGRITY
// ================================================================================================
//
// Obliviousness hides *which* block an access targets, but nothing above
// stops an *active* server from corrupting, dropping or replaying stale
// buckets undetected.
//
// This section adds a Merkle tree over the same binary tree Path ORAM
// uses, so verification touches only what an access already touches
// (`O(log n)`). `Client` keeps just the 32-byte root, which needs to be
// checked, not hidden.
//
// Node `v` hashes to `H(bucket_hash(v), hash(left(v)), hash(right(v)))`,
// with a fixed sentinel for missing children at the leaves. Each access
// already rewrites every bucket on `path_nodes(leaf)`, exactly the nodes
// whose hashes change; with one off-path sibling hash per level, `Client`
// recomputes the chain to the root and checks it before trusting anything
// the server returned.

use sha2::{Digest, Sha256};

const EMPTY_CHILD: [u8; 32] = [0u8; 32];

fn hash_bucket<V: AsRef<[u8]>>(blocks: &[Block<V>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"novachannel-oram bucket v1");
    // u64, not u32: a truncated length would let different bucket contents
    // hash identically, which this hash exists to prevent.
    hasher.update((blocks.len() as u64).to_be_bytes());
    for b in blocks {
        hasher.update(b.id.to_be_bytes());
        let bytes = b.value.as_ref();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

fn hash_node(bucket_hash: [u8; 32], left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"novachannel-oram node v1");
    hasher.update(bucket_hash);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// A [`ServerStorage`] that also maintains and reveals each node's Merkle
/// hash, so a [`Client`] can detect tampering without trusting the server.
/// The hashes reveal nothing beyond which nodes were touched, which
/// obliviousness already allows.
pub trait VerifiableServerStorage<V>: ServerStorage<V> {
    /// The currently-stored Merkle hash for `node`.
    fn node_hash(&self, node: usize) -> [u8; 32];
    /// Updates the stored hash for `node` after its bucket contents (or a
    /// descendant's) changed.
    fn set_node_hash(&mut self, node: usize, hash: [u8; 32]);
}

/// The reference [`VerifiableServerStorage`]: [`InMemoryServer`] plus node
/// hashes kept in step by [`Client::verified_read`] /
/// [`Client::verified_write`].
///
/// A fresh instance holds **placeholder zeros, not empty-subtree hashes**:
/// call [`Client::init_empty_root`] before any verified access, or every
/// access fails against an honest server. `new` doesn't compute them so the
/// empty-subtree hash has one definition (`init_empty_root`).
pub struct IntegrityCheckedServer<V> {
    inner: InMemoryServer<V>,
    hashes: Vec<[u8; 32]>,
}

impl<V> IntegrityCheckedServer<V> {
    pub fn new(num_nodes: usize, bucket_capacity: usize) -> Self {
        IntegrityCheckedServer {
            inner: InMemoryServer::new(num_nodes, bucket_capacity),
            hashes: vec![EMPTY_CHILD; num_nodes],
        }
    }
}

impl<V> ServerStorage<V> for IntegrityCheckedServer<V> {
    fn read_and_clear(&mut self, node: usize) -> Vec<Block<V>> {
        self.inner.read_and_clear(node)
    }

    fn write(&mut self, node: usize, blocks: Vec<Block<V>>) {
        self.inner.write(node, blocks);
    }

    fn bucket_capacity(&self) -> usize {
        self.inner.bucket_capacity()
    }
}

impl<V> VerifiableServerStorage<V> for IntegrityCheckedServer<V> {
    fn node_hash(&self, node: usize) -> [u8; 32] {
        self.hashes[node]
    }

    fn set_node_hash(&mut self, node: usize, hash: [u8; 32]) {
        self.hashes[node] = hash;
    }
}

/// Returned by [`Client::verified_read`]/[`Client::verified_write`] when the
/// server's bucket contents don't match the trusted root: tampered, dropped
/// or stale data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityError;

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ORAM server storage failed integrity verification against the trusted root"
        )
    }
}

impl std::error::Error for IntegrityError {}

impl<V: Clone + AsRef<[u8]>, S: VerifiableServerStorage<V>> Client<V, S> {
    /// Establishes the trusted root for a fresh, empty server and seeds every
    /// node hash on it (a fresh [`IntegrityCheckedServer`] holds placeholder
    /// zeros). **This is the only definition of the empty-subtree hash**, so a
    /// second copy can't drift (`ENGINEERING-STANDARDS.md` §4.2).
    ///
    /// Resuming against an already-populated server needs the root from a
    /// trusted out-of-band source, as with `novachannel::handshake`'s identity
    /// pinning: a root obtained from the untrusted server proves nothing.
    pub fn init_empty_root(&mut self) {
        let empty_bucket_hash = hash_bucket::<V>(&[]);
        let num_leaves = self.num_leaves as usize;

        for node in num_leaves..(2 * num_leaves) {
            let h = hash_node(empty_bucket_hash, EMPTY_CHILD, EMPTY_CHILD);
            self.server.set_node_hash(node, h);
        }
        for node in (1..num_leaves).rev() {
            let left = self.server.node_hash(2 * node);
            let right = self.server.node_hash(2 * node + 1);
            let h = hash_node(empty_bucket_hash, left, right);
            self.server.set_node_hash(node, h);
        }
        self.root = self.server.node_hash(1);
    }

    /// The client's current trusted root — not secret; safe to hand to a
    /// third party to audit the server against independently.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Like [`Client::read`], but verifies every bucket the server returns
    /// against the trusted root before trusting any of it.
    pub fn verified_read(
        &mut self,
        id: BlockId,
        rng: &mut impl Rng,
    ) -> Result<Option<V>, IntegrityError> {
        self.verified_access(id, None, rng)
    }

    /// Like [`Client::write`], with the same verification as
    /// [`Client::verified_read`].
    pub fn verified_write(
        &mut self,
        id: BlockId,
        value: V,
        rng: &mut impl Rng,
    ) -> Result<Option<V>, IntegrityError> {
        self.verified_access(id, Some(value), rng)
    }

    /// Recomputes the Merkle chain bottom-up along the leaf-to-root `path`,
    /// given each node's bucket hash (`contents_at` returns `hash_bucket(..)`)
    /// and fetching each level's off-path sibling hash from the server (not
    /// touched by this access, so still trusted).
    ///
    /// Returns every node's combined hash (`hash_node(bucket_hash, left,
    /// right)`), not just the root, so the caller can update
    /// [`VerifiableServerStorage::set_node_hash`] for every node on the path.
    fn recompute_path_hashes(
        &self,
        path: &[usize],
        contents_at: impl Fn(usize) -> [u8; 32],
    ) -> Vec<(usize, [u8; 32])> {
        let mut result = Vec::with_capacity(path.len());
        let mut cur_hash: Option<[u8; 32]> = None;
        let mut prev_node: Option<usize> = None;
        for &node in path {
            let bucket_hash = contents_at(node);
            let is_leaf = node >= self.num_leaves as usize;
            let new_hash = if is_leaf {
                hash_node(bucket_hash, EMPTY_CHILD, EMPTY_CHILD)
            } else {
                let prev = prev_node.expect("internal node always has a processed child");
                let sibling = prev ^ 1;
                let sibling_hash = self.server.node_hash(sibling);
                let cur = cur_hash.expect("internal node always has a processed child");
                let (left, right) = if prev.is_multiple_of(2) {
                    (cur, sibling_hash)
                } else {
                    (sibling_hash, cur)
                };
                hash_node(bucket_hash, left, right)
            };
            result.push((node, new_hash));
            cur_hash = Some(new_hash);
            prev_node = Some(node);
        }
        result
    }

    fn verified_access(
        &mut self,
        id: BlockId,
        new_value: Option<V>,
        rng: &mut impl Rng,
    ) -> Result<Option<V>, IntegrityError> {
        let old_leaf = match self.position_map.get(&id) {
            Some(&leaf) => leaf,
            None => self.random_leaf(rng),
        };
        let new_leaf = self.random_leaf(rng);
        self.position_map.insert(id, new_leaf);

        let path = self.path_nodes(old_leaf);
        let mut contents: Vec<(usize, Vec<Block<V>>)> = Vec::with_capacity(path.len());
        for &node in &path {
            contents.push((node, self.server.read_and_clear(node)));
        }

        let hashes: std::collections::HashMap<usize, [u8; 32]> = contents
            .iter()
            .map(|(node, blocks)| (*node, hash_bucket::<V>(blocks)))
            .collect();
        let path_hashes = self.recompute_path_hashes(&path, |node| hashes[&node]);
        let observed_root = path_hashes.last().expect("path is never empty").1;
        if observed_root != self.root {
            // Put everything back, so a caller retrying against an honest server isn't
            // left with buckets emptied on this one.
            for (node, blocks) in contents {
                self.server.write(node, blocks);
            }
            return Err(IntegrityError);
        }

        for (_, blocks) in contents {
            self.stash.extend(blocks);
        }

        let existing = self.stash.iter().position(|b| b.id == id);
        let old_value = existing.map(|i| self.stash[i].value.clone());
        match (existing, new_value) {
            (Some(i), Some(v)) => self.stash[i].value = v,
            (Some(_), None) => {}
            (None, Some(v)) => self.stash.push(Block { id, value: v }),
            (None, None) => {}
        }

        let capacity = self.server.bucket_capacity();
        let mut chosen_per_node = Vec::with_capacity(path.len());
        for &node in &path {
            let mut chosen = Vec::with_capacity(capacity);
            let mut i = 0;
            while i < self.stash.len() && chosen.len() < capacity {
                let leaf_of = *self
                    .position_map
                    .get(&self.stash[i].id)
                    .expect("stashed block must have a position");
                if self.is_ancestor_of_leaf(node, leaf_of) {
                    chosen.push(self.stash.remove(i));
                } else {
                    i += 1;
                }
            }
            chosen_per_node.push((node, chosen));
        }

        let new_bucket_hashes: std::collections::HashMap<usize, [u8; 32]> = chosen_per_node
            .iter()
            .map(|(node, chosen)| (*node, hash_bucket::<V>(chosen)))
            .collect();
        let new_path_hashes = self.recompute_path_hashes(&path, |node| new_bucket_hashes[&node]);
        self.root = new_path_hashes.last().expect("path is never empty").1;
        let new_combined_hashes: std::collections::HashMap<usize, [u8; 32]> =
            new_path_hashes.into_iter().collect();
        for (node, chosen) in chosen_per_node {
            let hash = new_combined_hashes[&node];
            self.server.write(node, chosen);
            self.server.set_node_hash(node, hash);
        }

        Ok(old_value)
    }
}

// CONFIDENTIALITY
// ================================================================================================
//
// Obliviousness and integrity say nothing about the server simply reading
// `Block::value`, which [`InMemoryServer`]/[`IntegrityCheckedServer`] store
// as given.
//
// [`EncryptingServerStorage`] is a [`ServerStorage`] decorator (no change
// to [`Client`]) between `Client` and the storage that reaches the server.
// It AEAD-seals each block's `id` and `value` together and hands `inner` a
// block with a throwaway id of `0`. Sealing the id matters: a clear id next
// to an opaque value would let the server correlate "id X changed" across
// accesses.
//
// Per-block encryption alone still leaked two things, so this layer hides
// them as well:
//
//   - **Blocks per bucket.** `Client::evict_path` writes back 0 to `Z`
//     blocks, and that load correlates with the access pattern. Standard
//     Path ORAM (Stefanov et al. §3.2) writes exactly `Z` slots per bucket,
//     padding with encrypted dummies.
//   - **Value length.** Sealing caller-sized `Vec<u8>` values as-is makes a
//     900-byte block among 40-byte ones a label. Path ORAM assumes fixed-size
//     blocks for this reason.
//
// Without these, the obliviousness claim in the module docs would be
// false. [`EncryptingServerStorage::new`] takes a fixed `block_value_len`;
// each sealed block is `tag || id || length || value` padded to it, and
// every bucket is written as exactly `bucket_capacity` such ciphertexts,
// dummies filling the rest. The server sees `Z` equal-length ciphertexts
// per bucket on every access. Dummies are dropped on read, so `Client` and
// the Merkle hashing see exactly the blocks written.
//
// Composing with integrity (`Client<Vec<u8>,
// EncryptingServerStorage<IntegrityCheckedServer<Vec<u8>>>>`) needs no third
// implementation. `Client` hashes the plaintext blocks this layer returns
// (one hashing implementation, §6.13's "compose via bytes"), so tampered,
// dropped or replayed ciphertext changes the plaintext bucket hash and
// surfaces as `IntegrityError`. A block failing AEAD authentication (bit
// corruption; whole-bucket swaps and replays decrypt fine and are caught
// by the Merkle check) is dropped from the returned bucket instead of
// panicking, which also changes the hash, so it is still an
// `IntegrityError`, never a crash or wrong answer. Without the integrity
// layer (`EncryptingServerStorage<InMemoryServer<Vec<u8>>>` with plain
// `read`/`write`) a corrupted block silently disappears, which is no worse
// than that configuration's documented lack of tamper detection.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroize;

const ORAM_NONCE_LEN: usize = 12;
const ORAM_ID_LEN: usize = 8;
const ORAM_TAG_LEN: usize = 1;
const ORAM_VALUE_LEN_LEN: usize = 4;
/// Marks a sealed block as carrying a real `(id, value)` rather than
/// padding. Inside the AEAD, so the server cannot tell the two apart.
const ORAM_TAG_REAL: u8 = 1;
const ORAM_TAG_DUMMY: u8 = 0;

/// One AEAD-sealed block: a 12-byte nonce, then the ChaCha20-Poly1305
/// ciphertext of `tag || id.to_be_bytes() || value_len.to_be_bytes() ||
/// value`, zero-padded to exactly
/// `ORAM_TAG_LEN + ORAM_ID_LEN + ORAM_VALUE_LEN_LEN + block_value_len`
/// bytes so every sealed block has the same length. The fixed length and the
/// dummy `tag` are part of obliviousness (see CONFIDENTIALITY).
///
/// # Panics
/// Panics if `value` exceeds `block_value_len`; callers check first and
/// return their own error.
fn seal_oram_block(
    key: &[u8; 32],
    nonce: [u8; ORAM_NONCE_LEN],
    tag: u8,
    id: BlockId,
    value: &[u8],
    block_value_len: usize,
) -> Vec<u8> {
    assert!(
        value.len() <= block_value_len,
        "block value exceeds this EncryptingServerStorage's fixed block size"
    );
    let mut plaintext =
        Vec::with_capacity(ORAM_TAG_LEN + ORAM_ID_LEN + ORAM_VALUE_LEN_LEN + block_value_len);
    plaintext.push(tag);
    plaintext.extend_from_slice(&id.to_be_bytes());
    plaintext.extend_from_slice(&(value.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(value);
    plaintext.resize(
        ORAM_TAG_LEN + ORAM_ID_LEN + ORAM_VALUE_LEN_LEN + block_value_len,
        0u8,
    );
    let ciphertext = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
        .expect("ChaCha20Poly1305 encryption over a bounded plaintext cannot fail");
    plaintext.zeroize();
    let mut out = Vec::with_capacity(ORAM_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Inverse of [`seal_oram_block`]. `None` on authentication failure,
/// malformed length or a dummy; `EncryptingServerStorage::read_and_clear`
/// treats all three as "not a block to return" (see CONFIDENTIALITY).
fn open_oram_block(key: &[u8; 32], sealed: &[u8]) -> Option<(BlockId, Vec<u8>)> {
    if sealed.len() < ORAM_NONCE_LEN {
        return None;
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(ORAM_NONCE_LEN);
    let nonce: [u8; ORAM_NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at(ORAM_NONCE_LEN) already guarantees the length");
    let mut plaintext = ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from(nonce), ciphertext)
        .ok()?;
    let header = ORAM_TAG_LEN + ORAM_ID_LEN + ORAM_VALUE_LEN_LEN;
    if plaintext.len() < header || plaintext[0] != ORAM_TAG_REAL {
        plaintext.zeroize();
        return None;
    }
    let id = BlockId::from_be_bytes(
        plaintext[ORAM_TAG_LEN..ORAM_TAG_LEN + ORAM_ID_LEN]
            .try_into()
            .expect("slice of exactly ORAM_ID_LEN bytes"),
    );
    let value_len = u32::from_be_bytes(
        plaintext[ORAM_TAG_LEN + ORAM_ID_LEN..header]
            .try_into()
            .expect("slice of exactly ORAM_VALUE_LEN_LEN bytes"),
    ) as usize;
    if header + value_len > plaintext.len() {
        plaintext.zeroize();
        return None;
    }
    let value = plaintext[header..header + value_len].to_vec();
    plaintext.zeroize();
    Some((id, value))
}

/// A [`ServerStorage<Vec<u8>>`] decorator that AEAD-seals every block before
/// it reaches `inner`. Threat model and composition with
/// [`VerifiableServerStorage`]: see CONFIDENTIALITY.
pub struct EncryptingServerStorage<S> {
    inner: S,
    key: [u8; 32],
    /// The fixed plaintext size every block is padded to, so ciphertext length
    /// says nothing about contents.
    block_value_len: usize,
    /// A strictly increasing per-block nonce counter rather than random nonces:
    /// one key seals many blocks over a long deployment and ChaCha20-Poly1305
    /// fails catastrophically on nonce reuse; a counter can't collide before
    /// 2^64 blocks, unlike a random 96-bit nonce's birthday bound.
    nonce_counter: u64,
}

impl<S> Drop for EncryptingServerStorage<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<S> EncryptingServerStorage<S> {
    /// `key` is a caller-provisioned 32-byte AEAD key; distributing and
    /// rotating it is the caller's job.
    ///
    /// `block_value_len` is the fixed size every value is padded to. The real
    /// length is stored inside the AEAD and restored on read, but every
    /// ciphertext the server sees is the same length. Pick the largest value
    /// the application stores: longer values panic on write (see
    /// [`ServerStorage::write`]'s impl), and oversizing only costs bandwidth.
    ///
    /// # Panics
    /// Panics if `block_value_len` is zero (a configuration error).
    pub fn new(inner: S, key: [u8; 32], block_value_len: usize) -> Self {
        assert!(
            block_value_len > 0,
            "block_value_len must be at least 1 byte"
        );
        // `seal_oram_block` records a value's real length in a `u32`, so
        // anything past that would truncate rather than fail.
        assert!(
            block_value_len <= u32::MAX as usize,
            "block_value_len must fit in a u32"
        );
        EncryptingServerStorage {
            inner,
            key,
            block_value_len,
            nonce_counter: 0,
        }
    }

    /// The fixed per-block value size this layer pads to.
    pub fn block_value_len(&self) -> usize {
        self.block_value_len
    }

    fn next_nonce(&mut self) -> [u8; ORAM_NONCE_LEN] {
        let n = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.checked_add(1).expect(
            "EncryptingServerStorage's nonce counter exhausted (2^64 blocks written under one key) -- rotate the key",
        );
        let mut nonce = [0u8; ORAM_NONCE_LEN];
        nonce[ORAM_NONCE_LEN - 8..].copy_from_slice(&n.to_be_bytes());
        nonce
    }
}

impl<S: ServerStorage<Vec<u8>>> ServerStorage<Vec<u8>> for EncryptingServerStorage<S> {
    /// Unseals the bucket, dropping [`Self::write`]'s dummies and anything that
    /// fails authentication (see CONFIDENTIALITY). `Client` sees exactly the
    /// blocks it wrote, and Merkle hashes are computed over those.
    fn read_and_clear(&mut self, node: usize) -> Vec<Block<Vec<u8>>> {
        self.inner
            .read_and_clear(node)
            .into_iter()
            .filter_map(|sealed| open_oram_block(&self.key, &sealed.value))
            .map(|(id, value)| Block { id, value })
            .collect()
    }

    /// Seals every block and pads the bucket to `bucket_capacity` with dummies,
    /// so the server always sees exactly `bucket_capacity` equal-length
    /// ciphertexts per bucket. The physical id given to `inner` is always `0`;
    /// the real id is inside the ciphertext.
    ///
    /// # Panics
    /// Panics if `blocks` exceeds `bucket_capacity` or any value exceeds
    /// `block_value_len`; both are caller configuration errors ([`Client`]
    /// never exceeds the capacity it reads from this trait).
    fn write(&mut self, node: usize, blocks: Vec<Block<Vec<u8>>>) {
        let capacity = self.inner.bucket_capacity();
        assert!(
            blocks.len() <= capacity,
            "cannot write more blocks into a bucket than its capacity"
        );
        let block_value_len = self.block_value_len;
        let dummies = capacity - blocks.len();

        let mut sealed = Vec::with_capacity(capacity);
        for b in blocks {
            assert!(
                b.value.len() <= block_value_len,
                "block value exceeds this EncryptingServerStorage's fixed block size"
            );
            let nonce = self.next_nonce();
            sealed.push(Block {
                id: 0,
                value: seal_oram_block(
                    &self.key,
                    nonce,
                    ORAM_TAG_REAL,
                    b.id,
                    &b.value,
                    block_value_len,
                ),
            });
        }
        for _ in 0..dummies {
            let nonce = self.next_nonce();
            sealed.push(Block {
                id: 0,
                value: seal_oram_block(&self.key, nonce, ORAM_TAG_DUMMY, 0, &[], block_value_len),
            });
        }
        self.inner.write(node, sealed);
    }

    fn bucket_capacity(&self) -> usize {
        self.inner.bucket_capacity()
    }
}

impl<S: VerifiableServerStorage<Vec<u8>>> VerifiableServerStorage<Vec<u8>>
    for EncryptingServerStorage<S>
{
    fn node_hash(&self, node: usize) -> [u8; 32] {
        self.inner.node_hash(node)
    }

    fn set_node_hash(&mut self, node: usize, hash: [u8; 32]) {
        self.inner.set_node_hash(node, hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Fixed block size for the `EncryptingServerStorage` tests, larger than any
    /// value they store: the padding must be invisible to `Client`.
    const TEST_BLOCK_LEN: usize = 48;

    /// A second, independent `ServerStorage`: [`InMemoryServer`] plus a bucket
    /// touch counter, standing in for a networked server.
    /// [`client_works_unchanged_against_a_different_server_impl`] drives it
    /// through [`Client`] directly (not the [`PathOram`] alias), demonstrating
    /// that swapping `ServerStorage` needs no change to `Client`.
    struct CountingServer<V> {
        inner: InMemoryServer<V>,
        reads: usize,
        writes: usize,
    }

    impl<V> CountingServer<V> {
        fn new(num_nodes: usize, bucket_capacity: usize) -> Self {
            CountingServer {
                inner: InMemoryServer::new(num_nodes, bucket_capacity),
                reads: 0,
                writes: 0,
            }
        }
    }

    impl<V> ServerStorage<V> for CountingServer<V> {
        fn read_and_clear(&mut self, node: usize) -> Vec<Block<V>> {
            self.reads += 1;
            self.inner.read_and_clear(node)
        }

        fn write(&mut self, node: usize, blocks: Vec<Block<V>>) {
            self.writes += 1;
            self.inner.write(node, blocks);
        }

        fn bucket_capacity(&self) -> usize {
            self.inner.bucket_capacity()
        }
    }

    #[test]
    fn client_works_unchanged_against_a_different_server_impl() {
        let depth = depth_for_capacity(64);
        let num_leaves = 1u64 << depth;
        let server = CountingServer::new((2 * num_leaves) as usize, 4);
        let mut client: Client<u64, CountingServer<u64>> = Client::with_server(depth, server);
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        for id in 0..10u64 {
            assert_eq!(client.write(id, id * 10, &mut rng), None);
        }
        for id in 0..10u64 {
            assert_eq!(client.read(id, &mut rng), Some(id * 10));
        }

        // Every access touches `depth + 1` buckets for both the read and
        // the write-back half — 20 accesses total (10 writes + 10 reads).
        let expected_touches = 20 * (depth as usize + 1);
        assert_eq!(client.server.reads, expected_touches);
        assert_eq!(client.server.writes, expected_touches);
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut oram: PathOram<u64> = PathOram::new(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        for id in 0..20u64 {
            assert_eq!(oram.write(id, id * 100, &mut rng), None);
        }
        for id in 0..20u64 {
            assert_eq!(oram.read(id, &mut rng), Some(id * 100));
        }
    }

    #[test]
    fn unwritten_block_reads_as_none() {
        let mut oram: PathOram<u64> = PathOram::new(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        assert_eq!(oram.read(999, &mut rng), None);
    }

    #[test]
    fn capacity_reports_the_number_of_leaves() {
        let oram: PathOram<u64> = PathOram::new(64, 4);
        assert_eq!(oram.capacity(), 64);
    }

    #[test]
    fn overwrite_returns_previous_value() {
        let mut oram: PathOram<u64> = PathOram::new(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        oram.write(5, 1, &mut rng);
        assert_eq!(oram.write(5, 2, &mut rng), Some(1));
        assert_eq!(oram.read(5, &mut rng), Some(2));
    }

    #[test]
    fn heavy_random_workload_stays_consistent_with_a_reference_map() {
        let mut oram: PathOram<u64> = PathOram::new(256, 4);
        let mut reference: HashMap<BlockId, u64> = HashMap::new();
        let mut rng = ChaCha20Rng::seed_from_u64(4);

        for step in 0..5000u64 {
            let id = rng.random_range(0..200u64);
            if rng.random_bool(0.5) {
                let value = step;
                let got = oram.write(id, value, &mut rng);
                assert_eq!(got, reference.insert(id, value));
            } else {
                let got = oram.read(id, &mut rng);
                assert_eq!(got, reference.get(&id).copied());
            }
        }
        // Sanity: stash shouldn't have grown unboundedly for a workload
        // this size against a 256-leaf tree with Z=4.
        assert!(
            oram.stash_len() < 200,
            "stash grew to {} — eviction likely broken",
            oram.stash_len()
        );
    }

    fn verified_client(
        capacity_leaves: u64,
        bucket_capacity: usize,
    ) -> Client<Vec<u8>, IntegrityCheckedServer<Vec<u8>>> {
        let depth = depth_for_capacity(capacity_leaves);
        let num_leaves = 1u64 << depth;
        let server = IntegrityCheckedServer::new((2 * num_leaves) as usize, bucket_capacity);
        let mut client = Client::with_server(depth, server);
        client.init_empty_root();
        client
    }

    #[test]
    fn integrity_error_has_a_human_readable_display() {
        let msg = IntegrityError.to_string();
        assert!(msg.contains("integrity"));
    }

    #[test]
    fn root_getter_returns_the_current_trusted_root() {
        let client = verified_client(64, 4);
        // Not zero (the pre-`init_empty_root` placeholder) — a real root
        // was computed and stored by `verified_client`'s setup.
        assert_ne!(client.root(), [0u8; 32]);
    }

    #[test]
    fn verified_access_round_trips_against_an_honest_server() {
        let mut client = verified_client(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(10);

        for id in 0..20u64 {
            assert_eq!(
                client.verified_write(id, vec![id as u8; 3], &mut rng),
                Ok(None)
            );
        }
        for id in 0..20u64 {
            assert_eq!(
                client.verified_read(id, &mut rng),
                Ok(Some(vec![id as u8; 3]))
            );
        }
    }

    #[test]
    fn a_heavy_verified_workload_stays_consistent_with_a_reference_map() {
        let mut client = verified_client(256, 4);
        let mut reference: HashMap<BlockId, Vec<u8>> = HashMap::new();
        let mut rng = ChaCha20Rng::seed_from_u64(12);

        for step in 0..2000u64 {
            let id = rng.random_range(0..200u64);
            if rng.random_bool(0.5) {
                let value = vec![step as u8; (step % 5 + 1) as usize];
                let got = client.verified_write(id, value.clone(), &mut rng).unwrap();
                assert_eq!(got, reference.insert(id, value));
            } else {
                let got = client.verified_read(id, &mut rng).unwrap();
                assert_eq!(got, reference.get(&id).cloned());
            }
        }
    }

    #[test]
    fn a_server_that_tampers_with_a_bucket_is_caught() {
        let mut client = verified_client(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(11);

        client.verified_write(1, vec![1, 2, 3], &mut rng).unwrap();

        // Corrupt the root bucket directly, bypassing `Client`, as a malicious or
        // buggy server would. Every access touches the root (`path_nodes` ends at
        // node 1), so the next verified access must catch it.
        client.server.inner.buckets[1].push(Block {
            id: 999,
            value: vec![0xFF],
        });

        assert_eq!(client.verified_read(1, &mut rng), Err(IntegrityError));
    }

    #[test]
    fn a_server_that_replays_a_stale_bucket_is_caught() {
        let mut client = verified_client(64, 4);
        // Load-bearing seed, chosen with a throwaway probe (§0.5, validate the
        // instrument) so the root bucket actually differs between the two writes
        // below; otherwise the replay is a no-op and the test proves nothing.
        let mut rng = ChaCha20Rng::seed_from_u64(127);

        client.verified_write(2, vec![9, 9], &mut rng).unwrap();
        // Snapshot the root bucket, make another access that changes it, then
        // replay the stale snapshot: an old but internally consistent bucket. A
        // "does this look well-formed" check misses that; only the root comparison
        // catches it.
        let stale_root_bucket = client.server.inner.buckets[1].clone();
        client.verified_write(3, vec![7, 7], &mut rng).unwrap();
        client.server.inner.buckets[1] = stale_root_bucket;

        assert_eq!(client.verified_read(2, &mut rng), Err(IntegrityError));
    }

    fn encrypting_client(
        capacity_leaves: u64,
        bucket_capacity: usize,
        key: [u8; 32],
    ) -> Client<Vec<u8>, EncryptingServerStorage<InMemoryServer<Vec<u8>>>> {
        let depth = depth_for_capacity(capacity_leaves);
        let num_leaves = 1u64 << depth;
        let inner = InMemoryServer::new((2 * num_leaves) as usize, bucket_capacity);
        Client::with_server(
            depth,
            EncryptingServerStorage::new(inner, key, TEST_BLOCK_LEN),
        )
    }

    #[test]
    fn encrypting_storage_round_trips_values_and_never_stores_them_in_the_clear() {
        let key = [7u8; 32];
        let mut client = encrypting_client(64, 4, key);
        let mut rng = ChaCha20Rng::seed_from_u64(20);

        let secret_marker = b"totally-secret-rate-limit-counter".to_vec();
        assert_eq!(client.write(1, secret_marker.clone(), &mut rng), None);
        assert_eq!(client.read(1, &mut rng), Some(secret_marker.clone()));

        // Confidentiality checked directly: the marker plaintext must not appear
        // anywhere in what the untrusted inner server holds.
        for bucket in &client.server.inner.buckets {
            for block in bucket {
                assert_ne!(block.value, secret_marker);
                assert!(
                    !block
                        .value
                        .windows(secret_marker.len())
                        .any(|w| w == secret_marker.as_slice()),
                    "plaintext leaked into server-visible storage"
                );
            }
        }
    }

    /// Checked against what the untrusted server holds, not `Client`'s view:
    /// every bucket ever written looks the same, with the same block count and
    /// ciphertext lengths, whatever the real occupancy and value lengths.
    ///
    /// Before dummy padding and fixed block size, a bucket's block count was
    /// its real occupancy (0..=Z) and ciphertext length tracked value length,
    /// both readable by the server.
    #[test]
    fn every_written_bucket_looks_identical_to_the_server_whatever_it_holds() {
        let key = [3u8; 32];
        let mut client = encrypting_client(64, 4, key);
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        // Deliberately lopsided: very different value lengths, and enough writes
        // that some buckets fill while others stay nearly empty.
        for id in 0..40u64 {
            let len = (id as usize * 7) % (TEST_BLOCK_LEN + 1);
            client.write(id, vec![id as u8; len], &mut rng);
        }
        for id in 0..40u64 {
            client.read(id, &mut rng);
        }

        let capacity = client.server.inner.bucket_capacity();
        let mut expected_ciphertext_len = None;
        let mut written_buckets = 0usize;
        for bucket in &client.server.inner.buckets {
            if bucket.is_empty() {
                // Never written: the server already learns which nodes are touched, so
                // that isn't new. What must not vary is anything about a written bucket.
                continue;
            }
            written_buckets += 1;
            assert_eq!(
                bucket.len(),
                capacity,
                "a written bucket must always hold exactly Z blocks"
            );
            for block in bucket {
                assert_eq!(block.id, 0, "the real id belongs inside the ciphertext");
                let len = *expected_ciphertext_len.get_or_insert(block.value.len());
                assert_eq!(
                    block.value.len(),
                    len,
                    "every sealed block must be the same length"
                );
            }
        }
        assert!(
            written_buckets > 1,
            "instrument check: the workload must actually have written several buckets"
        );

        // ...and the padding is invisible above the storage layer: every
        // value still round-trips at its own real length.
        for id in 0..40u64 {
            let len = (id as usize * 7) % (TEST_BLOCK_LEN + 1);
            assert_eq!(
                client.read(id, &mut rng),
                Some(vec![id as u8; len]),
                "id {id}"
            );
        }
    }

    /// `depth_for_capacity` used `(n as f64).log2().ceil()`, which is exact
    /// for small powers of two but not above `2^53`, where `u64` values don't
    /// round-trip through `f64` and a capacity could get too small a depth. The
    /// integer form is exact everywhere, and an absurd capacity now fails with
    /// a message instead of a shift-overflow panic.
    #[test]
    fn depth_for_capacity_is_exact_across_the_whole_supported_range() {
        assert_eq!(depth_for_capacity(1), 0);
        assert_eq!(depth_for_capacity(2), 1);
        assert_eq!(depth_for_capacity(3), 2);
        assert_eq!(depth_for_capacity(4), 2);
        assert_eq!(depth_for_capacity(5), 3);

        for d in 0..=MAX_DEPTH {
            let exact = 1u64 << d;
            assert_eq!(depth_for_capacity(exact), d, "2^{d} exactly");
            if d < MAX_DEPTH {
                assert_eq!(depth_for_capacity(exact + 1), d + 1, "2^{d} + 1");
            }
        }
    }

    #[test]
    #[should_panic(expected = "beyond this crate's MAX_DEPTH")]
    fn a_capacity_beyond_the_supported_depth_says_so_rather_than_overflowing() {
        depth_for_capacity(u64::MAX);
    }

    /// A dummy must be unrecoverable as a block even by someone holding
    /// the key: the tag that marks it lives inside the AEAD, so
    /// `open_oram_block` is where it is dropped.
    #[test]
    fn a_dummy_block_is_authenticated_but_never_returned_as_a_block() {
        let key = [5u8; 32];
        let dummy = seal_oram_block(&key, [0u8; ORAM_NONCE_LEN], ORAM_TAG_DUMMY, 0, &[], 16);
        let real = seal_oram_block(&key, [1u8; ORAM_NONCE_LEN], ORAM_TAG_REAL, 42, b"hi", 16);

        assert_eq!(
            dummy.len(),
            real.len(),
            "a dummy must not be distinguishable by length"
        );
        assert_eq!(open_oram_block(&key, &dummy), None);
        assert_eq!(open_oram_block(&key, &real), Some((42, b"hi".to_vec())));
    }

    #[test]
    fn encrypting_storage_with_the_wrong_key_does_not_decrypt() {
        let mut writer = encrypting_client(64, 4, [1u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        assert_eq!(writer.write(5, b"value".to_vec(), &mut rng), None);

        // Every ciphertext physically stored, opened with the wrong key,
        // must fail authentication rather than return garbage plaintext.
        let mut any_ciphertext_present = false;
        for bucket in &writer.server.inner.buckets {
            for block in bucket {
                any_ciphertext_present = true;
                assert_eq!(open_oram_block(&[2u8; 32], &block.value), None);
            }
        }
        assert!(
            any_ciphertext_present,
            "test setup expects at least one block still resident in a bucket"
        );
    }

    fn encrypting_verified_client(
        capacity_leaves: u64,
        bucket_capacity: usize,
        key: [u8; 32],
    ) -> Client<Vec<u8>, EncryptingServerStorage<IntegrityCheckedServer<Vec<u8>>>> {
        let depth = depth_for_capacity(capacity_leaves);
        let num_leaves = 1u64 << depth;
        let inner = IntegrityCheckedServer::new((2 * num_leaves) as usize, bucket_capacity);
        let mut client = Client::with_server(
            depth,
            EncryptingServerStorage::new(inner, key, TEST_BLOCK_LEN),
        );
        client.init_empty_root();
        client
    }

    #[test]
    fn encrypting_storage_composes_with_integrity_checking() {
        let mut client = encrypting_verified_client(64, 4, [9u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(22);

        for id in 0..20u64 {
            assert_eq!(
                client.verified_write(id, vec![id as u8; 3], &mut rng),
                Ok(None)
            );
        }
        for id in 0..20u64 {
            assert_eq!(
                client.verified_read(id, &mut rng),
                Ok(Some(vec![id as u8; 3]))
            );
        }
    }

    #[test]
    fn a_corrupted_ciphertext_is_caught_as_an_integrity_error_not_a_panic() {
        let mut client = encrypting_verified_client(64, 4, [3u8; 32]);
        let mut rng = ChaCha20Rng::seed_from_u64(23);

        client.verified_write(1, vec![1, 2, 3], &mut rng).unwrap();

        // Flip a byte in the root bucket's ciphertext on the physical storage,
        // bypassing `Client`. Every access touches the root, so the next verified
        // access must report `IntegrityError` (see CONFIDENTIALITY), not panic.
        let root_bucket = &mut client.server.inner.inner.buckets[1];
        assert!(
            !root_bucket.is_empty(),
            "test setup expects the root bucket to hold the block just written"
        );
        root_bucket[0].value[ORAM_NONCE_LEN] ^= 0xFF;

        assert_eq!(client.verified_read(1, &mut rng), Err(IntegrityError));
    }
}
