//! Path ORAM: an oblivious storage layer where the *sequence of physical
//! storage locations touched* is independent of which logical block was
//! accessed — an observer watching storage access patterns (not
//! contents) learns nothing about which block a caller is reading or
//! writing.
//!
//! # Where this fits
//! Even with a channel that's confidential and authenticated (`novachannel`)
//! and a membership proof that hides *who* sent a message (`novachannel-rln`),
//! a server holding per-user state (rate-limit counters, nullifier sets, ...)
//! can still leak identity through *which record it touched* — e.g., "record
//! #4821 was read" narrows the sender to whoever owns that record, even
//! through end-to-end encryption. Path ORAM closes that gap for
//! server-side state lookups.
//!
//! # Complexity, honestly
//! Each [`PathOram::access`] touches `O(log n)` storage buckets, not
//! `O(1)` — that's not a shortcoming of this implementation, it's a
//! proven lower bound (Goldreich-Ostrovsky) for *any* ORAM construction:
//! hiding the access pattern over `n` blocks with `O(1)` client storage
//! requires `Ω(log n)` amortized bandwidth per access. `O(1)` ORAM is not
//! an engineering gap to close, it's a provably unachievable target.
//!
//! # Client/server split
//! [`Client`] holds only the secret state that makes the scheme oblivious —
//! the position map and the stash — and never touches bucket storage
//! directly; every bucket read/write goes through the [`ServerStorage`]
//! trait. This isn't decoration: it's what makes "the position map and
//! stash must never be colocated with server storage" a fact about the
//! *types* rather than a rule a future change could quietly violate by
//! adding a field to the wrong struct. [`InMemoryServer`] is the reference
//! `ServerStorage` implementation used for testing; a networked deployment
//! implements the same trait over RPCs instead, and `Client`'s logic
//! doesn't change at all. [`PathOram`] is `Client<V, InMemoryServer<V>>`
//! — the batteries-included default for when you don't need a different
//! `ServerStorage`.
//!
//! One thing this split does *not* do: [`Block`] carries `id` and `value`
//! in the clear even in [`InMemoryServer`]. A real deployment's
//! `ServerStorage` implementation must encrypt both before they leave the
//! client — this crate provides the access-pattern obliviousness, not
//! confidentiality of what's stored, which is `novachannel`'s job.
//!
//! # Algorithm
//! Standard Path ORAM (Stefanov et al., CCS 2013): a binary tree of
//! buckets, each holding up to `Z` blocks. Every logical block is mapped to
//! a uniformly random *leaf*; a block is guaranteed to currently live
//! somewhere along the path from the root to its mapped leaf (either in a
//! bucket on that path, or in the client-side stash as overflow). Every
//! access — read or write, indistinguishably — re-randomizes the target
//! block's leaf, downloads and clears every bucket on the path to its
//! (now-old) leaf into the stash, updates the target block if needed, and
//! greedily re-evicts as much of the stash as possible back into the path,
//! deepest-eligible bucket first.

#![deny(unsafe_code)]
// Every `.unwrap()` this catches either gets replaced with a
// `.expect("reason")` documenting why it can't actually fail, or is a
// bug — the same discipline libsignal's own crates enforce
// (`#![warn(clippy::unwrap_used)]` in their `protocol`/`zkgroup` crate
// roots), turning a one-time manual audit into a standing, compiler-
// checked one. Exempted in test code, where `.unwrap()` on a value the
// test itself just constructed is the normal, idiomatic thing to do.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::HashMap;

use rand::Rng;

pub type BlockId = u64;

#[derive(Clone)]
pub struct Block<V> {
    pub id: BlockId,
    pub value: V,
}

/// Everything an untrusted server needs to implement: storage for buckets
/// by node index, with no notion of which block "belongs" to whom (that
/// knowledge — the position map — lives only in [`Client`]). Bucket node
/// indices use heap numbering: root = 1, children of `i` are `2i`/`2i+1`,
/// leaves are `num_leaves..2*num_leaves`.
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

/// The reference [`ServerStorage`]: plain in-process `Vec` buckets. Stands
/// in for what a real deployment would reach over the network — see the
/// module docs on why swapping this for a networked implementation
/// requires no change to [`Client`] at all.
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

/// Rounds a desired leaf capacity up to the tree depth that provides it.
pub fn depth_for_capacity(capacity_leaves: u64) -> u32 {
    (capacity_leaves.max(1) as f64).log2().ceil() as u32
}

/// The oblivious client: owns exactly the secret state that makes Path
/// ORAM work (the position map and the stash) and drives an arbitrary
/// [`ServerStorage`] through the protocol. See the module docs — this
/// separation is the whole point.
pub struct Client<V: Clone, S: ServerStorage<V>> {
    depth: u32,
    num_leaves: u64,
    server: S,
    /// Secret client state: which leaf each block is currently assigned to.
    /// **Must never be exposed to `S`** — that's exactly what `S` being a
    /// trait object the client merely *calls*, rather than a field it
    /// shares, is for.
    position_map: HashMap<BlockId, u64>,
    /// Secret client-side overflow. Bounded in practice (Stefanov et al.
    /// show it stays small with overwhelming probability for reasonable
    /// `Z`), but this reference implementation doesn't enforce a cap —
    /// callers who need a hard bound should monitor `stash_len()`.
    stash: Vec<Block<V>>,
    /// The client's trusted Merkle root over server-visible bucket
    /// contents. Only meaningful (and only ever read or written) when `S`
    /// implements [`VerifiableServerStorage`] and the caller uses
    /// `verified_read`/`verified_write` (see `integrity` module docs);
    /// harmless dead weight otherwise. This is *not* secret — unlike
    /// `position_map`/`stash`, it can be handed to a third party to audit,
    /// which is exactly the property that makes it useful.
    root: [u8; 32],
}

impl<V: Clone, S: ServerStorage<V>> Client<V, S> {
    /// `depth` must match how `server` was sized (`2^depth` leaves,
    /// `2^(depth+1)` bucket nodes) — see [`depth_for_capacity`] and
    /// [`PathOram::new`] for the common case of building both together.
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
        rng.gen_range(0..self.num_leaves)
    }

    /// Reads (and clears) every bucket on `path_nodes(leaf)` into the stash.
    fn read_path_into_stash(&mut self, leaf: u64) {
        for node in self.path_nodes(leaf) {
            self.stash.append(&mut self.server.read_and_clear(node));
        }
    }

    /// Greedily re-evicts stash blocks back onto the path, deepest
    /// (leaf-most) eligible bucket first — the standard Path ORAM eviction
    /// order, which is what keeps the stash small in expectation.
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

    /// Oblivious read: returns the current value, or `None` if `id` has
    /// never been written. Touches the same access pattern as a write of
    /// equal size to any other block — an observer of the bucket-index
    /// sequence cannot distinguish this call from a write, nor tell which
    /// `id` was targeted.
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

/// The batteries-included default: a [`Client`] paired with the reference
/// [`InMemoryServer`]. Reach for [`Client`] directly with your own
/// [`ServerStorage`] impl for a networked deployment.
pub type PathOram<V> = Client<V, InMemoryServer<V>>;

impl<V: Clone> PathOram<V> {
    /// `capacity_leaves` is rounded up to the next power of two; `Z` is the
    /// per-bucket capacity (4 is the standard choice, giving negligible
    /// stash overflow probability for realistic tree sizes).
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
// Path ORAM as implemented above provides obliviousness — a passive server
// learns nothing about *which* logical block an access targets — but
// nothing stops an *active* server from tampering with what it returns: it
// could silently corrupt, drop, or replay stale bucket contents, and
// `Client` would have no way to notice. That's a real gap between what the
// module docs describe (a server the client merely doesn't trust with
// secrecy) and what's actually enforced (nothing about integrity).
//
// This section closes it the standard way integrity-checked outsourced
// storage does: a Merkle hash tree layered over the *same* binary tree
// Path ORAM already uses, so verifying a path costs nothing beyond what an
// access already touches (`O(log n)`, not an added asymptotic cost).
// `Client` keeps only the 32-byte root — itself not secret, since its job
// is to be checked, not hidden.
//
// Node `v`'s hash is `H(bucket_hash(v), hash(left(v)), hash(right(v)))`,
// with a fixed sentinel standing in for "no child" at the ORAM tree's
// leaf level. On every access, `Client` already reads and rewrites every
// bucket on `path_nodes(leaf)` — exactly the nodes whose hash changes, and
// exactly the nodes it needs the *sibling* hashes of (one per level, off
// the path, unions unchanged) to recompute the chain from leaf to root
// and check it against the trusted root before believing anything the
// server just returned.

use sha2::{Digest, Sha256};

const EMPTY_CHILD: [u8; 32] = [0u8; 32];

fn hash_bucket<V: AsRef<[u8]>>(blocks: &[Block<V>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"novachannel-oram bucket v1");
    hasher.update((blocks.len() as u32).to_be_bytes());
    for b in blocks {
        hasher.update(b.id.to_be_bytes());
        let bytes = b.value.as_ref();
        hasher.update((bytes.len() as u32).to_be_bytes());
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

/// A [`ServerStorage`] that also maintains (and reveals) the Merkle hash
/// of every bucket node, so a [`Client`] can verify integrity without
/// trusting the server. The hashes themselves reveal nothing beyond what
/// obliviousness already permits an observer to see (which nodes were
/// touched); what they add is the ability to *detect* tampering with the
/// contents of those nodes.
pub trait VerifiableServerStorage<V>: ServerStorage<V> {
    /// The currently-stored Merkle hash for `node`.
    fn node_hash(&self, node: usize) -> [u8; 32];
    /// Updates the stored hash for `node` after its bucket contents (or a
    /// descendant's) changed.
    fn set_node_hash(&mut self, node: usize, hash: [u8; 32]);
}

/// The reference [`VerifiableServerStorage`]: [`InMemoryServer`] plus a
/// parallel array of node hashes, updated in lock-step by
/// [`Client::verified_read`]/[`Client::verified_write`].
///
/// The hashes a fresh instance is constructed with are **placeholder
/// zeros, not valid hashes of an empty subtree** — call
/// [`Client::init_empty_root`] before any verified access, or every
/// access will spuriously fail integrity verification against a perfectly
/// honest server. `new` doesn't compute the correct initial hashes itself
/// specifically so there's exactly one definition of "the hash of an
/// empty subtree" in this crate (see `init_empty_root`'s doc comment).
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

/// Returned by [`Client::verified_read`]/[`Client::verified_write`] when
/// the server's returned bucket contents don't match the client's trusted
/// root — i.e. the server tampered with, dropped, or replayed stale data.
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
    /// Establishes the client's trusted root for a freshly created,
    /// all-empty server, seeding every node's hash on the server to match
    /// (a fresh [`IntegrityCheckedServer`]'s hashes are placeholder zeros,
    /// not valid "empty subtree" hashes — this is what makes them valid).
    /// **The single definition of "the hash of an empty subtree" lives
    /// here and nowhere else** — `IntegrityCheckedServer::new` doesn't
    /// duplicate it, specifically so the two can't drift apart the way
    /// `ENGINEERING-STANDARDS.md` §4.2 warns a second copy of the same
    /// formula eventually does.
    ///
    /// A real deployment resuming against an already-populated server must
    /// instead obtain the root from an out-of-band trusted source — the
    /// same trust-provisioning pattern `novachannel::handshake`'s
    /// peer-identity pinning uses, and for the same reason: a root
    /// computed by asking the untrusted server for one isn't trustworthy.
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

    /// Given the leaf-to-root `path` and each node's current *bucket*
    /// contents (`contents_at` returns `hash_bucket(..)`, not yet combined
    /// with any child hash), recomputes the full Merkle chain bottom-up,
    /// fetching each level's off-path sibling hash from the server
    /// (untouched by this access, so still trustworthy) to combine with
    /// the running hash.
    ///
    /// Returns every node's final *combined* hash (`hash_node(bucket_hash,
    /// left, right)`, not the raw bucket hash `contents_at` was given) —
    /// the caller needs these, not just the root, to update
    /// [`VerifiableServerStorage::set_node_hash`] correctly for every node
    /// on the path, not only node 1.
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
            // Put everything back so a caller who retries (e.g. against a
            // different, honest server) isn't left with buckets stuck
            // empty on the untrustworthy one.
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// A second, independent `ServerStorage` — wraps [`InMemoryServer`] but
    /// counts bucket touches, standing in for "a real networked server
    /// implementation" without actually adding network I/O to a unit test.
    /// Its existence, and [`client_works_unchanged_against_a_different_server_impl`]
    /// using it through [`Client`] directly (not the [`PathOram`] alias),
    /// is the actual proof that swapping `ServerStorage` requires no change
    /// to `Client`'s logic — the architectural claim in the module docs,
    /// not just an assertion of it.
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
            let id = rng.gen_range(0..200u64);
            if rng.gen_bool(0.5) {
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
            let id = rng.gen_range(0..200u64);
            if rng.gen_bool(0.5) {
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

        // Corrupt the root bucket directly, bypassing `Client` entirely —
        // standing in for a malicious or simply buggy server. Every access
        // touches the root (`path_nodes` always ends at node 1), so the
        // very next verified access must detect this.
        client.server.inner.buckets[1].push(Block {
            id: 999,
            value: vec![0xFF],
        });

        assert_eq!(client.verified_read(1, &mut rng), Err(IntegrityError));
    }

    #[test]
    fn a_server_that_replays_a_stale_bucket_is_caught() {
        let mut client = verified_client(64, 4);
        let mut rng = ChaCha20Rng::seed_from_u64(13);

        client.verified_write(2, vec![9, 9], &mut rng).unwrap();
        // Snapshot the (honest, current) root bucket, then perform another
        // access that changes it, then replay the stale snapshot back —
        // simulating a server that serves an old, otherwise
        // internally-consistent version of a bucket instead of the
        // current one. Individually-valid-looking stale data is exactly
        // the case a naive "does this bucket look well-formed" check
        // would miss; only a root comparison catches it.
        let stale_root_bucket = client.server.inner.buckets[1].clone();
        client.verified_write(3, vec![7, 7], &mut rng).unwrap();
        client.server.inner.buckets[1] = stale_root_bucket;

        assert_eq!(client.verified_read(2, &mut rng), Err(IntegrityError));
    }
}
