//! A plain (non-ZK) Merkle tree over `NovaRescue` compression, used to hold
//! the RLN membership set. The tree itself is public infrastructure (every
//! member and verifier can maintain it, e.g. from an on-chain contract's
//! event log); the privacy property comes from the STARK proof of
//! membership in [`crate::proof`], not from the tree being secret.

use winterfell::math::{fields::f128::BaseElement, FieldElement};

use crate::permutation::{compress2, Params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// One step of a Merkle authentication path: the sibling hash and which
/// side the prover's node sits on.
#[derive(Clone, Copy, Debug)]
pub struct PathStep {
    pub sibling: BaseElement,
    pub side: Side,
}

pub struct MerkleTree {
    depth: usize,
    /// `levels[0]` = leaves, `levels[depth]` = the single root.
    levels: Vec<Vec<BaseElement>>,
    params: Params,
}

impl MerkleTree {
    /// Builds a tree of the given depth (`2^depth` leaves), padding with a
    /// fixed zero leaf for any unused slots.
    pub fn new(depth: usize, leaves: &[BaseElement]) -> Self {
        let capacity = 1usize << depth;
        assert!(leaves.len() <= capacity, "too many leaves for this depth");

        let params = Params::new();
        let mut level: Vec<BaseElement> = leaves.to_vec();
        level.resize(capacity, BaseElement::ZERO);

        let mut levels = vec![level];
        for _ in 0..depth {
            let prev = levels
                .last()
                .expect("levels is seeded with one element before this loop runs");
            let next: Vec<BaseElement> = prev
                .chunks(2)
                .map(|pair| compress2(&params, pair[0], pair[1]))
                .collect();
            levels.push(next);
        }

        MerkleTree {
            depth,
            levels,
            params,
        }
    }

    pub fn root(&self) -> BaseElement {
        self.levels[self.depth][0]
    }

    /// A canonical byte encoding of the current root, for callers who need
    /// to sign or otherwise treat it as an opaque message — e.g. a
    /// mixnode quorum jointly attesting to "the current membership root"
    /// via `novachannel-mpc`'s FROST implementation, so clients trust the
    /// set of members via a threshold signature instead of needing
    /// separate PKI for the membership tree itself.
    pub fn root_bytes(&self) -> [u8; 16] {
        use winterfell::math::StarkField;
        self.root().as_int().to_be_bytes()
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Authentication path for leaf `index`, ordered from the leaf's level
    /// up to (but not including) the root.
    pub fn path(&self, index: usize) -> Vec<PathStep> {
        assert!(index < self.levels[0].len());
        let mut steps = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let is_right = idx % 2 == 1;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            steps.push(PathStep {
                sibling: self.levels[level][sibling_idx],
                side: if is_right { Side::Right } else { Side::Left },
            });
            idx /= 2;
        }
        steps
    }

    /// Reference (non-ZK) verifier, used in tests to sanity-check that a
    /// path built by [`MerkleTree::path`] is internally consistent before
    /// it's fed to the STARK prover — the STARK proves this same relation
    /// without revealing `leaf` or the path.
    pub fn verify_path(
        params: &Params,
        leaf: BaseElement,
        path: &[PathStep],
        root: BaseElement,
    ) -> bool {
        let mut cur = leaf;
        for step in path {
            cur = match step.side {
                Side::Left => compress2(params, cur, step.sibling),
                Side::Right => compress2(params, step.sibling, cur),
            };
        }
        cur == root
    }
}
