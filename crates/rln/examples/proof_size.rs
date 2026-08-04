//! Measures actual RLN STARK proof sizes under a few `ProofOptions`
//! configurations, so "STARK proofs are bigger than Groth16's" (the
//! honest tradeoff noted in `docs/SYSTEMIZATION.md` §3.2) has real numbers
//! attached instead of staying an abstract claim. Run with:
//!
//!     cargo run -p novachannel-rln --release --example proof_size
//!
//! # Reading the numbers
//! FRI's conjectured soundness for this query/blowup combination is
//! roughly `num_queries * log2(blowup_factor)` bits (the standard
//! back-of-envelope bound cited alongside winterfell's own examples) —
//! this example prints that alongside the actual measured proof size for
//! each configuration, so the size/soundness tradeoff `ProofOptions`
//! controls is visible directly rather than asserted.
//!
//! For comparison: a Groth16 proof is 2 G1 + 1 G2 elements — on BN254,
//! that's 128 bytes compressed, independent of circuit size or the
//! security level chosen (security there comes from curve size, not proof
//! parameters). Whatever this example prints for the STARK is the real
//! bandwidth cost of choosing hash-based, no-trusted-setup, post-quantum
//! soundness over that.

use novachannel_rln::air::{self, Witness};
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::permutation::{compress2, Params};
use novachannel_rln::{bytes_to_field, epoch_field, Identity};
use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover};

struct Config {
    label: &'static str,
    num_queries: usize,
    blowup_factor: usize,
    grinding_factor: u32,
}

fn main() {
    // Blowup factor 8 is the minimum this AIR accepts (`ProofOptions`
    // enforces a floor derived from the circuit's own constraint degrees —
    // 4 is rejected outright), so it's held fixed here and query count is
    // the dial: proof size and conjectured soundness both scale with it,
    // isolating that one relationship instead of conflating two dials.
    let configs = [
        Config {
            label: "fewer queries, weaker",
            num_queries: 16,
            blowup_factor: 8,
            grinding_factor: 0,
        },
        Config {
            label: "this crate's default (~96-bit conjectured)",
            num_queries: 32,
            blowup_factor: 8,
            grinding_factor: 0,
        },
        Config {
            label: "more queries, stronger (~192-bit conjectured)",
            num_queries: 64,
            blowup_factor: 8,
            grinding_factor: 0,
        },
    ];

    let params = Params::new();
    let identity = Identity::generate();
    let leaves = vec![identity.commitment(&params)];
    let tree = MerkleTree::new(air::DEPTH, &leaves);
    let path = tree.path(0);
    let witness = Witness {
        sk: identity.sk,
        path,
    };

    let epoch = epoch_field(1);
    let x = bytes_to_field(b"proof-size measurement");
    let a1 = compress2(&params, identity.sk, epoch);
    let y = identity.sk + a1 * x;

    println!(
        "{:<45} {:>10} {:>10} {:>18} {:>14}",
        "config", "queries", "blowup", "~conjectured bits", "proof size"
    );
    for c in &configs {
        let options = ProofOptions::new(
            c.num_queries,
            c.blowup_factor,
            c.grinding_factor,
            FieldExtension::None,
            8,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );

        let trace = air::build_trace(&params, &witness, epoch, x);
        let root = trace.get(0, air::ROOT_ROW_PUB);
        let pub_inputs = air::PublicInputs {
            root,
            epoch,
            x,
            y,
            nullifier: a1,
        };

        let prover = air::RlnProver::new(options, pub_inputs);
        let proof = prover.prove(trace).expect("proof generation failed");
        let bytes = proof.to_bytes();

        let conjectured_bits = (c.num_queries as f64) * (c.blowup_factor as f64).log2();
        println!(
            "{:<45} {:>10} {:>10} {:>18.0} {:>10} bytes",
            c.label,
            c.num_queries,
            c.blowup_factor,
            conjectured_bits,
            bytes.len()
        );
    }

    println!(
        "\nGroth16 comparison point: 128 bytes compressed (BN254), independent of circuit size."
    );
}
