//! Measures RLN STARK proof sizes under several `ProofOptions`, putting
//! numbers on the "bigger than Groth16" tradeoff in
//! `docs/SYSTEMIZATION.md` §3.2. Run with:
//!
//!     cargo run -p novachannel-rln --release --example proof_size
//!
//! # Reading the numbers
//! The security column is winterfell's own `Proof::conjectured_security`.
//! This example used to print `num_queries * log2(blowup_factor) +
//! grinding_factor`, which is only the query term of winterfell's
//! `min(field_security, query_security) - 1` (capped by hash collision
//! resistance), and overstated the default by 21 bits (148 vs 127): a
//! 64-bit field with a quadratic extension caps `field_security` at 128
//! regardless of queries.
//!
//! For comparison, a Groth16 proof on BN254 is 128 bytes compressed (2 G1 +
//! 1 G2), independent of circuit size and security level. The STARK numbers
//! printed here are the bandwidth cost of hash-based, setup-free,
//! post-quantum soundness.

use novachannel_rln::air::{self, Witness};
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::permutation::{compress2, Params};
use novachannel_rln::{bytes_to_field, epoch_field, Identity};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::fields::f64::BaseElement;
use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover};

struct Config {
    label: &'static str,
    num_queries: usize,
    blowup_factor: usize,
    grinding_factor: u32,
    field_extension: FieldExtension,
}

fn main() {
    // Blowup 16 is the minimum this AIR accepts: `ProofOptions` derives a floor
    // from the constraint degrees, and the degree-7 S-box with five blended
    // periodic selectors exceeds what blowup 8 covers (the old `NovaRescue`
    // AIR accepted 8). So blowup is fixed and query count is the one dial;
    // size and conjectured soundness both scale with it.
    let configs = [
        Config {
            label: "16 queries, no field extension",
            num_queries: 16,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::None,
        },
        Config {
            label: "the default before the 128-bit hardening pass",
            num_queries: 24,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::None,
        },
        Config {
            label: "this crate's default (see air.rs)",
            num_queries: 32,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Quadratic,
        },
        Config {
            label: "cubic: reaches 128 bits, rejected on cost (see air.rs)",
            num_queries: 32,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Cubic,
        },
        Config {
            label: "more queries, same cap: queries are not the binding term",
            num_queries: 48,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Cubic,
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
        "{:<55} {:>8} {:>8} {:>11} {:>17} {:>14}",
        "config", "queries", "blowup", "extension", "conjectured bits", "proof size"
    );
    for c in &configs {
        let options = ProofOptions::new(
            c.num_queries,
            c.blowup_factor,
            c.grinding_factor,
            c.field_extension,
            8,
            31,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );

        let trace = air::build_trace(&params, &witness, epoch, x);
        let root = trace.get(0, air::root_row(air::DEPTH));
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

        // Winterfell's own computation, not a re-derivation of it.
        let conjectured_bits = proof
            .conjectured_security::<Blake3_256<BaseElement>>()
            .bits();
        println!(
            "{:<55} {:>8} {:>8} {:>11} {:>17} {:>8} bytes",
            c.label,
            c.num_queries,
            c.blowup_factor,
            format!("{:?}", c.field_extension),
            conjectured_bits,
            bytes.len()
        );
    }

    println!(
        "\nGroth16 comparison point: 128 bytes compressed (BN254), independent of circuit size."
    );
    println!(
        "Note the first two rows: with no field extension a 64-bit base field caps conjectured\n\
         security at 63 bits however many queries are added, which is why the extension degree --\n\
         not the query count -- is the dial that matters here. The last row shows the other end of\n\
         the same story: past a cubic extension the cap is Blake3_256's 128-bit collision\n\
         resistance, so extra queries buy proof size and nothing else."
    );
}
