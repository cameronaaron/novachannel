//! Measures actual RLN STARK proof sizes under a few `ProofOptions`
//! configurations, so "STARK proofs are bigger than Groth16's" (the
//! honest tradeoff noted in `docs/SYSTEMIZATION.md` §3.2) has real numbers
//! attached instead of staying an abstract claim. Run with:
//!
//!     cargo run -p novachannel-rln --release --example proof_size
//!
//! # Reading the numbers
//! The security column is winterfell's own
//! `Proof::conjectured_security`, read off each proof after it is
//! generated — not the `num_queries * log2(blowup_factor) +
//! grinding_factor` approximation this example used to print. That
//! approximation is only the *query* term of winterfell's formula, which
//! actually computes `min(field_security, query_security) - 1`, capped by
//! the hash's collision resistance. Printing the query term alone
//! overstated this crate's default by 21 bits (148 claimed, 127 real),
//! because a 64-bit field under a quadratic extension caps
//! `field_security` at 128 no matter how many queries are added. Reporting
//! what the library computes, rather than a formula that disagrees with
//! it, is the whole point of measuring.
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
    // Blowup factor 16 is the minimum this AIR accepts (`ProofOptions`
    // enforces a floor derived from the circuit's own constraint degrees;
    // 8 is rejected outright since the Poseidon2 port's degree-7 S-box
    // combined with its five blended periodic selectors pushes the
    // dominant transition constraint's degree bound past what blowup 8
    // covers -- the from-scratch `NovaRescue` permutation this AIR used
    // before accepted blowup 8), so it's held fixed here and query count
    // is the dial: proof size and conjectured soundness both scale with
    // it, isolating that one relationship instead of conflating two dials.
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
