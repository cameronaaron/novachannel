//! Measures actual RLN STARK proving (and verification) *time*, the
//! measurement `docs/SYSTEMIZATION.md` §3.2 named as missing alongside
//! `proof_size.rs`'s byte counts: "proving time isn't benchmarked anywhere
//! in this repository... on a constrained mobile CPU that cost is paid per
//! rate-limited action." This example is that measurement, on whatever CPU
//! runs it. Run with:
//!
//!     cargo run -p novachannel-rln --release --example proving_time
//!
//! # Reading the numbers
//! Same four `ProofOptions` configurations `proof_size.rs` uses, so proving
//! time and proof size can be read side by side for the same soundness
//! level. Proving time is wall-clock on whatever machine runs this — no
//! claim is made about mobile-CPU-specific numbers, since no such device
//! ran this; the point is giving *a* real number instead of none, so a
//! deployment can scale it by its own target hardware's relative single-core
//! throughput rather than guessing blind. Each configuration is proved 5
//! times and the run reports min/median/max, since STARK proving time has
//! real variance from the circuit's own randomized witness data and OS
//! scheduling noise, not just measurement error a single run would hide.

use std::time::{Duration, Instant};

use novachannel_rln::air::{self, RlnAir, Witness};
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::permutation::{compress2, Params};
use novachannel_rln::{bytes_to_field, epoch_field, Identity};
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree as WinterMerkleTree};
use winterfell::math::fields::f64::BaseElement;
use winterfell::{AcceptableOptions, BatchingMethod, FieldExtension, Proof, ProofOptions, Prover};

struct Config {
    label: &'static str,
    num_queries: usize,
    blowup_factor: usize,
    grinding_factor: u32,
    field_extension: FieldExtension,
}

const REPEATS: usize = 5;

fn median(durations: &mut [Duration]) -> Duration {
    durations.sort();
    durations[durations.len() / 2]
}

fn main() {
    // Same four configurations `proof_size.rs` measures -- see that
    // example's own comment for why blowup is held fixed at 16.
    let configs = [
        Config {
            label: "fewer queries, weaker",
            num_queries: 16,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::None,
        },
        Config {
            label: "old default before the 128-bit hardening pass (~96-bit)",
            num_queries: 24,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::None,
        },
        Config {
            label: "this crate's default (~148-bit conjectured, see air.rs)",
            num_queries: 32,
            blowup_factor: 16,
            grinding_factor: 20,
            field_extension: FieldExtension::Quadratic,
        },
        Config {
            label: "more queries, stronger (~192-bit conjectured)",
            num_queries: 48,
            blowup_factor: 16,
            grinding_factor: 0,
            field_extension: FieldExtension::None,
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
    let x = bytes_to_field(b"proving-time measurement");
    let a1 = compress2(&params, identity.sk, epoch);
    let y = identity.sk + a1 * x;

    println!(
        "{:<45} {:>10} {:>12} {:>12} {:>12} {:>12}",
        "config", "queries", "prove min", "prove med", "prove max", "verify med"
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

        let pub_inputs = {
            let trace = air::build_trace(&params, &witness, epoch, x);
            let root = trace.get(0, air::root_row(air::DEPTH));
            air::PublicInputs {
                root,
                epoch,
                x,
                y,
                nullifier: a1,
            }
        };

        let mut prove_times = Vec::with_capacity(REPEATS);
        let mut proofs: Vec<Proof> = Vec::with_capacity(REPEATS);
        for _ in 0..REPEATS {
            // A fresh trace per run: `Prover::prove` consumes its trace, and
            // building one is itself part of what a real caller pays on
            // every proof, not overhead to hide from the measurement.
            let trace = air::build_trace(&params, &witness, epoch, x);
            let prover = air::RlnProver::new(options.clone(), pub_inputs.clone());
            let start = Instant::now();
            let proof = prover.prove(trace).expect("proof generation failed");
            prove_times.push(start.elapsed());
            proofs.push(proof);
        }

        // Verifying against `AcceptableOptions::OptionSet(vec![options])`
        // rather than `air::verify`'s hardcoded 95-bit floor: the point
        // here is timing verification at whatever security level this
        // configuration actually provides, including the deliberately
        // weaker ones, not enforcing the production minimum.
        let acceptable = AcceptableOptions::OptionSet(vec![options.clone()]);
        let mut verify_times = Vec::with_capacity(REPEATS);
        for proof in &proofs {
            let start = Instant::now();
            winterfell::verify::<
                RlnAir,
                Blake3_256<BaseElement>,
                DefaultRandomCoin<Blake3_256<BaseElement>>,
                WinterMerkleTree<Blake3_256<BaseElement>>,
            >(proof.clone(), pub_inputs.clone(), &acceptable)
            .expect("verification failed");
            verify_times.push(start.elapsed());
        }

        let min = *prove_times.iter().min().unwrap();
        let max = *prove_times.iter().max().unwrap();
        let med = median(&mut prove_times);
        let verify_med = median(&mut verify_times);

        println!(
            "{:<45} {:>10} {:>12?} {:>12?} {:>12?} {:>12?}",
            c.label, c.num_queries, min, med, max, verify_med
        );
    }

    println!(
        "\n{REPEATS} runs per configuration on this machine ({} cores available); no claim about \
         mobile-CPU-specific numbers is made -- scale by a target device's relative single-core \
         throughput. Verification, unlike proving, is the side a resource-constrained *verifier* \
         (not necessarily the same low-end device that proved) actually pays.",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
}
