use ark_r1cs_std::fields::fp::FpVar;
// use chrono::Local;
// use env_logger::Builder;
use log::{debug, error, info, trace, warn};
// use std::env;
// use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(feature = "dex")]
use swiftness_air::layout::dex::Layout;
#[cfg(feature = "recursive")]
use swiftness_air::layout::recursive::Layout;
#[cfg(feature = "recursive_with_poseidon")]
use swiftness_air::layout::recursive_with_poseidon::Layout;
#[cfg(feature = "small")]
use swiftness_air::layout::small::Layout;
#[cfg(feature = "starknet")]
use swiftness_air::layout::starknet::Layout;
#[cfg(feature = "starknet_with_keccak")]
use swiftness_air::layout::starknet_with_keccak::Layout;
use swiftness_field::{Fp, SimpleField};
pub use swiftness_proof_parser::*;
pub use swiftness_stark::*;

use clap::Parser;
use jemallocator::Jemalloc;
use swiftness_utils::curve::StarkwareCurve;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
#[command(author, version, about)]
struct CairoVMVerifier {
    /// Path to proof JSON file
    #[clap(short, long)]
    proof: PathBuf,
}

fn init_logger() {
    env_logger::init();
    error!("test error");
    warn!("test warn");
    info!("test info");
    debug!("test debug");
    trace!("test trace");
}
fn init_memory_logger() {
    let start_time = Instant::now();

    thread::spawn(move || loop {
        if start_time.elapsed() >= Duration::from_secs(600) {
            println!("Memory logger stopped after 10 minutes.");
            break;
        }

        swiftness_utils::mem_tools::print_memory_usage();

        thread::sleep(Duration::from_secs(1));
    });
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();
    init_memory_logger();
    info!("Parsing proof from file");
    let cli = CairoVMVerifier::parse();
    let stark_proof = parse(std::fs::read_to_string(cli.proof)?)?;
    let security_bits: FpVar<Fp> = stark_proof.config.security_bits();
    info!("Verifying proof");
    let (program_hash, output_hash) =
        match stark_proof.verify::<StarkwareCurve, Layout>(security_bits) {
            Ok((program_hash, output_hash)) => (program_hash, output_hash),
            Err(e) => {
                panic!("Error: {:?}", e);
            }
        };
    debug!(
        "program_hash: {}, output_hash: {}",
        program_hash.get_value(),
        output_hash.get_value()
    );
    info!("Proof verified successfully");
    Ok(())
}
