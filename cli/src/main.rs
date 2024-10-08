use std::path::PathBuf;
use ark_r1cs_std::fields::fp::FpVar;
use swiftness_field::{Fp, SimpleField};
pub use swiftness_proof_parser::*;
pub use swiftness_stark::*;

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

use clap::Parser;
use swiftness_utils::curve::StarkwareCurve;

#[derive(Parser)]
#[command(author, version, about)]
struct CairoVMVerifier {
    /// Path to proof JSON file
    #[clap(short, long)]
    proof: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CairoVMVerifier::parse();
    let stark_proof = parse(std::fs::read_to_string(cli.proof)?)?;
    let security_bits: FpVar<Fp> = stark_proof.config.security_bits();
    let (program_hash, output_hash) = stark_proof.verify::<StarkwareCurve, Layout>(security_bits).unwrap();
    println!("program_hash: {}, output_hash: {}", program_hash.get_value(), output_hash.get_value());
    Ok(())
}
