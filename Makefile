.PHONY: verify
verify:
	cargo run --release --bin ark_swiftness_cli --features starknet_with_keccak,keccak --no-default-features -- --proof ./proofs/starknet_with_keccak/cairo0_example_proof.json
