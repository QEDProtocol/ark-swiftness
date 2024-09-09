use starknet_crypto::Felt;
use swiftness_air::domains::StarkDomains;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> StarkDomains<F> {
    StarkDomains {
        log_eval_domain_size: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
        eval_domain_size: F::from_stark_felt(Felt::from_hex_unchecked("0x100000")),
        eval_generator: F::from_stark_felt(Felt::from_hex_unchecked( "0x594beafca8a00d9581d81caee93dc85c727c9af7fc4c648e3d47b998574e81f",)),
        log_trace_domain_size: F::from_stark_felt(Felt::from_hex_unchecked("0x12")),
        trace_domain_size: F::from_stark_felt(Felt::from_hex_unchecked("0x40000")),
        trace_generator: F::from_stark_felt(Felt::from_hex_unchecked( "0x4768803ef85256034f67453635f87997ff61841e411ee63ce7b0a8b9745a046",)),
    }
}
