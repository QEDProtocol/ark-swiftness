use crate::{
    public_memory::PublicInput,
    types::{AddrValue, Page, SegmentInfo},
};
use alloc::vec;
use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn get<F: SimpleField + PoseidonHash>() -> PublicInput<F> {
    PublicInput {
        log_n_steps: F::from_stark_felt(Felt::from_hex_unchecked("0xe")),
        range_check_min: F::from_stark_felt(Felt::from_hex_unchecked("0x7ffa")),
        range_check_max: F::from_stark_felt(Felt::from_hex_unchecked("0x8001")),
        layout: F::from_stark_felt(Felt::from_hex_unchecked("0x726563757273697665")),
        dynamic_params: vec![],
        segments: vec![
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x5")),
            },
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x25")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x68")),
            },
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x68")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
            },
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
            },
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x1ea")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x1ea")),
            },
            SegmentInfo {
                begin_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x9ea")),
                stop_ptr: F::from_stark_felt(Felt::from_hex_unchecked("0x9ea")),
            },
        ],
        padding_addr: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
        padding_value: F::from_stark_felt(Felt::from_hex_unchecked("0x40780017fff7fff")),
        main_page: Page(vec![
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x40780017fff7fff")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x3")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1104800180018000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x5")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x10780017fff7fff")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x6")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x0")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x7")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x40780017fff7fff")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x8")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x9")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x400380007ffa8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xa")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480680017fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xb")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xc")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480680017fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xd")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xe")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a80007fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0xf")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1104800180018000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x10")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x9")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x11")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x400280017ffa7fff")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x12")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x482680017ffa8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x13")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x2")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x14")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a7ffb7fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x15")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a7ffc7fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x16")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a7ffd7fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x17")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x208b7fff7fff7ffe")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x18")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x20780017fff7ffd")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x19")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x4")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1a")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a7ffc7fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1b")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x208b7fff7fff7ffe")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1c")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x480a7ffc7fff8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1d")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x482a7ffc7ffb8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1e")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x482680017ffd8000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x1f")),
                value: F::from_stark_felt(Felt::from_hex_unchecked(
                    "0x800000000000011000000000000000000000000000000000000000000000000",
                )),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x20")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1104800180018000")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x21")),
                value: F::from_stark_felt(Felt::from_hex_unchecked(
                    "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff9",
                )),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x22")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x208b7fff7fff7ffe")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x23")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x25")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x24")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x0")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x25")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x68")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x26")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x27")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1ea")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x28")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x9ea")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x64")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x65")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x6a")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x66")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x1ea")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x67")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x9ea")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x68")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0xa")),
            },
            AddrValue {
                address: F::from_stark_felt(Felt::from_hex_unchecked("0x69")),
                value: F::from_stark_felt(Felt::from_hex_unchecked("0x90")),
            },
        ]),
        continuous_page_headers: vec![],
    }
}
