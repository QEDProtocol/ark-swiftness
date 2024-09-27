use super::global_values::GlobalValues;
use crate::layout::LayoutTrait;
use starknet_crypto::Felt;
use swiftness_field::SimpleField;
use swiftness_hash::poseidon::PoseidonHash;

pub fn eval_composition_polynomial_inner<F: SimpleField + PoseidonHash>(
    mask_values: &[F],
    constraint_coefficients: &[F],
    point: &F,
    trace_generator: &F,
    global_values: &GlobalValues<F>,
) -> F {
    // Compute powers.
    let pow0 = point.powers_felt(&global_values.trace_length.rsh(11));
    let pow1 = pow0.clone() * &pow0; // pow(point, (safe_div(global_values.trace_length, 1024))).
    let pow2 = point.powers_felt(&global_values.trace_length.rsh(7));
    let pow3 = point.powers_felt(&global_values.trace_length.rsh(5));
    let pow4 = pow3.clone() * &pow3; // pow(point, (safe_div(global_values.trace_length, 16))).
    let pow5 = point.powers_felt(&global_values.trace_length.rsh(2));
    let pow6 = pow5.clone() * &pow5; // pow(point, (safe_div(global_values.trace_length, 2))).
    let pow7 = pow6.clone() * &pow6; // pow(point, global_values.trace_length).
    let pow8 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(128 as u64)));
    let pow9 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(2048 as u64)));
    let pow10 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(1 as u64)));
    let pow11 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(4 as u64)));
    let pow12 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(2 as u64)));
    let pow13 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(16 as u64)));
    let pow14 = trace_generator.powers_felt(&global_values.trace_length.rsh(1));
    let pow15 = trace_generator
        .powers_felt(&(F::from_constant(255 as u64).clone() * &global_values.trace_length.rsh(8)));
    let pow16 = trace_generator.powers_felt(&global_values.trace_length.rsh(6));
    let pow17 = pow16.clone() * &pow16; // pow(trace_generator, (safe_div(global_values.trace_length, 32))).
    let pow18 = pow16.clone() * &pow17; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 64))).
    let pow19 = pow16.clone() * &pow18; // pow(trace_generator, (safe_div(global_values.trace_length, 16))).
    let pow20 = pow16.clone() * &pow19; // pow(trace_generator, (safe_div((safe_mult(5, global_values.trace_length)), 64))).
    let pow21 = pow16.clone() * &pow20; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 32))).
    let pow22 = pow16.clone() * &pow21; // pow(trace_generator, (safe_div((safe_mult(7, global_values.trace_length)), 64))).
    let pow23 = pow16.clone() * &pow22; // pow(trace_generator, (safe_div(global_values.trace_length, 8))).
    let pow24 = pow16.clone() * &pow23; // pow(trace_generator, (safe_div((safe_mult(9, global_values.trace_length)), 64))).
    let pow25 = pow16.clone() * &pow24; // pow(trace_generator, (safe_div((safe_mult(5, global_values.trace_length)), 32))).
    let pow26 = pow16.clone() * &pow25; // pow(trace_generator, (safe_div((safe_mult(11, global_values.trace_length)), 64))).
    let pow27 = pow16.clone() * &pow26; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 16))).
    let pow28 = pow16.clone() * &pow27; // pow(trace_generator, (safe_div((safe_mult(13, global_values.trace_length)), 64))).
    let pow29 = pow16.clone() * &pow28; // pow(trace_generator, (safe_div((safe_mult(7, global_values.trace_length)), 32))).
    let pow30 = pow16.clone() * &pow29; // pow(trace_generator, (safe_div((safe_mult(15, global_values.trace_length)), 64))).
    let pow31 = trace_generator.powers_felt(
        &((F::one().clone() + &F::two()).clone() * &global_values.trace_length.rsh(2)),
    );
    let pow32 = pow27.clone() * &pow31; // pow(trace_generator, (safe_div((safe_mult(15, global_values.trace_length)), 16))).
    let pow33 = pow18.clone() * &pow32; // pow(trace_generator, (safe_div((safe_mult(63, global_values.trace_length)), 64))).

    // Compute domains.
    let domain0 = pow7.clone() - &F::one();
    let domain1 = pow6.clone() - &F::one();
    let domain2 = pow5.clone() - &F::one();
    let domain3 = pow4.clone() - &pow32;
    let domain4 = pow4.clone() - &F::one();
    let domain5 = pow3.clone() - &F::one();
    let domain6 = pow2.clone() - &F::one();
    let domain7 = pow2.clone() - &pow31;
    let temp = pow2.clone() - &pow16;
    let temp = temp * (pow2.clone() - &pow17);
    let temp = temp * (pow2.clone() - &pow18);
    let temp = temp * (pow2.clone() - &pow19);
    let temp = temp * (pow2.clone() - &pow20);
    let temp = temp * (pow2.clone() - &pow21);
    let temp = temp * (pow2.clone() - &pow22);
    let temp = temp * (pow2.clone() - &pow23);
    let temp = temp * (pow2.clone() - &pow24);
    let temp = temp * (pow2.clone() - &pow25);
    let temp = temp * (pow2.clone() - &pow26);
    let temp = temp * (pow2.clone() - &pow27);
    let temp = temp * (pow2.clone() - &pow28);
    let temp = temp * (pow2.clone() - &pow29);
    let temp = temp * (pow2.clone() - &pow30);
    let domain8 = temp * &(domain6);
    let domain9 = pow1.clone() - &F::one();
    let domain10 = pow1.clone() - &pow15;
    let domain11 = pow1.clone() - &pow33;
    let domain12 = pow0.clone() - &pow14;
    let domain13 = pow0.clone() - &F::one();
    let domain14 = point.clone() - &pow13;
    let domain15 = point.clone() - &F::one();
    let domain16 = point.clone() - &pow12;
    let domain17 = point.clone() - &pow11;
    let domain18 = point.clone() - &pow10;
    let domain19 = point.clone() - &pow9;
    let domain20 = point.clone() - &pow8;

    // Fetch mask variables.
    let column0_row0 = mask_values[0].clone();
    let column0_row1 = mask_values[1].clone();
    let column0_row2 = mask_values[2].clone();
    let column0_row3 = mask_values[3].clone();
    let column0_row4 = mask_values[4].clone();
    let column0_row5 = mask_values[5].clone();
    let column0_row6 = mask_values[6].clone();
    let column0_row7 = mask_values[7].clone();
    let column0_row8 = mask_values[8].clone();
    let column0_row9 = mask_values[9].clone();
    let column0_row10 = mask_values[10].clone();
    let column0_row11 = mask_values[11].clone();
    let column0_row12 = mask_values[12].clone();
    let column0_row13 = mask_values[13].clone();
    let column0_row14 = mask_values[14].clone();
    let column0_row15 = mask_values[15].clone();
    let column1_row0 = mask_values[16].clone();
    let column1_row1 = mask_values[17].clone();
    let column1_row2 = mask_values[18].clone();
    let column1_row4 = mask_values[19].clone();
    let column1_row6 = mask_values[20].clone();
    let column1_row8 = mask_values[21].clone();
    let column1_row10 = mask_values[22].clone();
    let column1_row12 = mask_values[23].clone();
    let column1_row14 = mask_values[24].clone();
    let column1_row16 = mask_values[25].clone();
    let column1_row18 = mask_values[26].clone();
    let column1_row20 = mask_values[27].clone();
    let column1_row22 = mask_values[28].clone();
    let column1_row24 = mask_values[29].clone();
    let column1_row26 = mask_values[30].clone();
    let column1_row28 = mask_values[31].clone();
    let column1_row30 = mask_values[32].clone();
    let column1_row32 = mask_values[33].clone();
    let column1_row33 = mask_values[34].clone();
    let column1_row64 = mask_values[35].clone();
    let column1_row65 = mask_values[36].clone();
    let column1_row88 = mask_values[37].clone();
    let column1_row90 = mask_values[38].clone();
    let column1_row92 = mask_values[39].clone();
    let column1_row94 = mask_values[40].clone();
    let column1_row96 = mask_values[41].clone();
    let column1_row97 = mask_values[42].clone();
    let column1_row120 = mask_values[43].clone();
    let column1_row122 = mask_values[44].clone();
    let column1_row124 = mask_values[45].clone();
    let column1_row126 = mask_values[46].clone();
    let column2_row0 = mask_values[47].clone();
    let column2_row1 = mask_values[48].clone();
    let column3_row0 = mask_values[49].clone();
    let column3_row1 = mask_values[50].clone();
    let column3_row2 = mask_values[51].clone();
    let column3_row3 = mask_values[52].clone();
    let column3_row4 = mask_values[53].clone();
    let column3_row5 = mask_values[54].clone();
    let column3_row8 = mask_values[55].clone();
    let column3_row9 = mask_values[56].clone();
    let column3_row10 = mask_values[57].clone();
    let column3_row11 = mask_values[58].clone();
    let column3_row12 = mask_values[59].clone();
    let column3_row13 = mask_values[60].clone();
    let column3_row16 = mask_values[61].clone();
    let column3_row26 = mask_values[62].clone();
    let column3_row27 = mask_values[63].clone();
    let column3_row42 = mask_values[64].clone();
    let column3_row43 = mask_values[65].clone();
    let column3_row58 = mask_values[66].clone();
    let column3_row74 = mask_values[67].clone();
    let column3_row75 = mask_values[68].clone();
    let column3_row91 = mask_values[69].clone();
    let column3_row122 = mask_values[70].clone();
    let column3_row123 = mask_values[71].clone();
    let column3_row154 = mask_values[72].clone();
    let column3_row202 = mask_values[73].clone();
    let column3_row522 = mask_values[74].clone();
    let column3_row523 = mask_values[75].clone();
    let column3_row1034 = mask_values[76].clone();
    let column3_row1035 = mask_values[77].clone();
    let column3_row2058 = mask_values[78].clone();
    let column4_row0 = mask_values[79].clone();
    let column4_row1 = mask_values[80].clone();
    let column4_row2 = mask_values[81].clone();
    let column4_row3 = mask_values[82].clone();
    let column5_row0 = mask_values[83].clone();
    let column5_row1 = mask_values[84].clone();
    let column5_row2 = mask_values[85].clone();
    let column5_row3 = mask_values[86].clone();
    let column5_row4 = mask_values[87].clone();
    let column5_row5 = mask_values[88].clone();
    let column5_row6 = mask_values[89].clone();
    let column5_row7 = mask_values[90].clone();
    let column5_row8 = mask_values[91].clone();
    let column5_row12 = mask_values[92].clone();
    let column5_row28 = mask_values[93].clone();
    let column5_row44 = mask_values[94].clone();
    let column5_row60 = mask_values[95].clone();
    let column5_row76 = mask_values[96].clone();
    let column5_row92 = mask_values[97].clone();
    let column5_row108 = mask_values[98].clone();
    let column5_row124 = mask_values[99].clone();
    let column5_row1021 = mask_values[100].clone();
    let column5_row1023 = mask_values[101].clone();
    let column5_row1025 = mask_values[102].clone();
    let column5_row1027 = mask_values[103].clone();
    let column5_row2045 = mask_values[104].clone();
    let column6_row0 = mask_values[105].clone();
    let column6_row1 = mask_values[106].clone();
    let column6_row2 = mask_values[107].clone();
    let column6_row3 = mask_values[108].clone();
    let column6_row4 = mask_values[109].clone();
    let column6_row5 = mask_values[110].clone();
    let column6_row7 = mask_values[111].clone();
    let column6_row9 = mask_values[112].clone();
    let column6_row11 = mask_values[113].clone();
    let column6_row13 = mask_values[114].clone();
    let column6_row17 = mask_values[115].clone();
    let column6_row25 = mask_values[116].clone();
    let column6_row768 = mask_values[117].clone();
    let column6_row772 = mask_values[118].clone();
    let column6_row784 = mask_values[119].clone();
    let column6_row788 = mask_values[120].clone();
    let column6_row1004 = mask_values[121].clone();
    let column6_row1008 = mask_values[122].clone();
    let column6_row1022 = mask_values[123].clone();
    let column6_row1024 = mask_values[124].clone();
    let column7_inter1_row0 = mask_values[125].clone();
    let column7_inter1_row1 = mask_values[126].clone();
    let column8_inter1_row0 = mask_values[127].clone();
    let column8_inter1_row1 = mask_values[128].clone();
    let column9_inter1_row0 = mask_values[129].clone();
    let column9_inter1_row1 = mask_values[130].clone();
    let column9_inter1_row2 = mask_values[131].clone();
    let column9_inter1_row5 = mask_values[132].clone();

    // Compute intermediate values.
    let cpu_decode_opcode_range_check_bit_0 =
        column0_row0.clone() - (column0_row1.clone() + &column0_row1);
    let cpu_decode_opcode_range_check_bit_2 =
        column0_row2.clone() - (column0_row3.clone() + &column0_row3);
    let cpu_decode_opcode_range_check_bit_4 =
        column0_row4.clone() - (column0_row5.clone() + &column0_row5);
    let cpu_decode_opcode_range_check_bit_3 =
        column0_row3.clone() - (column0_row4.clone() + &column0_row4);
    let cpu_decode_flag_op1_base_op0_0 = F::one()
        - (cpu_decode_opcode_range_check_bit_2.clone()
            + &cpu_decode_opcode_range_check_bit_4.clone()
            + &cpu_decode_opcode_range_check_bit_3);
    let cpu_decode_opcode_range_check_bit_5 =
        column0_row5.clone() - (column0_row6.clone() + &column0_row6);
    let cpu_decode_opcode_range_check_bit_6 =
        column0_row6.clone() - (column0_row7.clone() + &column0_row7);
    let cpu_decode_opcode_range_check_bit_9 =
        column0_row9.clone() - (column0_row10.clone() + &column0_row10);
    let cpu_decode_flag_res_op1_0 = F::one()
        - (cpu_decode_opcode_range_check_bit_5.clone()
            + &cpu_decode_opcode_range_check_bit_6.clone()
            + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_7 =
        column0_row7.clone() - (column0_row8.clone() + &column0_row8);
    let cpu_decode_opcode_range_check_bit_8 =
        column0_row8.clone() - (column0_row9.clone() + &column0_row9);
    let cpu_decode_flag_pc_update_regular_0 = F::one()
        - (cpu_decode_opcode_range_check_bit_7.clone()
            + &cpu_decode_opcode_range_check_bit_8.clone()
            + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_12 =
        column0_row12.clone() - (column0_row13.clone() + &column0_row13);
    let cpu_decode_opcode_range_check_bit_13 =
        column0_row13.clone() - (column0_row14.clone() + &column0_row14);
    let cpu_decode_fp_update_regular_0 = F::one()
        - (cpu_decode_opcode_range_check_bit_12.clone() + &cpu_decode_opcode_range_check_bit_13);
    let cpu_decode_opcode_range_check_bit_1 = column0_row1 - (column0_row2.clone() + &column0_row2);
    let npc_reg_0 = column3_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one();
    let cpu_decode_opcode_range_check_bit_10 =
        column0_row10 - (column0_row11.clone() + &column0_row11);
    let cpu_decode_opcode_range_check_bit_11 =
        column0_row11 - (column0_row12.clone() + &column0_row12);
    let cpu_decode_opcode_range_check_bit_14 =
        column0_row14 - (column0_row15.clone() + &column0_row15);
    let memory_address_diff_0 = column4_row2.clone() - &column4_row0;
    let range_check16_diff_0 = column5_row6.clone() - &column5_row2;
    let pedersen_hash0_ec_subset_sum_bit_0 =
        column6_row0.clone() - (column6_row4.clone() + &column6_row4);
    let pedersen_hash0_ec_subset_sum_bit_neg_0 =
        F::one().clone() - &pedersen_hash0_ec_subset_sum_bit_0;
    let range_check_builtin_value0_0 = column5_row12;
    let range_check_builtin_value1_0 =
        range_check_builtin_value0_0.clone() * &global_values.offset_size.clone() + &column5_row28;
    let range_check_builtin_value2_0 =
        range_check_builtin_value1_0.clone() * &global_values.offset_size.clone() + &column5_row44;
    let range_check_builtin_value3_0 =
        range_check_builtin_value2_0.clone() * &global_values.offset_size.clone() + &column5_row60;
    let range_check_builtin_value4_0 =
        range_check_builtin_value3_0.clone() * &global_values.offset_size.clone() + &column5_row76;
    let range_check_builtin_value5_0 =
        range_check_builtin_value4_0.clone() * &global_values.offset_size.clone() + &column5_row92;
    let range_check_builtin_value6_0 =
        range_check_builtin_value5_0.clone() * &global_values.offset_size.clone() + &column5_row108;
    let range_check_builtin_value7_0 =
        range_check_builtin_value6_0.clone() * &global_values.offset_size.clone() + &column5_row124;
    let bitwise_sum_var_0_0 = column1_row0.clone()
        + column1_row2.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x2")).clone()
        + column1_row4.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x4")).clone()
        + column1_row6.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x8")).clone()
        + column1_row8.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked("0x10000000000000000")).clone()
        + column1_row10.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked("0x20000000000000000")).clone()
        + column1_row12.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000000")).clone()
        + column1_row14.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked("0x80000000000000000"));
    let bitwise_sum_var_8_0 = column1_row16.clone()
        * &F::from_stark_felt(Felt::from_hex_unchecked(
            "0x100000000000000000000000000000000",
        ))
        .clone()
        + column1_row18.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x200000000000000000000000000000000",
            ))
            .clone()
        + column1_row20.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x400000000000000000000000000000000",
            ))
            .clone()
        + column1_row22.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000",
            ))
            .clone()
        + column1_row24.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x1000000000000000000000000000000000000000000000000",
            ))
            .clone()
        + column1_row26.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x2000000000000000000000000000000000000000000000000",
            ))
            .clone()
        + column1_row28.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x4000000000000000000000000000000000000000000000000",
            ))
            .clone()
        + column1_row30.clone()
            * &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x8000000000000000000000000000000000000000000000000",
            ));

    // Sum constraints.
    let mut total_sum = F::zero();

    // Constraint: cpu/decode/opcode_range_check/bit.
    let mut value = (cpu_decode_opcode_range_check_bit_0.clone()
        * &cpu_decode_opcode_range_check_bit_0.clone()
        - &cpu_decode_opcode_range_check_bit_0)
        .clone()
        * &domain3.field_div(&(domain0));
    total_sum += constraint_coefficients[0].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check/zero.
    value = (column0_row0).field_div(&(domain3));
    total_sum += constraint_coefficients[1].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check_input.
    value = (column3_row1.clone()
        - (((column0_row0.clone() * &global_values.offset_size.clone() + &column5_row4).clone()
            * &global_values.offset_size.clone()
            + &column5_row8)
            .clone()
            * &global_values.offset_size.clone()
            + &column5_row0))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[2].clone() * &value;

    // Constraint: cpu/decode/flag_op1_base_op0_bit.
    value = (cpu_decode_flag_op1_base_op0_0.clone() * &cpu_decode_flag_op1_base_op0_0.clone()
        - &cpu_decode_flag_op1_base_op0_0)
        .field_div(&(domain4));
    total_sum += constraint_coefficients[3].clone() * &value;

    // Constraint: cpu/decode/flag_res_op1_bit.
    value = (cpu_decode_flag_res_op1_0.clone() * cpu_decode_flag_res_op1_0.clone()
        - &cpu_decode_flag_res_op1_0)
        .field_div(&(domain4));
    total_sum += constraint_coefficients[4].clone() * &value;

    // Constraint: cpu/decode/flag_pc_update_regular_bit.
    value = (cpu_decode_flag_pc_update_regular_0.clone()
        * &cpu_decode_flag_pc_update_regular_0.clone()
        - &cpu_decode_flag_pc_update_regular_0)
        .field_div(&(domain4));
    total_sum += constraint_coefficients[5].clone() * &value;

    // Constraint: cpu/decode/fp_update_regular_bit.
    value = (cpu_decode_fp_update_regular_0.clone() * &cpu_decode_fp_update_regular_0.clone()
        - &cpu_decode_fp_update_regular_0)
        .field_div(&(domain4));
    total_sum += constraint_coefficients[6].clone() * &value;

    // Constraint: cpu/operands/mem_dst_addr.
    value = (column3_row8.clone() + &global_values.half_offset_size
        - (cpu_decode_opcode_range_check_bit_0.clone() * &column6_row9
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_0).clone()
                * &column6_row1.clone()
            + &column5_row0))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[7].clone() * &value;

    // Constraint: cpu/operands/mem0_addr.
    value = (column3_row4.clone() + &global_values.half_offset_size
        - (cpu_decode_opcode_range_check_bit_1.clone() * &column6_row9
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_1).clone()
                * &column6_row1.clone()
            + &column5_row8))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[8].clone() * &value;

    // Constraint: cpu/operands/mem1_addr.
    value = (column3_row12.clone() + &global_values.half_offset_size
        - (cpu_decode_opcode_range_check_bit_2.clone() * &column3_row0.clone()
            + cpu_decode_opcode_range_check_bit_4.clone() * &column6_row1.clone()
            + cpu_decode_opcode_range_check_bit_3.clone() * &column6_row9.clone()
            + cpu_decode_flag_op1_base_op0_0.clone() * &column3_row5.clone()
            + &column5_row4))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[9].clone() * &value;

    // Constraint: cpu/operands/ops_mul.
    value = (column6_row5.clone() - column3_row5.clone() * &column3_row13).field_div(&(domain4));
    total_sum += constraint_coefficients[10].clone() * &value;

    // Constraint: cpu/operands/res.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone() * &column6_row13
        - (cpu_decode_opcode_range_check_bit_5 * (column3_row5.clone() + &column3_row13).clone()
            + cpu_decode_opcode_range_check_bit_6.clone() * &column6_row5.clone()
            + cpu_decode_flag_res_op1_0.clone() * &column3_row13))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[11].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp0.
    value = (column6_row3.clone() - cpu_decode_opcode_range_check_bit_9.clone() * &column3_row9)
        .clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[12].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp1.
    value = (column6_row11.clone() - column6_row3.clone() * &column6_row13).clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[13].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_negative.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone()
        * &column3_row16.clone()
        + column6_row3 * (column3_row16.clone() - (column3_row0.clone() + &column3_row13))
        - (cpu_decode_flag_pc_update_regular_0.clone() * &npc_reg_0.clone()
            + cpu_decode_opcode_range_check_bit_7.clone() * &column6_row13.clone()
            + cpu_decode_opcode_range_check_bit_8 * (column3_row0.clone() + &column6_row13)))
        .clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[14].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_positive.
    value = ((column6_row11.clone() - &cpu_decode_opcode_range_check_bit_9)
        * (column3_row16.clone() - &npc_reg_0))
        .clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[15].clone() * &value;

    // Constraint: cpu/update_registers/update_ap/ap_update.
    value = (column6_row17
        - (column6_row1.clone()
            + cpu_decode_opcode_range_check_bit_10.clone() * &column6_row13.clone()
            + &cpu_decode_opcode_range_check_bit_11.clone()
            + cpu_decode_opcode_range_check_bit_12.clone() * &F::two()))
        .clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[16].clone() * &value;

    // Constraint: cpu/update_registers/update_fp/fp_update.
    value = (column6_row25
        - (cpu_decode_fp_update_regular_0.clone() * &column6_row9.clone()
            + cpu_decode_opcode_range_check_bit_13.clone() * &column3_row9.clone()
            + cpu_decode_opcode_range_check_bit_12.clone() * (column6_row1.clone() + &F::two())))
        .clone()
        * &domain14.field_div(&(domain4));
    total_sum += constraint_coefficients[17].clone() * &value;

    // Constraint: cpu/opcodes/call/push_fp.
    value = (cpu_decode_opcode_range_check_bit_12.clone() * (column3_row9.clone() - &column6_row9))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[18].clone() * &value;

    // Constraint: cpu/opcodes/call/push_pc.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column3_row5
            - (column3_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[19].clone() * &value;

    // Constraint: cpu/opcodes/call/off0.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column5_row0.clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[20].clone() * &value;

    // Constraint: cpu/opcodes/call/off1.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column5_row8 - (global_values.half_offset_size.clone() + &F::one())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[21].clone() * &value;

    // Constraint: cpu/opcodes/call/flags.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (cpu_decode_opcode_range_check_bit_12.clone()
            + cpu_decode_opcode_range_check_bit_12.clone()
            + &F::two()
            - (cpu_decode_opcode_range_check_bit_0.clone()
                + cpu_decode_opcode_range_check_bit_1.clone()
                + &F::two().clone()
                + &F::two())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[22].clone() * &value;

    // Constraint: cpu/opcodes/ret/off0.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (column5_row0.clone() + &F::two().clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[23].clone() * &value;

    // Constraint: cpu/opcodes/ret/off2.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (column5_row4.clone() + &F::one().clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[24].clone() * &value;

    // Constraint: cpu/opcodes/ret/flags.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (cpu_decode_opcode_range_check_bit_7.clone()
            + &cpu_decode_opcode_range_check_bit_0.clone()
            + &cpu_decode_opcode_range_check_bit_3.clone()
            + &cpu_decode_flag_res_op1_0.clone()
            - &F::two()
            - &F::two()))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[25].clone() * &value;

    // Constraint: cpu/opcodes/assert_eq/assert_eq.
    value = (cpu_decode_opcode_range_check_bit_14 * (column3_row9.clone() - &column6_row13))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[26].clone() * &value;

    // Constraint: initial_ap.
    value = (column6_row1.clone() - &global_values.initial_ap).field_div(&(domain15));
    total_sum += constraint_coefficients[27].clone() * &value;

    // Constraint: initial_fp.
    value = (column6_row9.clone() - &global_values.initial_ap).field_div(&(domain15));
    total_sum += constraint_coefficients[28].clone() * &value;

    // Constraint: initial_pc.
    value = (column3_row0.clone() - &global_values.initial_pc).field_div(&(domain15));
    total_sum += constraint_coefficients[29].clone() * &value;

    // Constraint: final_ap.
    value = (column6_row1.clone() - &global_values.final_ap).field_div(&(domain14));
    total_sum += constraint_coefficients[30].clone() * &value;

    // Constraint: final_fp.
    value = (column6_row9.clone() - &global_values.initial_ap).field_div(&(domain14));
    total_sum += constraint_coefficients[31].clone() * &value;

    // Constraint: final_pc.
    value = (column3_row0.clone() - &global_values.final_pc).field_div(&(domain14));
    total_sum += constraint_coefficients[32].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/init0.
    value = ((global_values
        .memory_multi_column_perm_perm_interaction_elm
        .clone()
        - (column4_row0.clone()
            + global_values
                .memory_multi_column_perm_hash_interaction_elm0
                .clone()
                * &column4_row1))
        .clone()
        * &column9_inter1_row0.clone()
        + &column3_row0.clone()
        + global_values
            .memory_multi_column_perm_hash_interaction_elm0
            .clone()
            * &column3_row1.clone()
        - &global_values.memory_multi_column_perm_perm_interaction_elm)
        .field_div(&(domain15));
    total_sum += constraint_coefficients[33].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/step0.
    value = ((global_values
        .memory_multi_column_perm_perm_interaction_elm
        .clone()
        - (column4_row2.clone()
            + global_values
                .memory_multi_column_perm_hash_interaction_elm0
                .clone()
                * &column4_row3))
        .clone()
        * &column9_inter1_row2
        - (global_values
            .memory_multi_column_perm_perm_interaction_elm
            .clone()
            - (column3_row2.clone()
                + global_values
                    .memory_multi_column_perm_hash_interaction_elm0
                    .clone()
                    * &column3_row3))
            .clone()
            * &column9_inter1_row0)
        .clone()
        * &domain16.field_div(&(domain1));
    total_sum += constraint_coefficients[34].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/last.
    value = (column9_inter1_row0.clone()
        - &global_values.memory_multi_column_perm_perm_public_memory_prod)
        .field_div(&(domain16));
    total_sum += constraint_coefficients[35].clone() * &value;

    // Constraint: memory/diff_is_bit.
    value = (memory_address_diff_0.clone() * memory_address_diff_0.clone()
        - &memory_address_diff_0)
        .clone()
        * &domain16.field_div(&(domain1));
    total_sum += constraint_coefficients[36].clone() * &value;

    // Constraint: memory/is_func.
    value = ((memory_address_diff_0.clone() - &F::one()) * (column4_row1.clone() - &column4_row3))
        .clone()
        * &domain16.field_div(&(domain1));
    total_sum += constraint_coefficients[37].clone() * &value;

    // Constraint: memory/initial_addr.
    value = (column4_row0.clone() - &F::one()).field_div(&(domain15));
    total_sum += constraint_coefficients[38].clone() * &value;

    // Constraint: public_memory_addr_zero.
    value = (column3_row2).field_div(&(domain4));
    total_sum += constraint_coefficients[39].clone() * &value;

    // Constraint: public_memory_value_zero.
    value = (column3_row3).field_div(&(domain4));
    total_sum += constraint_coefficients[40].clone() * &value;

    // Constraint: range_check16/perm/init0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column5_row2).clone()
        * &column9_inter1_row1.clone()
        + &column5_row0.clone()
        - &global_values.range_check16_perm_interaction_elm)
        .field_div(&(domain15));
    total_sum += constraint_coefficients[41].clone() * &value;

    // Constraint: range_check16/perm/step0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column5_row6).clone()
        * &column9_inter1_row5
        - (global_values.range_check16_perm_interaction_elm.clone() - &column5_row4).clone()
            * &column9_inter1_row1)
        .clone()
        * &domain17.field_div(&(domain2));
    total_sum += constraint_coefficients[42].clone() * &value;

    // Constraint: range_check16/perm/last.
    value = (column9_inter1_row1.clone() - &global_values.range_check16_perm_public_memory_prod)
        .field_div(&(domain17));
    total_sum += constraint_coefficients[43].clone() * &value;

    // Constraint: range_check16/diff_is_bit.
    value = (range_check16_diff_0.clone() * range_check16_diff_0.clone() - &range_check16_diff_0)
        .clone()
        * &domain17.field_div(&(domain2));
    total_sum += constraint_coefficients[44].clone() * &value;

    // Constraint: range_check16/minimum.
    value = (column5_row2.clone() - &global_values.range_check_min).field_div(&(domain15));
    total_sum += constraint_coefficients[45].clone() * &value;

    // Constraint: range_check16/maximum.
    value = (column5_row2.clone() - &global_values.range_check_max).field_div(&(domain17));
    total_sum += constraint_coefficients[46].clone() * &value;

    // Constraint: diluted_check/permutation/init0.
    value = ((global_values
        .diluted_check_permutation_interaction_elm
        .clone()
        - &column2_row0)
        .clone()
        * &column8_inter1_row0.clone()
        + &column1_row0.clone()
        - &global_values.diluted_check_permutation_interaction_elm)
        .field_div(&(domain15));
    total_sum += constraint_coefficients[47].clone() * &value;

    // Constraint: diluted_check/permutation/step0.
    value = ((global_values
        .diluted_check_permutation_interaction_elm
        .clone()
        - &column2_row1)
        .clone()
        * &column8_inter1_row1
        - (global_values
            .diluted_check_permutation_interaction_elm
            .clone()
            - &column1_row1)
            .clone()
            * &column8_inter1_row0)
        .clone()
        * &domain18.field_div(&(domain0));
    total_sum += constraint_coefficients[48].clone() * &value;

    // Constraint: diluted_check/permutation/last.
    value = (column8_inter1_row0.clone()
        - &global_values.diluted_check_permutation_public_memory_prod)
        .field_div(&(domain18));
    total_sum += constraint_coefficients[49].clone() * &value;

    // Constraint: diluted_check/init.
    value = (column7_inter1_row0.clone() - &F::one()).field_div(&(domain15));
    total_sum += constraint_coefficients[50].clone() * &value;

    // Constraint: diluted_check/first_element.
    value = (column2_row0.clone() - &global_values.diluted_check_first_elm).field_div(&(domain15));
    total_sum += constraint_coefficients[51].clone() * &value;

    // Constraint: diluted_check/step.
    value = (column7_inter1_row1
        - (column7_inter1_row0.clone()
            * (F::one().clone()
                + global_values.diluted_check_interaction_z.clone()
                    * (column2_row1.clone() - &column2_row0))
                .clone()
            + global_values.diluted_check_interaction_alpha.clone()
                * (column2_row1.clone() - &column2_row0)
                * (column2_row1.clone() - &column2_row0)))
        .clone()
        * &domain18.field_div(&(domain0));
    total_sum += constraint_coefficients[52].clone() * &value;

    // Constraint: diluted_check/last.
    value = (column7_inter1_row0.clone() - &global_values.diluted_check_final_cum_val)
        .field_div(&(domain18));
    total_sum += constraint_coefficients[53].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column6_row7.clone()
        * (column6_row0.clone() - (column6_row4.clone() + &column6_row4)))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[54].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column6_row7.clone()
        * (column6_row4.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000000000000000000",
            ))
            .clone()
                * &column6_row768))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[55].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column6_row7.clone()
        - column6_row1022.clone() * (column6_row768 - (column6_row772.clone() + &column6_row772)))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[56].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column6_row1022.clone()
        * (column6_row772.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x8")).clone() * &column6_row784))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[57].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column6_row1022.clone()
        - (column6_row1004.clone() - (column6_row1008.clone() + &column6_row1008))
            * (column6_row784 - (column6_row788.clone() + &column6_row788)))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[58].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column6_row1004.clone() - (column6_row1008.clone() + &column6_row1008))
        * (column6_row788.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone()
                * &column6_row1004))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[59].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/booleanity_test.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone()
        * (pedersen_hash0_ec_subset_sum_bit_0.clone() - &F::one()))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[60].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_extraction_end.
    value = (column6_row0).field_div(&(domain11));
    total_sum += constraint_coefficients[61].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/zeros_tail.
    value = (column6_row0).field_div(&(domain10));
    total_sum += constraint_coefficients[62].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/slope.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone()
        * (column5_row3.clone() - &global_values.pedersen_points_y).clone()
        - column6_row2.clone() * (column5_row1.clone() - &global_values.pedersen_points_x))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[63].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/x.
    value = (column6_row2.clone() * &column6_row2.clone()
        - pedersen_hash0_ec_subset_sum_bit_0.clone()
            * (column5_row1.clone() + &global_values.pedersen_points_x.clone() + &column5_row5))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[64].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/y.
    value = (pedersen_hash0_ec_subset_sum_bit_0 * (column5_row3.clone() + &column5_row7).clone()
        - column6_row2 * (column5_row1.clone() - &column5_row5))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[65].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/x.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone()
        * (column5_row5.clone() - &column5_row1))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[66].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/y.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0 * (column5_row7.clone() - &column5_row3))
        .clone()
        * &domain10.field_div(&(domain2));
    total_sum += constraint_coefficients[67].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/x.
    value = (column5_row1025.clone() - &column5_row1021).clone() * &domain12.field_div(&(domain9));
    total_sum += constraint_coefficients[68].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/y.
    value = (column5_row1027.clone() - &column5_row1023).clone() * &domain12.field_div(&(domain9));
    total_sum += constraint_coefficients[69].clone() * &value;

    // Constraint: pedersen/hash0/init/x.
    value = (column5_row1.clone() - &global_values.pedersen_shift_point.x).field_div(&(domain13));
    total_sum += constraint_coefficients[70].clone() * &value;

    // Constraint: pedersen/hash0/init/y.
    value = (column5_row3.clone() - &global_values.pedersen_shift_point.y).field_div(&(domain13));
    total_sum += constraint_coefficients[71].clone() * &value;

    // Constraint: pedersen/input0_value0.
    value = (column3_row11.clone() - &column6_row0).field_div(&(domain13));
    total_sum += constraint_coefficients[72].clone() * &value;

    // Constraint: pedersen/input0_addr.
    value = (column3_row2058
        - (column3_row522.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .clone()
        * &domain19.field_div(&(domain13));
    total_sum += constraint_coefficients[73].clone() * &value;

    // Constraint: pedersen/init_addr.
    value = (column3_row10.clone() - &global_values.initial_pedersen_addr).field_div(&(domain15));
    total_sum += constraint_coefficients[74].clone() * &value;

    // Constraint: pedersen/input1_value0.
    value = (column3_row1035.clone() - &column6_row1024).field_div(&(domain13));
    total_sum += constraint_coefficients[75].clone() * &value;

    // Constraint: pedersen/input1_addr.
    value = (column3_row1034.clone()
        - (column3_row10.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .field_div(&(domain13));
    total_sum += constraint_coefficients[76].clone() * &value;

    // Constraint: pedersen/output_value0.
    value = (column3_row523.clone() - &column5_row2045).field_div(&(domain13));
    total_sum += constraint_coefficients[77].clone() * &value;

    // Constraint: pedersen/output_addr.
    value = (column3_row522
        - (column3_row1034.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .field_div(&(domain13));
    total_sum += constraint_coefficients[78].clone() * &value;

    // Constraint: range_check_builtin/value.
    value = (range_check_builtin_value7_0.clone() - &column3_row75).field_div(&(domain6));
    total_sum += constraint_coefficients[79].clone() * &value;

    // Constraint: range_check_builtin/addr_step.
    value = (column3_row202
        - (column3_row74.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .clone()
        * &domain20.field_div(&(domain6));
    total_sum += constraint_coefficients[80].clone() * &value;

    // Constraint: range_check_builtin/init_addr.
    value =
        (column3_row74.clone() - &global_values.initial_range_check_addr).field_div(&(domain15));
    total_sum += constraint_coefficients[81].clone() * &value;

    // Constraint: bitwise/init_var_pool_addr.
    value = (column3_row26.clone() - &global_values.initial_bitwise_addr).field_div(&(domain15));
    total_sum += constraint_coefficients[82].clone() * &value;

    // Constraint: bitwise/step_var_pool_addr.
    value = (column3_row58
        - (column3_row26.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .clone()
        * &domain7.field_div(&(domain5));
    total_sum += constraint_coefficients[83].clone() * &value;

    // Constraint: bitwise/x_or_y_addr.
    value = (column3_row42.clone()
        - (column3_row122.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .field_div(&(domain6));
    total_sum += constraint_coefficients[84].clone() * &value;

    // Constraint: bitwise/next_var_pool_addr.
    value = (column3_row154
        - (column3_row42.clone() + &F::from_stark_felt(Felt::from_hex_unchecked("0x1"))))
        .clone()
        * &domain20.field_div(&(domain6));
    total_sum += constraint_coefficients[85].clone() * &value;

    // Constraint: bitwise/partition.
    value = (bitwise_sum_var_0_0.clone() + bitwise_sum_var_8_0.clone() - &column3_row27)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[86].clone() * &value;

    // Constraint: bitwise/or_is_and_plus_xor.
    value = (column3_row43 - (column3_row91.clone() + &column3_row123)).field_div(&(domain6));
    total_sum += constraint_coefficients[87].clone() * &value;

    // Constraint: bitwise/addition_is_xor_with_and.
    value = (column1_row0.clone() + &column1_row32
        - (column1_row96.clone() + column1_row64.clone() + &column1_row64))
        .field_div(&(domain8));
    total_sum += constraint_coefficients[88].clone() * &value;

    // Constraint: bitwise/unique_unpacking192.
    value = ((column1_row88.clone() + &column1_row120).clone()
        * &F::from_stark_felt(Felt::from_hex_unchecked("0x10")).clone()
        - &column1_row1)
        .field_div(&(domain6));
    total_sum += constraint_coefficients[89].clone() * &value;

    // Constraint: bitwise/unique_unpacking193.
    value = ((column1_row90.clone() + &column1_row122).clone()
        * &F::from_stark_felt(Felt::from_hex_unchecked("0x10")).clone()
        - &column1_row65)
        .field_div(&(domain6));
    total_sum += constraint_coefficients[90].clone() * &value;

    // Constraint: bitwise/unique_unpacking194.
    value = ((column1_row92.clone() + &column1_row124).clone()
        * &F::from_stark_felt(Felt::from_hex_unchecked("0x10")).clone()
        - &column1_row33)
        .field_div(&(domain6));
    total_sum += constraint_coefficients[91].clone() * &value;

    // Constraint: bitwise/unique_unpacking195.
    value = ((column1_row94.clone() + &column1_row126).clone()
        * &F::from_stark_felt(Felt::from_hex_unchecked("0x100")).clone()
        - &column1_row97)
        .field_div(&(domain6));
    total_sum += constraint_coefficients[92].clone() * &value;

    total_sum
}

pub fn eval_oods_polynomial_inner<F: SimpleField + PoseidonHash, Layout: LayoutTrait<F>>(
    column_values: &[F],
    oods_values: &[F],
    constraint_coefficients: &[F],
    point: &F,
    oods_point: &F,
    trace_generator: &F,
) -> F {
    // Compute powers.
    let pow0 = trace_generator.powers([0_u64]);
    let pow1 = trace_generator.powers([1004_u64]);
    let pow2 = trace_generator.powers([768_u64]);
    let pow3 = trace_generator.powers([522_u64]);
    let pow4 = trace_generator.powers([1_u64]);
    let pow5 = pow3.clone() * &pow4; // pow(trace_generator, 523).
    let pow6 = pow4.clone() * &pow4; // pow(trace_generator, 2).
    let pow7 = pow4.clone() * &pow6; // pow(trace_generator, 3).
    let pow8 = pow4.clone() * &pow7; // pow(trace_generator, 4).
    let pow9 = pow1.clone() * &pow8; // pow(trace_generator, 1008).
    let pow10 = pow2.clone() * &pow8; // pow(trace_generator, 772).
    let pow11 = pow4.clone() * &pow8; // pow(trace_generator, 5).
    let pow12 = pow4.clone() * &pow11; // pow(trace_generator, 6).
    let pow13 = pow4.clone() * &pow12; // pow(trace_generator, 7).
    let pow14 = pow4.clone() * &pow13; // pow(trace_generator, 8).
    let pow15 = pow4.clone() * &pow14; // pow(trace_generator, 9).
    let pow16 = pow4.clone() * &pow15; // pow(trace_generator, 10).
    let pow17 = pow4.clone() * &pow16; // pow(trace_generator, 11).
    let pow18 = pow4.clone() * &pow17; // pow(trace_generator, 12).
    let pow19 = pow4.clone() * &pow18; // pow(trace_generator, 13).
    let pow20 = pow4.clone() * &pow19; // pow(trace_generator, 14).
    let pow21 = pow4.clone() * &pow20; // pow(trace_generator, 15).
    let pow22 = pow4.clone() * &pow21; // pow(trace_generator, 16).
    let pow23 = pow2.clone() * &pow22; // pow(trace_generator, 784).
    let pow24 = pow4.clone() * &pow22; // pow(trace_generator, 17).
    let pow25 = pow1.clone() * &pow24; // pow(trace_generator, 1021).
    let pow26 = pow4.clone() * &pow24; // pow(trace_generator, 18).
    let pow27 = pow1.clone() * &pow26; // pow(trace_generator, 1022).
    let pow28 = pow4.clone() * &pow27; // pow(trace_generator, 1023).
    let pow29 = pow6.clone() * &pow26; // pow(trace_generator, 20).
    let pow30 = pow6.clone() * &pow29; // pow(trace_generator, 22).
    let pow31 = pow6.clone() * &pow30; // pow(trace_generator, 24).
    let pow32 = pow4.clone() * &pow31; // pow(trace_generator, 25).
    let pow33 = pow4.clone() * &pow32; // pow(trace_generator, 26).
    let pow34 = pow1.clone() * &pow29; // pow(trace_generator, 1024).
    let pow35 = pow25.clone() * &pow34; // pow(trace_generator, 2045).
    let pow36 = pow4.clone() * &pow34; // pow(trace_generator, 1025).
    let pow37 = pow6.clone() * &pow36; // pow(trace_generator, 1027).
    let pow38 = pow4.clone() * &pow33; // pow(trace_generator, 27).
    let pow39 = pow4.clone() * &pow38; // pow(trace_generator, 28).
    let pow40 = pow6.clone() * &pow39; // pow(trace_generator, 30).
    let pow41 = pow6.clone() * &pow40; // pow(trace_generator, 32).
    let pow42 = pow4.clone() * &pow41; // pow(trace_generator, 33).
    let pow43 = pow1.clone() * &pow40; // pow(trace_generator, 1034).
    let pow44 = pow4.clone() * &pow43; // pow(trace_generator, 1035).
    let pow45 = pow19.clone() * &pow35; // pow(trace_generator, 2058).
    let pow46 = pow15.clone() * &pow42; // pow(trace_generator, 42).
    let pow47 = pow4.clone() * &pow46; // pow(trace_generator, 43).
    let pow48 = pow4.clone() * &pow47; // pow(trace_generator, 44).
    let pow49 = pow20.clone() * &pow48; // pow(trace_generator, 58).
    let pow50 = pow6.clone() * &pow49; // pow(trace_generator, 60).
    let pow51 = pow2.clone() * &pow29; // pow(trace_generator, 788).
    let pow52 = pow8.clone() * &pow50; // pow(trace_generator, 64).
    let pow53 = pow4.clone() * &pow52; // pow(trace_generator, 65).
    let pow54 = pow15.clone() * &pow53; // pow(trace_generator, 74).
    let pow55 = pow4.clone() * &pow54; // pow(trace_generator, 75).
    let pow56 = pow4.clone() * &pow55; // pow(trace_generator, 76).
    let pow57 = pow18.clone() * &pow56; // pow(trace_generator, 88).
    let pow58 = pow6.clone() * &pow57; // pow(trace_generator, 90).
    let pow59 = pow4.clone() * &pow58; // pow(trace_generator, 91).
    let pow60 = pow4.clone() * &pow59; // pow(trace_generator, 92).
    let pow61 = pow6.clone() * &pow60; // pow(trace_generator, 94).
    let pow62 = pow6.clone() * &pow61; // pow(trace_generator, 96).
    let pow63 = pow4.clone() * &pow62; // pow(trace_generator, 97).
    let pow64 = pow17.clone() * &pow63; // pow(trace_generator, 108).
    let pow65 = pow18.clone() * &pow64; // pow(trace_generator, 120).
    let pow66 = pow6.clone() * &pow65; // pow(trace_generator, 122).
    let pow67 = pow4.clone() * &pow66; // pow(trace_generator, 123).
    let pow68 = pow4.clone() * &pow67; // pow(trace_generator, 124).
    let pow69 = pow6.clone() * &pow68; // pow(trace_generator, 126).
    let pow70 = pow56.clone() * &pow69; // pow(trace_generator, 202).
    let pow71 = pow39.clone() * &pow69; // pow(trace_generator, 154).

    // Fetch columns.
    let column0 = column_values[0].clone();
    let column1 = column_values[1].clone();
    let column2 = column_values[2].clone();
    let column3 = column_values[3].clone();
    let column4 = column_values[4].clone();
    let column5 = column_values[5].clone();
    let column6 = column_values[6].clone();
    let column7 = column_values[7].clone();
    let column8 = column_values[8].clone();
    let column9 = column_values[9].clone();

    // Sum the OODS constraints on the trace polynomials.
    let mut value: F;
    let mut total_sum = F::zero();

    value =
        (column0.clone() - &oods_values[0]).field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[0].clone() * &value;

    value =
        (column0.clone() - &oods_values[1]).field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[1].clone() * &value;

    value =
        (column0.clone() - &oods_values[2]).field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[2].clone() * &value;

    value =
        (column0.clone() - &oods_values[3]).field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[3].clone() * &value;

    value =
        (column0.clone() - &oods_values[4]).field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[4].clone() * &value;

    value = (column0.clone() - &oods_values[5])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[5].clone() * &value;

    value = (column0.clone() - &oods_values[6])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[6].clone() * &value;

    value = (column0.clone() - &oods_values[7])
        .field_div(&(point.clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[7].clone() * &value;

    value = (column0.clone() - &oods_values[8])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[8].clone() * &value;

    value = (column0.clone() - &oods_values[9])
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[9].clone() * &value;

    value = (column0.clone() - &oods_values[10])
        .field_div(&(point.clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[10].clone() * &value;

    value = (column0.clone() - &oods_values[11])
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[11].clone() * &value;

    value = (column0.clone() - &oods_values[12])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[12].clone() * &value;

    value = (column0.clone() - &oods_values[13])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[13].clone() * &value;

    value = (column0.clone() - &oods_values[14])
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[14].clone() * &value;

    value = (column0.clone() - &oods_values[15])
        .field_div(&(point.clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[15].clone() * &value;

    value = (column1.clone() - &oods_values[16])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[16].clone() * &value;

    value = (column1.clone() - &oods_values[17])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[17].clone() * &value;

    value = (column1.clone() - &oods_values[18])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[18].clone() * &value;

    value = (column1.clone() - &oods_values[19])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[19].clone() * &value;

    value = (column1.clone() - &oods_values[20])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[20].clone() * &value;

    value = (column1.clone() - &oods_values[21])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[21].clone() * &value;

    value = (column1.clone() - &oods_values[22])
        .field_div(&(point.clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[22].clone() * &value;

    value = (column1.clone() - &oods_values[23])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[23].clone() * &value;

    value = (column1.clone() - &oods_values[24])
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[24].clone() * &value;

    value = (column1.clone() - &oods_values[25])
        .field_div(&(point.clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[25].clone() * &value;

    value = (column1.clone() - &oods_values[26])
        .field_div(&(point.clone() - pow26.clone() * oods_point));
    total_sum += constraint_coefficients[26].clone() * &value;

    value = (column1.clone() - &oods_values[27])
        .field_div(&(point.clone() - pow29.clone() * oods_point));
    total_sum += constraint_coefficients[27].clone() * &value;

    value = (column1.clone() - &oods_values[28])
        .field_div(&(point.clone() - pow30.clone() * oods_point));
    total_sum += constraint_coefficients[28].clone() * &value;

    value = (column1.clone() - &oods_values[29])
        .field_div(&(point.clone() - pow31.clone() * oods_point));
    total_sum += constraint_coefficients[29].clone() * &value;

    value = (column1.clone() - &oods_values[30])
        .field_div(&(point.clone() - pow33.clone() * oods_point));
    total_sum += constraint_coefficients[30].clone() * &value;

    value = (column1.clone() - &oods_values[31])
        .field_div(&(point.clone() - pow39.clone() * oods_point));
    total_sum += constraint_coefficients[31].clone() * &value;

    value = (column1.clone() - &oods_values[32])
        .field_div(&(point.clone() - pow40.clone() * oods_point));
    total_sum += constraint_coefficients[32].clone() * &value;

    value = (column1.clone() - &oods_values[33])
        .field_div(&(point.clone() - pow41.clone() * oods_point));
    total_sum += constraint_coefficients[33].clone() * &value;

    value = (column1.clone() - &oods_values[34])
        .field_div(&(point.clone() - pow42.clone() * oods_point));
    total_sum += constraint_coefficients[34].clone() * &value;

    value = (column1.clone() - &oods_values[35])
        .field_div(&(point.clone() - pow52.clone() * oods_point));
    total_sum += constraint_coefficients[35].clone() * &value;

    value = (column1.clone() - &oods_values[36])
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[36].clone() * &value;

    value = (column1.clone() - &oods_values[37])
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[37].clone() * &value;

    value = (column1.clone() - &oods_values[38])
        .field_div(&(point.clone() - pow58.clone() * oods_point));
    total_sum += constraint_coefficients[38].clone() * &value;

    value = (column1.clone() - &oods_values[39])
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[39].clone() * &value;

    value = (column1.clone() - &oods_values[40])
        .field_div(&(point.clone() - pow61.clone() * oods_point));
    total_sum += constraint_coefficients[40].clone() * &value;

    value = (column1.clone() - &oods_values[41])
        .field_div(&(point.clone() - pow62.clone() * oods_point));
    total_sum += constraint_coefficients[41].clone() * &value;

    value = (column1.clone() - &oods_values[42])
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[42].clone() * &value;

    value = (column1.clone() - &oods_values[43])
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[43].clone() * &value;

    value = (column1.clone() - &oods_values[44])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[44].clone() * &value;

    value = (column1.clone() - &oods_values[45])
        .field_div(&(point.clone() - pow68.clone() * oods_point));
    total_sum += constraint_coefficients[45].clone() * &value;

    value = (column1.clone() - &oods_values[46])
        .field_div(&(point.clone() - pow69.clone() * oods_point));
    total_sum += constraint_coefficients[46].clone() * &value;

    value = (column2.clone() - &oods_values[47])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[47].clone() * &value;

    value = (column2.clone() - &oods_values[48])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[48].clone() * &value;

    value = (column3.clone() - &oods_values[49])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[49].clone() * &value;

    value = (column3.clone() - &oods_values[50])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[50].clone() * &value;

    value = (column3.clone() - &oods_values[51])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[51].clone() * &value;

    value = (column3.clone() - &oods_values[52])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[52].clone() * &value;

    value = (column3.clone() - &oods_values[53])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[53].clone() * &value;

    value = (column3.clone() - &oods_values[54])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[54].clone() * &value;

    value = (column3.clone() - &oods_values[55])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[55].clone() * &value;

    value = (column3.clone() - &oods_values[56])
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[56].clone() * &value;

    value = (column3.clone() - &oods_values[57])
        .field_div(&(point.clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[57].clone() * &value;

    value = (column3.clone() - &oods_values[58])
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[58].clone() * &value;

    value = (column3.clone() - &oods_values[59])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[59].clone() * &value;

    value = (column3.clone() - &oods_values[60])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[60].clone() * &value;

    value = (column3.clone() - &oods_values[61])
        .field_div(&(point.clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[61].clone() * &value;

    value = (column3.clone() - &oods_values[62])
        .field_div(&(point.clone() - pow33.clone() * oods_point));
    total_sum += constraint_coefficients[62].clone() * &value;

    value = (column3.clone() - &oods_values[63])
        .field_div(&(point.clone() - pow38.clone() * oods_point));
    total_sum += constraint_coefficients[63].clone() * &value;

    value = (column3.clone() - &oods_values[64])
        .field_div(&(point.clone() - pow46.clone() * oods_point));
    total_sum += constraint_coefficients[64].clone() * &value;

    value = (column3.clone() - &oods_values[65])
        .field_div(&(point.clone() - pow47.clone() * oods_point));
    total_sum += constraint_coefficients[65].clone() * &value;

    value = (column3.clone() - &oods_values[66])
        .field_div(&(point.clone() - pow49.clone() * oods_point));
    total_sum += constraint_coefficients[66].clone() * &value;

    value = (column3.clone() - &oods_values[67])
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[67].clone() * &value;

    value = (column3.clone() - &oods_values[68])
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[68].clone() * &value;

    value = (column3.clone() - &oods_values[69])
        .field_div(&(point.clone() - pow59.clone() * oods_point));
    total_sum += constraint_coefficients[69].clone() * &value;

    value = (column3.clone() - &oods_values[70])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[70].clone() * &value;

    value = (column3.clone() - &oods_values[71])
        .field_div(&(point.clone() - pow67.clone() * oods_point));
    total_sum += constraint_coefficients[71].clone() * &value;

    value = (column3.clone() - &oods_values[72])
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[72].clone() * &value;

    value = (column3.clone() - &oods_values[73])
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[73].clone() * &value;

    value = (column3.clone() - &oods_values[74])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[74].clone() * &value;

    value = (column3.clone() - &oods_values[75])
        .field_div(&(point.clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[75].clone() * &value;

    value = (column3.clone() - &oods_values[76])
        .field_div(&(point.clone() - pow43.clone() * oods_point));
    total_sum += constraint_coefficients[76].clone() * &value;

    value = (column3.clone() - &oods_values[77])
        .field_div(&(point.clone() - pow44.clone() * oods_point));
    total_sum += constraint_coefficients[77].clone() * &value;

    value = (column3.clone() - &oods_values[78])
        .field_div(&(point.clone() - pow45.clone() * oods_point));
    total_sum += constraint_coefficients[78].clone() * &value;

    value = (column4.clone() - &oods_values[79])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[79].clone() * &value;

    value = (column4.clone() - &oods_values[80])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[80].clone() * &value;

    value = (column4.clone() - &oods_values[81])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[81].clone() * &value;

    value = (column4.clone() - &oods_values[82])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[82].clone() * &value;

    value = (column5.clone() - &oods_values[83])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[83].clone() * &value;

    value = (column5.clone() - &oods_values[84])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[84].clone() * &value;

    value = (column5.clone() - &oods_values[85])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[85].clone() * &value;

    value = (column5.clone() - &oods_values[86])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[86].clone() * &value;

    value = (column5.clone() - &oods_values[87])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[87].clone() * &value;

    value = (column5.clone() - &oods_values[88])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[88].clone() * &value;

    value = (column5.clone() - &oods_values[89])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[89].clone() * &value;

    value = (column5.clone() - &oods_values[90])
        .field_div(&(point.clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[90].clone() * &value;

    value = (column5.clone() - &oods_values[91])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[91].clone() * &value;

    value = (column5.clone() - &oods_values[92])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[92].clone() * &value;

    value = (column5.clone() - &oods_values[93])
        .field_div(&(point.clone() - pow39.clone() * oods_point));
    total_sum += constraint_coefficients[93].clone() * &value;

    value = (column5.clone() - &oods_values[94])
        .field_div(&(point.clone() - pow48.clone() * oods_point));
    total_sum += constraint_coefficients[94].clone() * &value;

    value = (column5.clone() - &oods_values[95])
        .field_div(&(point.clone() - pow50.clone() * oods_point));
    total_sum += constraint_coefficients[95].clone() * &value;

    value = (column5.clone() - &oods_values[96])
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[96].clone() * &value;

    value = (column5.clone() - &oods_values[97])
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[97].clone() * &value;

    value = (column5.clone() - &oods_values[98])
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[98].clone() * &value;

    value = (column5.clone() - &oods_values[99])
        .field_div(&(point.clone() - pow68.clone() * oods_point));
    total_sum += constraint_coefficients[99].clone() * &value;

    value = (column5.clone() - &oods_values[100])
        .field_div(&(point.clone() - pow25.clone() * oods_point));
    total_sum += constraint_coefficients[100].clone() * &value;

    value = (column5.clone() - &oods_values[101])
        .field_div(&(point.clone() - pow28.clone() * oods_point));
    total_sum += constraint_coefficients[101].clone() * &value;

    value = (column5.clone() - &oods_values[102])
        .field_div(&(point.clone() - pow36.clone() * oods_point));
    total_sum += constraint_coefficients[102].clone() * &value;

    value = (column5.clone() - &oods_values[103])
        .field_div(&(point.clone() - pow37.clone() * oods_point));
    total_sum += constraint_coefficients[103].clone() * &value;

    value = (column5.clone() - &oods_values[104])
        .field_div(&(point.clone() - pow35.clone() * oods_point));
    total_sum += constraint_coefficients[104].clone() * &value;

    value = (column6.clone() - &oods_values[105])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[105].clone() * &value;

    value = (column6.clone() - &oods_values[106])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[106].clone() * &value;

    value = (column6.clone() - &oods_values[107])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[107].clone() * &value;

    value = (column6.clone() - &oods_values[108])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[108].clone() * &value;

    value = (column6.clone() - &oods_values[109])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[109].clone() * &value;

    value = (column6.clone() - &oods_values[110])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[110].clone() * &value;

    value = (column6.clone() - &oods_values[111])
        .field_div(&(point.clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[111].clone() * &value;

    value = (column6.clone() - &oods_values[112])
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[112].clone() * &value;

    value = (column6.clone() - &oods_values[113])
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[113].clone() * &value;

    value = (column6.clone() - &oods_values[114])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[114].clone() * &value;

    value = (column6.clone() - &oods_values[115])
        .field_div(&(point.clone() - pow24.clone() * oods_point));
    total_sum += constraint_coefficients[115].clone() * &value;

    value = (column6.clone() - &oods_values[116])
        .field_div(&(point.clone() - pow32.clone() * oods_point));
    total_sum += constraint_coefficients[116].clone() * &value;

    value = (column6.clone() - &oods_values[117])
        .field_div(&(point.clone() - pow2.clone() * oods_point));
    total_sum += constraint_coefficients[117].clone() * &value;

    value = (column6.clone() - &oods_values[118])
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[118].clone() * &value;

    value = (column6.clone() - &oods_values[119])
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[119].clone() * &value;

    value = (column6.clone() - &oods_values[120])
        .field_div(&(point.clone() - pow51.clone() * oods_point));
    total_sum += constraint_coefficients[120].clone() * &value;

    value = (column6.clone() - &oods_values[121])
        .field_div(&(point.clone() - pow1.clone() * oods_point));
    total_sum += constraint_coefficients[121].clone() * &value;

    value = (column6.clone() - &oods_values[122])
        .field_div(&(point.clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[122].clone() * &value;

    value = (column6.clone() - &oods_values[123])
        .field_div(&(point.clone() - pow27.clone() * oods_point));
    total_sum += constraint_coefficients[123].clone() * &value;

    value = (column6.clone() - &oods_values[124])
        .field_div(&(point.clone() - pow34.clone() * oods_point));
    total_sum += constraint_coefficients[124].clone() * &value;

    value = (column7.clone() - &oods_values[125])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[125].clone() * &value;

    value = (column7.clone() - &oods_values[126])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[126].clone() * &value;

    value = (column8.clone() - &oods_values[127])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[127].clone() * &value;

    value = (column8.clone() - &oods_values[128])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[128].clone() * &value;

    value = (column9.clone() - &oods_values[129])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[129].clone() * &value;

    value = (column9.clone() - &oods_values[130])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[130].clone() * &value;

    value = (column9.clone() - &oods_values[131])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[131].clone() * &value;

    value = (column9.clone() - &oods_values[132])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[132].clone() * &value;

    // Sum the OODS boundary constraints on the composition polynomials.
    let oods_point_to_deg = oods_point.powers([Layout::CONSTRAINT_DEGREE as u64]);

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND]
        .clone()
        - &oods_values[133])
        .field_div(&(point.clone() - &oods_point_to_deg));
    total_sum += constraint_coefficients[133].clone() * &value;

    value = (column_values
        [Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND.clone() + &1]
        .clone()
        - &oods_values[134])
        .field_div(&(point.clone() - oods_point_to_deg));
    total_sum += constraint_coefficients[134].clone() * &value;

    total_sum
}
