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
    let pow0 = point.powers_felt(&global_values.trace_length.rsh(13));
    let pow1 = pow0.clone() * &pow0; // pow(point, (safe_div(global_values.trace_length, 4096))).
    let pow2 = point.powers_felt(&global_values.trace_length.rsh(9));
    let pow3 = pow2.clone() * &pow2; // pow(point, (safe_div(global_values.trace_length, 256))).
    let pow4 = pow3.clone() * &pow3; // pow(point, (safe_div(global_values.trace_length, 128))).
    let pow5 = point.powers_felt(&global_values.trace_length.rsh(5));
    let pow6 = pow5.clone() * &pow5; // pow(point, (safe_div(global_values.trace_length, 16))).
    let pow7 = pow6.clone() * &pow6; // pow(point, (safe_div(global_values.trace_length, 8))).
    let pow8 = point.powers_felt(&global_values.trace_length.rsh(1));
    let pow9 = pow8.clone() * &pow8; // pow(point, global_values.trace_length).
    let pow10 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(8192 as u64)));
    let pow11 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(128 as u64)));
    let pow12 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(1 as u64)));
    let pow13 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(2 as u64)));
    let pow14 = trace_generator
        .powers_felt(&(global_values.trace_length.clone() - &F::from_constant(16 as u64)));
    let pow15 = trace_generator
        .powers_felt(&(F::from_constant(251 as u64).clone() * &global_values.trace_length.rsh(8)));
    let pow16 = trace_generator.powers_felt(&(global_values.trace_length.rsh(1)));
    let pow17 = trace_generator
        .powers_felt(&(F::from_constant(63 as u64).clone() * &global_values.trace_length.rsh(6)));
    let pow18 = trace_generator
        .powers_felt(&(F::from_constant(255 as u64).clone() * &global_values.trace_length.rsh(8)));
    let pow19 = trace_generator
        .powers_felt(&(F::from_constant(15 as u64).clone() * &global_values.trace_length.rsh(4)));

    // Compute domains.
    let domain0 = pow9.clone() - &F::one();
    let domain1 = pow8.clone() - &F::one();
    let domain2 = pow7.clone() - &F::one();
    let domain3 = pow6.clone() - &pow19;
    let domain4 = pow6.clone() - &F::one();
    let domain5 = pow5.clone() - &F::one();
    let domain6 = pow4.clone() - &F::one();
    let domain7 = pow3.clone() - &F::one();
    let domain8 = pow3.clone() - &pow18;
    let domain9 = pow3.clone() - &pow17;
    let domain10 = pow2.clone() - &pow16;
    let domain11 = pow2.clone() - &F::one();
    let domain12 = pow1.clone() - &pow18;
    let domain13 = pow1.clone() - &pow15;
    let domain14 = pow1.clone() - &F::one();
    let domain15 = pow0.clone() - &pow18;
    let domain16 = pow0.clone() - &pow15;
    let domain17 = pow0.clone() - &F::one();
    let domain18 = point.clone() - &pow14;
    let domain19 = point.clone() - &F::one();
    let domain20 = point.clone() - &pow13;
    let domain21 = point.clone() - &pow12;
    let domain22 = point.clone() - &pow11;
    let domain23 = point.clone() - &pow10;

    // Fetch mask variables.
    let column0_row0 = mask_values[0].clone();
    let column0_row1 = mask_values[1].clone();
    let column0_row4 = mask_values[2].clone();
    let column0_row8 = mask_values[3].clone();
    let column0_row12 = mask_values[4].clone();
    let column0_row28 = mask_values[5].clone();
    let column0_row44 = mask_values[6].clone();
    let column0_row60 = mask_values[7].clone();
    let column0_row76 = mask_values[8].clone();
    let column0_row92 = mask_values[9].clone();
    let column0_row108 = mask_values[10].clone();
    let column0_row124 = mask_values[11].clone();
    let column1_row0 = mask_values[12].clone();
    let column1_row1 = mask_values[13].clone();
    let column1_row2 = mask_values[14].clone();
    let column1_row3 = mask_values[15].clone();
    let column1_row4 = mask_values[16].clone();
    let column1_row5 = mask_values[17].clone();
    let column1_row6 = mask_values[18].clone();
    let column1_row7 = mask_values[19].clone();
    let column1_row8 = mask_values[20].clone();
    let column1_row9 = mask_values[21].clone();
    let column1_row10 = mask_values[22].clone();
    let column1_row11 = mask_values[23].clone();
    let column1_row12 = mask_values[24].clone();
    let column1_row13 = mask_values[25].clone();
    let column1_row14 = mask_values[26].clone();
    let column1_row15 = mask_values[27].clone();
    let column2_row0 = mask_values[28].clone();
    let column2_row1 = mask_values[29].clone();
    let column3_row0 = mask_values[30].clone();
    let column3_row1 = mask_values[31].clone();
    let column3_row255 = mask_values[32].clone();
    let column3_row256 = mask_values[33].clone();
    let column3_row511 = mask_values[34].clone();
    let column4_row0 = mask_values[35].clone();
    let column4_row1 = mask_values[36].clone();
    let column4_row255 = mask_values[37].clone();
    let column4_row256 = mask_values[38].clone();
    let column5_row0 = mask_values[39].clone();
    let column5_row1 = mask_values[40].clone();
    let column5_row192 = mask_values[41].clone();
    let column5_row193 = mask_values[42].clone();
    let column5_row196 = mask_values[43].clone();
    let column5_row197 = mask_values[44].clone();
    let column5_row251 = mask_values[45].clone();
    let column5_row252 = mask_values[46].clone();
    let column5_row256 = mask_values[47].clone();
    let column6_row0 = mask_values[48].clone();
    let column6_row1 = mask_values[49].clone();
    let column6_row255 = mask_values[50].clone();
    let column6_row256 = mask_values[51].clone();
    let column6_row511 = mask_values[52].clone();
    let column7_row0 = mask_values[53].clone();
    let column7_row1 = mask_values[54].clone();
    let column7_row255 = mask_values[55].clone();
    let column7_row256 = mask_values[56].clone();
    let column8_row0 = mask_values[57].clone();
    let column8_row1 = mask_values[58].clone();
    let column8_row192 = mask_values[59].clone();
    let column8_row193 = mask_values[60].clone();
    let column8_row196 = mask_values[61].clone();
    let column8_row197 = mask_values[62].clone();
    let column8_row251 = mask_values[63].clone();
    let column8_row252 = mask_values[64].clone();
    let column8_row256 = mask_values[65].clone();
    let column9_row0 = mask_values[66].clone();
    let column9_row1 = mask_values[67].clone();
    let column9_row255 = mask_values[68].clone();
    let column9_row256 = mask_values[69].clone();
    let column9_row511 = mask_values[70].clone();
    let column10_row0 = mask_values[71].clone();
    let column10_row1 = mask_values[72].clone();
    let column10_row255 = mask_values[73].clone();
    let column10_row256 = mask_values[74].clone();
    let column11_row0 = mask_values[75].clone();
    let column11_row1 = mask_values[76].clone();
    let column11_row192 = mask_values[77].clone();
    let column11_row193 = mask_values[78].clone();
    let column11_row196 = mask_values[79].clone();
    let column11_row197 = mask_values[80].clone();
    let column11_row251 = mask_values[81].clone();
    let column11_row252 = mask_values[82].clone();
    let column11_row256 = mask_values[83].clone();
    let column12_row0 = mask_values[84].clone();
    let column12_row1 = mask_values[85].clone();
    let column12_row255 = mask_values[86].clone();
    let column12_row256 = mask_values[87].clone();
    let column12_row511 = mask_values[88].clone();
    let column13_row0 = mask_values[89].clone();
    let column13_row1 = mask_values[90].clone();
    let column13_row255 = mask_values[91].clone();
    let column13_row256 = mask_values[92].clone();
    let column14_row0 = mask_values[93].clone();
    let column14_row1 = mask_values[94].clone();
    let column14_row192 = mask_values[95].clone();
    let column14_row193 = mask_values[96].clone();
    let column14_row196 = mask_values[97].clone();
    let column14_row197 = mask_values[98].clone();
    let column14_row251 = mask_values[99].clone();
    let column14_row252 = mask_values[100].clone();
    let column14_row256 = mask_values[101].clone();
    let column15_row0 = mask_values[102].clone();
    let column15_row255 = mask_values[103].clone();
    let column16_row0 = mask_values[104].clone();
    let column16_row255 = mask_values[105].clone();
    let column17_row0 = mask_values[106].clone();
    let column17_row255 = mask_values[107].clone();
    let column18_row0 = mask_values[108].clone();
    let column18_row255 = mask_values[109].clone();
    let column19_row0 = mask_values[110].clone();
    let column19_row1 = mask_values[111].clone();
    let column19_row2 = mask_values[112].clone();
    let column19_row3 = mask_values[113].clone();
    let column19_row4 = mask_values[114].clone();
    let column19_row5 = mask_values[115].clone();
    let column19_row6 = mask_values[116].clone();
    let column19_row7 = mask_values[117].clone();
    let column19_row8 = mask_values[118].clone();
    let column19_row9 = mask_values[119].clone();
    let column19_row12 = mask_values[120].clone();
    let column19_row13 = mask_values[121].clone();
    let column19_row16 = mask_values[122].clone();
    let column19_row22 = mask_values[123].clone();
    let column19_row23 = mask_values[124].clone();
    let column19_row38 = mask_values[125].clone();
    let column19_row39 = mask_values[126].clone();
    let column19_row70 = mask_values[127].clone();
    let column19_row71 = mask_values[128].clone();
    let column19_row102 = mask_values[129].clone();
    let column19_row103 = mask_values[130].clone();
    let column19_row134 = mask_values[131].clone();
    let column19_row135 = mask_values[132].clone();
    let column19_row167 = mask_values[133].clone();
    let column19_row199 = mask_values[134].clone();
    let column19_row230 = mask_values[135].clone();
    let column19_row263 = mask_values[136].clone();
    let column19_row295 = mask_values[137].clone();
    let column19_row327 = mask_values[138].clone();
    let column19_row391 = mask_values[139].clone();
    let column19_row423 = mask_values[140].clone();
    let column19_row455 = mask_values[141].clone();
    let column19_row4118 = mask_values[142].clone();
    let column19_row4119 = mask_values[143].clone();
    let column19_row8214 = mask_values[144].clone();
    let column20_row0 = mask_values[145].clone();
    let column20_row1 = mask_values[146].clone();
    let column20_row2 = mask_values[147].clone();
    let column20_row3 = mask_values[148].clone();
    let column21_row0 = mask_values[149].clone();
    let column21_row1 = mask_values[150].clone();
    let column21_row2 = mask_values[151].clone();
    let column21_row3 = mask_values[152].clone();
    let column21_row4 = mask_values[153].clone();
    let column21_row5 = mask_values[154].clone();
    let column21_row6 = mask_values[155].clone();
    let column21_row7 = mask_values[156].clone();
    let column21_row8 = mask_values[157].clone();
    let column21_row9 = mask_values[158].clone();
    let column21_row10 = mask_values[159].clone();
    let column21_row11 = mask_values[160].clone();
    let column21_row12 = mask_values[161].clone();
    let column21_row13 = mask_values[162].clone();
    let column21_row14 = mask_values[163].clone();
    let column21_row15 = mask_values[164].clone();
    let column21_row16 = mask_values[165].clone();
    let column21_row17 = mask_values[166].clone();
    let column21_row21 = mask_values[167].clone();
    let column21_row22 = mask_values[168].clone();
    let column21_row23 = mask_values[169].clone();
    let column21_row24 = mask_values[170].clone();
    let column21_row25 = mask_values[171].clone();
    let column21_row30 = mask_values[172].clone();
    let column21_row31 = mask_values[173].clone();
    let column21_row39 = mask_values[174].clone();
    let column21_row47 = mask_values[175].clone();
    let column21_row55 = mask_values[176].clone();
    let column21_row4081 = mask_values[177].clone();
    let column21_row4083 = mask_values[178].clone();
    let column21_row4089 = mask_values[179].clone();
    let column21_row4091 = mask_values[180].clone();
    let column21_row4093 = mask_values[181].clone();
    let column21_row4102 = mask_values[182].clone();
    let column21_row4110 = mask_values[183].clone();
    let column21_row8167 = mask_values[184].clone();
    let column21_row8177 = mask_values[185].clone();
    let column21_row8179 = mask_values[186].clone();
    let column21_row8183 = mask_values[187].clone();
    let column21_row8185 = mask_values[188].clone();
    let column21_row8187 = mask_values[189].clone();
    let column21_row8191 = mask_values[190].clone();
    let column22_row0 = mask_values[191].clone();
    let column22_row16 = mask_values[192].clone();
    let column22_row80 = mask_values[193].clone();
    let column22_row144 = mask_values[194].clone();
    let column22_row208 = mask_values[195].clone();
    let column22_row8160 = mask_values[196].clone();
    let column23_inter1_row0 = mask_values[197].clone();
    let column23_inter1_row1 = mask_values[198].clone();
    let column24_inter1_row0 = mask_values[199].clone();
    let column24_inter1_row2 = mask_values[200].clone();

    // Compute intermediate values.
    let cpu_decode_opcode_range_check_bit_0 =
        column1_row0.clone() - &(column1_row1.clone() + &column1_row1);
    let cpu_decode_opcode_range_check_bit_2 =
        column1_row2.clone() - &(column1_row3.clone() + &column1_row3);
    let cpu_decode_opcode_range_check_bit_4 =
        column1_row4.clone() - &(column1_row5.clone() + &column1_row5);
    let cpu_decode_opcode_range_check_bit_3 =
        column1_row3.clone() - &(column1_row4.clone() + &column1_row4);
    let cpu_decode_flag_op1_base_op0_0 = F::one().clone()
        - &(cpu_decode_opcode_range_check_bit_2.clone()
            + &cpu_decode_opcode_range_check_bit_4.clone()
            + &cpu_decode_opcode_range_check_bit_3);
    let cpu_decode_opcode_range_check_bit_5 =
        column1_row5.clone() - &(column1_row6.clone() + &column1_row6);
    let cpu_decode_opcode_range_check_bit_6 =
        column1_row6.clone() - &(column1_row7.clone() + &column1_row7);
    let cpu_decode_opcode_range_check_bit_9 =
        column1_row9.clone() - &(column1_row10.clone() + &column1_row10);
    let cpu_decode_flag_res_op1_0 = F::one().clone()
        - &(cpu_decode_opcode_range_check_bit_5.clone()
            + &cpu_decode_opcode_range_check_bit_6.clone()
            + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_7 =
        column1_row7.clone() - &(column1_row8.clone() + &column1_row8);
    let cpu_decode_opcode_range_check_bit_8 =
        column1_row8.clone() - &(column1_row9.clone() + &column1_row9);
    let cpu_decode_flag_pc_update_regular_0 = F::one().clone()
        - &(cpu_decode_opcode_range_check_bit_7.clone()
            + &cpu_decode_opcode_range_check_bit_8.clone()
            + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_12 =
        column1_row12.clone() - &(column1_row13.clone() + &column1_row13);
    let cpu_decode_opcode_range_check_bit_13 =
        column1_row13.clone() - &(column1_row14.clone() + &column1_row14);
    let cpu_decode_fp_update_regular_0 = F::one().clone()
        - &(cpu_decode_opcode_range_check_bit_12.clone() + &cpu_decode_opcode_range_check_bit_13);
    let cpu_decode_opcode_range_check_bit_1 =
        column1_row1.clone() - &(column1_row2.clone() + &column1_row2);
    let npc_reg_0 = column19_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one();
    let cpu_decode_opcode_range_check_bit_10 =
        column1_row10.clone() - &(column1_row11.clone() + &column1_row11);
    let cpu_decode_opcode_range_check_bit_11 =
        column1_row11.clone() - &(column1_row12.clone() + &column1_row12);
    let cpu_decode_opcode_range_check_bit_14 =
        column1_row14.clone() - &(column1_row15.clone() + &column1_row15);
    let memory_address_diff_0 = column20_row2.clone() - &column20_row0;
    let range_check16_diff_0 = column2_row1.clone() - &column2_row0;
    let pedersen_hash0_ec_subset_sum_bit_0 =
        column5_row0.clone() - &(column5_row1.clone() + &column5_row1);
    let pedersen_hash0_ec_subset_sum_bit_neg_0 =
        F::one().clone() - &pedersen_hash0_ec_subset_sum_bit_0;
    let pedersen_hash1_ec_subset_sum_bit_0 =
        column8_row0.clone() - &(column8_row1.clone() + &column8_row1);
    let pedersen_hash1_ec_subset_sum_bit_neg_0 =
        F::one().clone() - &pedersen_hash1_ec_subset_sum_bit_0;
    let pedersen_hash2_ec_subset_sum_bit_0 =
        column11_row0.clone() - &(column11_row1.clone() + &column11_row1);
    let pedersen_hash2_ec_subset_sum_bit_neg_0 =
        F::one().clone() - &pedersen_hash2_ec_subset_sum_bit_0;
    let pedersen_hash3_ec_subset_sum_bit_0 =
        column14_row0.clone() - &(column14_row1.clone() + &column14_row1);
    let pedersen_hash3_ec_subset_sum_bit_neg_0 =
        F::one().clone() - &pedersen_hash3_ec_subset_sum_bit_0;
    let range_check_builtin_value0_0 = column0_row12;
    let range_check_builtin_value1_0 =
        range_check_builtin_value0_0.clone() * global_values.offset_size.clone() + &column0_row28;
    let range_check_builtin_value2_0 =
        range_check_builtin_value1_0.clone() * global_values.offset_size.clone() + &column0_row44;
    let range_check_builtin_value3_0 =
        range_check_builtin_value2_0.clone() * global_values.offset_size.clone() + &column0_row60;
    let range_check_builtin_value4_0 =
        range_check_builtin_value3_0.clone() * global_values.offset_size.clone() + &column0_row76;
    let range_check_builtin_value5_0 =
        range_check_builtin_value4_0.clone() * global_values.offset_size.clone() + &column0_row92;
    let range_check_builtin_value6_0 =
        range_check_builtin_value5_0.clone() * global_values.offset_size.clone() + &column0_row108;
    let range_check_builtin_value7_0 =
        range_check_builtin_value6_0.clone() * global_values.offset_size.clone() + &column0_row124;
    let ecdsa_signature0_doubling_key_x_squared = column21_row6.clone() * &column21_row6;
    let ecdsa_signature0_exponentiate_generator_bit_0 =
        column21_row15.clone() - &(column21_row47.clone() + &column21_row47);
    let ecdsa_signature0_exponentiate_generator_bit_neg_0 =
        F::one().clone() - &ecdsa_signature0_exponentiate_generator_bit_0;
    let ecdsa_signature0_exponentiate_key_bit_0 =
        column21_row5.clone() - &(column21_row21.clone() + &column21_row21);
    let ecdsa_signature0_exponentiate_key_bit_neg_0 =
        F::one().clone() - &ecdsa_signature0_exponentiate_key_bit_0;

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
    value = (column1_row0).field_div(&(domain3));
    total_sum += constraint_coefficients[1].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check_input.
    value = (column19_row1.clone()
        - &(((column1_row0.clone() * global_values.offset_size.clone() + &column0_row4).clone()
            * &global_values.offset_size.clone()
            + &column0_row8)
            .clone()
            * &global_values.offset_size.clone()
            + &column0_row0))
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
    value = (column19_row8.clone() + &global_values.half_offset_size.clone()
        - &(cpu_decode_opcode_range_check_bit_0.clone() * &column21_row8
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_0).clone()
                * &column21_row0.clone()
            + &column0_row0))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[7].clone() * &value;

    // Constraint: cpu/operands/mem0_addr.
    value = (column19_row4.clone() + &global_values.half_offset_size.clone()
        - &(cpu_decode_opcode_range_check_bit_1.clone() * &column21_row8
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_1).clone()
                * &column21_row0.clone()
            + &column0_row8))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[8].clone() * &value;

    // Constraint: cpu/operands/mem1_addr.
    value = (column19_row12.clone() + &global_values.half_offset_size.clone()
        - &(cpu_decode_opcode_range_check_bit_2.clone() * &column19_row0.clone()
            + cpu_decode_opcode_range_check_bit_4.clone() * &column21_row0.clone()
            + cpu_decode_opcode_range_check_bit_3.clone() * &column21_row8.clone()
            + cpu_decode_flag_op1_base_op0_0.clone() * &column19_row5.clone()
            + &column0_row4))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[9].clone() * &value;

    // Constraint: cpu/operands/ops_mul.
    value = (column21_row4.clone() - column19_row5.clone() * &column19_row13).field_div(&(domain4));
    total_sum += constraint_coefficients[10].clone() * &value;

    // Constraint: cpu/operands/res.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone()
        * &column21_row12.clone()
        - &(cpu_decode_opcode_range_check_bit_5.clone()
            * &(column19_row5.clone() + &column19_row13).clone()
            + cpu_decode_opcode_range_check_bit_6.clone() * &column21_row4.clone()
            + cpu_decode_flag_res_op1_0.clone() * &column19_row13))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[11].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp0.
    value = (column21_row2.clone() - cpu_decode_opcode_range_check_bit_9.clone() * &column19_row9)
        .clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[12].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp1.
    value = (column21_row10.clone() - column21_row2.clone() * &column21_row12).clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[13].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_negative.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone()
        * &column19_row16.clone()
        + column21_row2.clone()
            * &(column19_row16.clone() - &(column19_row0.clone() + &column19_row13)).clone()
        - &(cpu_decode_flag_pc_update_regular_0.clone() * &npc_reg_0.clone()
            + cpu_decode_opcode_range_check_bit_7.clone() * &column21_row12.clone()
            + cpu_decode_opcode_range_check_bit_8.clone()
                * &(column19_row0.clone() + &column21_row12)))
        .clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[14].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_positive.
    value = ((column21_row10.clone() - &cpu_decode_opcode_range_check_bit_9).clone()
        * &(column19_row16.clone() - &npc_reg_0))
        .clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[15].clone() * &value;

    // Constraint: cpu/update_registers/update_ap/ap_update.
    value = (column21_row16.clone()
        - &(column21_row0.clone()
            + cpu_decode_opcode_range_check_bit_10.clone() * &column21_row12.clone()
            + &cpu_decode_opcode_range_check_bit_11.clone()
            + cpu_decode_opcode_range_check_bit_12.clone() * &F::two()))
        .clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[16].clone() * &value;

    // Constraint: cpu/update_registers/update_fp/fp_update.
    value = (column21_row24.clone()
        - &(cpu_decode_fp_update_regular_0.clone() * &column21_row8.clone()
            + cpu_decode_opcode_range_check_bit_13.clone() * &column19_row9.clone()
            + cpu_decode_opcode_range_check_bit_12.clone() * &(column21_row0.clone() + &F::two())))
        .clone()
        * &domain18.field_div(&(domain4));
    total_sum += constraint_coefficients[17].clone() * &value;

    // Constraint: cpu/opcodes/call/push_fp.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * &(column19_row9.clone() - &column21_row8))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[18].clone() * &value;

    // Constraint: cpu/opcodes/call/push_pc.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * &(column19_row5.clone()
            - &(column19_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[19].clone() * &value;

    // Constraint: cpu/opcodes/call/off0.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * &(column0_row0.clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[20].clone() * &value;

    // Constraint: cpu/opcodes/call/off1.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * &(column0_row8.clone() - &(global_values.half_offset_size.clone() + &F::one())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[21].clone() * &value;

    // Constraint: cpu/opcodes/call/flags.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * &(cpu_decode_opcode_range_check_bit_12.clone()
            + cpu_decode_opcode_range_check_bit_12.clone()
            + &F::one().clone()
            + &F::one().clone()
            - &(cpu_decode_opcode_range_check_bit_0.clone()
                + cpu_decode_opcode_range_check_bit_1.clone()
                + &F::two().clone()
                + &F::two())))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[22].clone() * &value;

    // Constraint: cpu/opcodes/ret/off0.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * &(column0_row0.clone() + &F::two().clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[23].clone() * &value;

    // Constraint: cpu/opcodes/ret/off2.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * &(column0_row4.clone() + &F::one().clone() - &global_values.half_offset_size))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[24].clone() * &value;

    // Constraint: cpu/opcodes/ret/flags.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * &(cpu_decode_opcode_range_check_bit_7.clone()
            + &cpu_decode_opcode_range_check_bit_0.clone()
            + &cpu_decode_opcode_range_check_bit_3.clone()
            + &cpu_decode_flag_res_op1_0.clone()
            - &F::two().clone()
            - &F::two()))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[25].clone() * &value;

    // Constraint: cpu/opcodes/assert_eq/assert_eq.
    value = (cpu_decode_opcode_range_check_bit_14.clone()
        * &(column19_row9.clone() - &column21_row12))
        .field_div(&(domain4));
    total_sum += constraint_coefficients[26].clone() * &value;

    // Constraint: initial_ap.
    value = (column21_row0.clone() - &global_values.initial_ap).field_div(&(domain19));
    total_sum += constraint_coefficients[27].clone() * &value;

    // Constraint: initial_fp.
    value = (column21_row8.clone() - &global_values.initial_ap).field_div(&(domain19));
    total_sum += constraint_coefficients[28].clone() * &value;

    // Constraint: initial_pc.
    value = (column19_row0.clone() - &global_values.initial_pc).field_div(&(domain19));
    total_sum += constraint_coefficients[29].clone() * &value;

    // Constraint: final_ap.
    value = (column21_row0.clone() - &global_values.final_ap).field_div(&(domain18));
    total_sum += constraint_coefficients[30].clone() * &value;

    // Constraint: final_fp.
    value = (column21_row8.clone() - &global_values.initial_ap).field_div(&(domain18));
    total_sum += constraint_coefficients[31].clone() * &value;

    // Constraint: final_pc.
    value = (column19_row0.clone() - &global_values.final_pc).field_div(&(domain18));
    total_sum += constraint_coefficients[32].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/init0.
    value = ((global_values
        .memory_multi_column_perm_perm_interaction_elm
        .clone()
        - &(column20_row0.clone()
            + global_values
                .memory_multi_column_perm_hash_interaction_elm0
                .clone()
                * &column20_row1))
        .clone()
        * &column24_inter1_row0.clone()
        + &column19_row0.clone()
        + global_values
            .memory_multi_column_perm_hash_interaction_elm0
            .clone()
            * &column19_row1.clone()
        - &global_values.memory_multi_column_perm_perm_interaction_elm)
        .field_div(&(domain19));
    total_sum += constraint_coefficients[33].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/step0.
    value = ((global_values
        .memory_multi_column_perm_perm_interaction_elm
        .clone()
        - &(column20_row2.clone()
            + global_values
                .memory_multi_column_perm_hash_interaction_elm0
                .clone()
                * &column20_row3))
        .clone()
        * &column24_inter1_row2.clone()
        - (global_values
            .memory_multi_column_perm_perm_interaction_elm
            .clone()
            - &(column19_row2.clone()
                + global_values
                    .memory_multi_column_perm_hash_interaction_elm0
                    .clone()
                    * &column19_row3))
            .clone()
            * &column24_inter1_row0)
        .clone()
        * &domain20.field_div(&(domain1));
    total_sum += constraint_coefficients[34].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/last.
    value = (column24_inter1_row0.clone()
        - &global_values.memory_multi_column_perm_perm_public_memory_prod)
        .field_div(&(domain20));
    total_sum += constraint_coefficients[35].clone() * &value;

    // Constraint: memory/diff_is_bit.
    value = (memory_address_diff_0.clone() * memory_address_diff_0.clone()
        - &memory_address_diff_0)
        .clone()
        * &domain20.field_div(&(domain1));
    total_sum += constraint_coefficients[36].clone() * &value;

    // Constraint: memory/is_func.
    value = ((memory_address_diff_0.clone() - &F::one()).clone()
        * &(column20_row1.clone() - &column20_row3))
        .clone()
        * &domain20.field_div(&(domain1));
    total_sum += constraint_coefficients[37].clone() * &value;

    // Constraint: memory/initial_addr.
    value = (column20_row0.clone() - &F::one()).field_div(&(domain19));
    total_sum += constraint_coefficients[38].clone() * &value;

    // Constraint: public_memory_addr_zero.
    value = (column19_row2).field_div(&(domain2));
    total_sum += constraint_coefficients[39].clone() * &value;

    // Constraint: public_memory_value_zero.
    value = (column19_row3).field_div(&(domain2));
    total_sum += constraint_coefficients[40].clone() * &value;

    // Constraint: range_check16/perm/init0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column2_row0).clone()
        * &column23_inter1_row0.clone()
        + &column0_row0.clone()
        - &global_values.range_check16_perm_interaction_elm)
        .field_div(&(domain19));
    total_sum += constraint_coefficients[41].clone() * &value;

    // Constraint: range_check16/perm/step0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column2_row1).clone()
        * &column23_inter1_row1.clone()
        - (global_values.range_check16_perm_interaction_elm.clone() - &column0_row1).clone()
            * &column23_inter1_row0)
        .clone()
        * &domain21.field_div(&(domain0));
    total_sum += constraint_coefficients[42].clone() * &value;

    // Constraint: range_check16/perm/last.
    value = (column23_inter1_row0.clone() - &global_values.range_check16_perm_public_memory_prod)
        .field_div(&(domain21));
    total_sum += constraint_coefficients[43].clone() * &value;

    // Constraint: range_check16/diff_is_bit.
    value = (range_check16_diff_0.clone() * range_check16_diff_0.clone() - &range_check16_diff_0)
        .clone()
        * &domain21.field_div(&(domain0));
    total_sum += constraint_coefficients[44].clone() * &value;

    // Constraint: range_check16/minimum.
    value = (column2_row0.clone() - &global_values.range_check_min).field_div(&(domain19));
    total_sum += constraint_coefficients[45].clone() * &value;

    // Constraint: range_check16/maximum.
    value = (column2_row0.clone() - &global_values.range_check_max).field_div(&(domain21));
    total_sum += constraint_coefficients[46].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column16_row255.clone()
        * &(column5_row0.clone() - &(column5_row1.clone() + &column5_row1)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[47].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column16_row255.clone()
        * &(column5_row1.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000000000000000000",
            ))
            .clone()
                * &column5_row192))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[48].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column16_row255.clone()
        - column15_row255.clone()
            * &(column5_row192.clone() - &(column5_row193.clone() + &column5_row193)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[49].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column15_row255.clone()
        * &(column5_row193.clone() - F::from_constant(8 as u64) * &column5_row196))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[50].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column15_row255.clone()
        - (column5_row251.clone() - &(column5_row252.clone() + &column5_row252)).clone()
            * &(column5_row196.clone() - &(column5_row197.clone() + &column5_row197)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[51].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column5_row251.clone() - &(column5_row252.clone() + &column5_row252)).clone()
        * &(column5_row197.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")) * &column5_row251))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[52].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/booleanity_test.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone()
        * &(pedersen_hash0_ec_subset_sum_bit_0.clone() - &F::one()))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[53].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_extraction_end.
    value = (column5_row0).field_div(&(domain9));
    total_sum += constraint_coefficients[54].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/zeros_tail.
    value = (column5_row0).field_div(&(domain8));
    total_sum += constraint_coefficients[55].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/slope.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone()
        * &(column4_row0.clone() - &global_values.pedersen_points_y).clone()
        - column15_row0.clone() * &(column3_row0.clone() - &global_values.pedersen_points_x))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[56].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/x.
    value = (column15_row0.clone() * &column15_row0.clone()
        - pedersen_hash0_ec_subset_sum_bit_0.clone()
            * &(column3_row0.clone() + global_values.pedersen_points_x.clone() + &column3_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[57].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/y.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone()
        * &(column4_row0.clone() + &column4_row1).clone()
        - column15_row0.clone() * &(column3_row0.clone() - &column3_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[58].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/x.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone()
        * &(column3_row1.clone() - &column3_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[59].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/y.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone()
        * &(column4_row1.clone() - &column4_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[60].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/x.
    value = (column3_row256.clone() - &column3_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[61].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/y.
    value = (column4_row256.clone() - &column4_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[62].clone() * &value;

    // Constraint: pedersen/hash0/init/x.
    value = (column3_row0.clone() - &global_values.pedersen_shift_point.x).field_div(&(domain11));
    total_sum += constraint_coefficients[63].clone() * &value;

    // Constraint: pedersen/hash0/init/y.
    value = (column4_row0.clone() - &global_values.pedersen_shift_point.y).field_div(&(domain11));
    total_sum += constraint_coefficients[64].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column18_row255.clone()
        * &(column8_row0.clone() - &(column8_row1.clone() + &column8_row1)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[65].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column18_row255.clone()
        * &(column8_row1.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000000000000000000",
            ))
            .clone()
                * &column8_row192))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[66].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column18_row255.clone()
        - column17_row255.clone()
            * &(column8_row192.clone() - &(column8_row193.clone() + &column8_row193)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[67].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column17_row255.clone()
        * &(column8_row193.clone() - F::from_constant(8 as u64) * &column8_row196))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[68].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column17_row255.clone()
        - (column8_row251.clone() - &(column8_row252.clone() + &column8_row252)).clone()
            * &(column8_row196.clone() - &(column8_row197.clone() + &column8_row197)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[69].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column8_row251.clone() - &(column8_row252.clone() + &column8_row252)).clone()
        * &(column8_row197.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")) * &column8_row251))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[70].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/booleanity_test.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone()
        * &(pedersen_hash1_ec_subset_sum_bit_0.clone() - &F::one()))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[71].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_extraction_end.
    value = (column8_row0).field_div(&(domain9));
    total_sum += constraint_coefficients[72].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/zeros_tail.
    value = (column8_row0).field_div(&(domain8));
    total_sum += constraint_coefficients[73].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/slope.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone()
        * &(column7_row0.clone() - &global_values.pedersen_points_y).clone()
        - column16_row0.clone() * &(column6_row0.clone() - &global_values.pedersen_points_x))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[74].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/x.
    value = (column16_row0.clone() * &column16_row0.clone()
        - pedersen_hash1_ec_subset_sum_bit_0.clone()
            * &(column6_row0.clone() + global_values.pedersen_points_x.clone() + &column6_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[75].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/y.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone()
        * &(column7_row0.clone() + &column7_row1).clone()
        - column16_row0.clone() * &(column6_row0.clone() - &column6_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[76].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/copy_point/x.
    value = (pedersen_hash1_ec_subset_sum_bit_neg_0.clone()
        * &(column6_row1.clone() - &column6_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[77].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/copy_point/y.
    value = (pedersen_hash1_ec_subset_sum_bit_neg_0.clone()
        * &(column7_row1.clone() - &column7_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[78].clone() * &value;

    // Constraint: pedersen/hash1/copy_point/x.
    value = (column6_row256.clone() - &column6_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[79].clone() * &value;

    // Constraint: pedersen/hash1/copy_point/y.
    value = (column7_row256.clone() - &column7_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[80].clone() * &value;

    // Constraint: pedersen/hash1/init/x.
    value = (column6_row0.clone() - &global_values.pedersen_shift_point.x).field_div(&(domain11));
    total_sum += constraint_coefficients[81].clone() * &value;

    // Constraint: pedersen/hash1/init/y.
    value = (column7_row0.clone() - &global_values.pedersen_shift_point.y).field_div(&(domain11));
    total_sum += constraint_coefficients[82].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column22_row144.clone()
        * &(column11_row0.clone() - &(column11_row1.clone() + &column11_row1)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[83].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column22_row144.clone()
        * &(column11_row1.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000000000000000000",
            ))
            .clone()
                * &column11_row192))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[84].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column22_row144.clone()
        - column22_row16.clone()
            * &(column11_row192.clone() - &(column11_row193.clone() + &column11_row193)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[85].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column22_row16.clone()
        * &(column11_row193.clone() - F::from_constant(8 as u64) * &column11_row196))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[86].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column22_row16.clone()
        - (column11_row251.clone() - &(column11_row252.clone() + &column11_row252)).clone()
            * &(column11_row196.clone() - &(column11_row197.clone() + &column11_row197)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[87].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column11_row251.clone() - &(column11_row252.clone() + &column11_row252)).clone()
        * &(column11_row197.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")) * &column11_row251))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[88].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/booleanity_test.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone()
        * &(pedersen_hash2_ec_subset_sum_bit_0.clone() - &F::one()))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[89].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_extraction_end.
    value = (column11_row0).field_div(&(domain9));
    total_sum += constraint_coefficients[90].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/zeros_tail.
    value = (column11_row0).field_div(&(domain8));
    total_sum += constraint_coefficients[91].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/slope.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone()
        * &(column10_row0.clone() - &global_values.pedersen_points_y).clone()
        - column17_row0.clone() * &(column9_row0.clone() - &global_values.pedersen_points_x))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[92].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/x.
    value = (column17_row0.clone() * &column17_row0.clone()
        - pedersen_hash2_ec_subset_sum_bit_0.clone()
            * &(column9_row0.clone() + global_values.pedersen_points_x.clone() + &column9_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[93].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/y.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone()
        * &(column10_row0.clone() + &column10_row1).clone()
        - column17_row0.clone() * &(column9_row0.clone() - &column9_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[94].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/copy_point/x.
    value = (pedersen_hash2_ec_subset_sum_bit_neg_0.clone()
        * &(column9_row1.clone() - &column9_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[95].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/copy_point/y.
    value = (pedersen_hash2_ec_subset_sum_bit_neg_0.clone()
        * &(column10_row1.clone() - &column10_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[96].clone() * &value;

    // Constraint: pedersen/hash2/copy_point/x.
    value = (column9_row256.clone() - &column9_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[97].clone() * &value;

    // Constraint: pedersen/hash2/copy_point/y.
    value = (column10_row256.clone() - &column10_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[98].clone() * &value;

    // Constraint: pedersen/hash2/init/x.
    value = (column9_row0.clone() - &global_values.pedersen_shift_point.x).field_div(&(domain11));
    total_sum += constraint_coefficients[99].clone() * &value;

    // Constraint: pedersen/hash2/init/y.
    value = (column10_row0.clone() - &global_values.pedersen_shift_point.y).field_div(&(domain11));
    total_sum += constraint_coefficients[100].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column22_row208.clone()
        * &(column14_row0.clone() - &(column14_row1.clone() + &column14_row1)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[101].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column22_row208.clone()
        * &(column14_row1.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000000000000000000000000000000000000000",
            ))
            .clone()
                * &column14_row192))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[102].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column22_row208.clone()
        - column22_row80.clone()
            * &(column14_row192.clone() - &(column14_row193.clone() + &column14_row193)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[103].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column22_row80.clone()
        * &(column14_row193.clone() - F::from_constant(8 as u64) * &column14_row196))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[104].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column22_row80.clone()
        - (column14_row251.clone() - &(column14_row252.clone() + &column14_row252)).clone()
            * &(column14_row196.clone() - &(column14_row197.clone() + &column14_row197)))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[105].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column14_row251.clone() - &(column14_row252.clone() + &column14_row252)).clone()
        * &(column14_row197.clone()
            - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")) * &column14_row251))
        .field_div(&(domain7));
    total_sum += constraint_coefficients[106].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/booleanity_test.
    value = (pedersen_hash3_ec_subset_sum_bit_0.clone()
        * &(pedersen_hash3_ec_subset_sum_bit_0.clone() - &F::one()))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[107].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_extraction_end.
    value = (column14_row0).field_div(&(domain9));
    total_sum += constraint_coefficients[108].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/zeros_tail.
    value = (column14_row0).field_div(&(domain8));
    total_sum += constraint_coefficients[109].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/slope.
    value = (pedersen_hash3_ec_subset_sum_bit_0.clone()
        * &(column13_row0.clone() - &global_values.pedersen_points_y).clone()
        - column18_row0.clone() * &(column12_row0.clone() - &global_values.pedersen_points_x))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[110].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/x.
    value = (column18_row0.clone() * &column18_row0.clone()
        - pedersen_hash3_ec_subset_sum_bit_0.clone()
            * &(column12_row0.clone() + global_values.pedersen_points_x.clone() + &column12_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[111].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/y.
    value = (pedersen_hash3_ec_subset_sum_bit_0.clone()
        * &(column13_row0.clone() + &column13_row1).clone()
        - column18_row0.clone() * &(column12_row0.clone() - &column12_row1))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[112].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/copy_point/x.
    value = (pedersen_hash3_ec_subset_sum_bit_neg_0.clone()
        * &(column12_row1.clone() - &column12_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[113].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/copy_point/y.
    value = (pedersen_hash3_ec_subset_sum_bit_neg_0.clone()
        * &(column13_row1.clone() - &column13_row0))
        .clone()
        * &domain8.field_div(&(domain0));
    total_sum += constraint_coefficients[114].clone() * &value;

    // Constraint: pedersen/hash3/copy_point/x.
    value = (column12_row256.clone() - &column12_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[115].clone() * &value;

    // Constraint: pedersen/hash3/copy_point/y.
    value = (column13_row256.clone() - &column13_row255).clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[116].clone() * &value;

    // Constraint: pedersen/hash3/init/x.
    value = (column12_row0.clone() - &global_values.pedersen_shift_point.x).field_div(&(domain11));
    total_sum += constraint_coefficients[117].clone() * &value;

    // Constraint: pedersen/hash3/init/y.
    value = (column13_row0.clone() - &global_values.pedersen_shift_point.y).field_div(&(domain11));
    total_sum += constraint_coefficients[118].clone() * &value;

    // Constraint: pedersen/input0_value0.
    value = (column19_row7.clone() - &column5_row0).field_div(&(domain11));
    total_sum += constraint_coefficients[119].clone() * &value;

    // Constraint: pedersen/input0_value1.
    value = (column19_row135.clone() - &column8_row0).field_div(&(domain11));
    total_sum += constraint_coefficients[120].clone() * &value;

    // Constraint: pedersen/input0_value2.
    value = (column19_row263.clone() - &column11_row0).field_div(&(domain11));
    total_sum += constraint_coefficients[121].clone() * &value;

    // Constraint: pedersen/input0_value3.
    value = (column19_row391.clone() - &column14_row0).field_div(&(domain11));
    total_sum += constraint_coefficients[122].clone() * &value;

    // Constraint: pedersen/input0_addr.
    value = (column19_row134.clone() - &(column19_row38.clone() + &F::one())).clone()
        * &domain22.field_div(&(domain6));
    total_sum += constraint_coefficients[123].clone() * &value;

    // Constraint: pedersen/init_addr.
    value = (column19_row6.clone() - &global_values.initial_pedersen_addr).field_div(&(domain19));
    total_sum += constraint_coefficients[124].clone() * &value;

    // Constraint: pedersen/input1_value0.
    value = (column19_row71.clone() - &column5_row256).field_div(&(domain11));
    total_sum += constraint_coefficients[125].clone() * &value;

    // Constraint: pedersen/input1_value1.
    value = (column19_row199.clone() - &column8_row256).field_div(&(domain11));
    total_sum += constraint_coefficients[126].clone() * &value;

    // Constraint: pedersen/input1_value2.
    value = (column19_row327.clone() - &column11_row256).field_div(&(domain11));
    total_sum += constraint_coefficients[127].clone() * &value;

    // Constraint: pedersen/input1_value3.
    value = (column19_row455.clone() - &column14_row256).field_div(&(domain11));
    total_sum += constraint_coefficients[128].clone() * &value;

    // Constraint: pedersen/input1_addr.
    value = (column19_row70.clone() - &(column19_row6.clone() + &F::one())).field_div(&(domain6));
    total_sum += constraint_coefficients[129].clone() * &value;

    // Constraint: pedersen/output_value0.
    value = (column19_row39.clone() - &column3_row511).field_div(&(domain11));
    total_sum += constraint_coefficients[130].clone() * &value;

    // Constraint: pedersen/output_value1.
    value = (column19_row167.clone() - &column6_row511).field_div(&(domain11));
    total_sum += constraint_coefficients[131].clone() * &value;

    // Constraint: pedersen/output_value2.
    value = (column19_row295.clone() - &column9_row511).field_div(&(domain11));
    total_sum += constraint_coefficients[132].clone() * &value;

    // Constraint: pedersen/output_value3.
    value = (column19_row423.clone() - &column12_row511).field_div(&(domain11));
    total_sum += constraint_coefficients[133].clone() * &value;

    // Constraint: pedersen/output_addr.
    value = (column19_row38.clone() - &(column19_row70.clone() + &F::one())).field_div(&(domain6));
    total_sum += constraint_coefficients[134].clone() * &value;

    // Constraint: range_check_builtin/value.
    value = (range_check_builtin_value7_0.clone() - &column19_row103).field_div(&(domain6));
    total_sum += constraint_coefficients[135].clone() * &value;

    // Constraint: range_check_builtin/addr_step.
    value = (column19_row230.clone() - &(column19_row102.clone() + &F::one())).clone()
        * &domain22.field_div(&(domain6));
    total_sum += constraint_coefficients[136].clone() * &value;

    // Constraint: range_check_builtin/init_addr.
    value =
        (column19_row102.clone() - &global_values.initial_range_check_addr).field_div(&(domain19));
    total_sum += constraint_coefficients[137].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/slope.
    value = (ecdsa_signature0_doubling_key_x_squared.clone()
        + &ecdsa_signature0_doubling_key_x_squared.clone()
        + &ecdsa_signature0_doubling_key_x_squared.clone()
        + &global_values.ecdsa_sig_config.alpha.clone()
        - (column21_row14.clone() + &column21_row14).clone() * &column21_row13)
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[138].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/x.
    value = (column21_row13.clone() * column21_row13.clone()
        - &(column21_row6.clone() + column21_row6.clone() + &column21_row22))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[139].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/y.
    value = (column21_row14.clone() + column21_row30.clone()
        - column21_row13.clone() * &(column21_row6.clone() - &column21_row22))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[140].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/booleanity_test.
    value = (ecdsa_signature0_exponentiate_generator_bit_0.clone()
        * &(ecdsa_signature0_exponentiate_generator_bit_0.clone() - &F::one()))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[141].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/bit_extraction_end.
    value = (column21_row15).field_div(&(domain16));
    total_sum += constraint_coefficients[142].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/zeros_tail.
    value = (column21_row15).field_div(&(domain15));
    total_sum += constraint_coefficients[143].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/slope.
    value = (ecdsa_signature0_exponentiate_generator_bit_0.clone()
        * &(column21_row23.clone() - &global_values.ecdsa_generator_points_y).clone()
        - column21_row31.clone()
            * &(column21_row7.clone() - &global_values.ecdsa_generator_points_x))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[144].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/x.
    value = (column21_row31.clone() * &column21_row31.clone()
        - ecdsa_signature0_exponentiate_generator_bit_0.clone()
            * &(column21_row7.clone()
                + global_values.ecdsa_generator_points_x.clone()
                + &column21_row39))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[145].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/y.
    value = (ecdsa_signature0_exponentiate_generator_bit_0.clone()
        * &(column21_row23.clone() + &column21_row55).clone()
        - column21_row31.clone() * &(column21_row7.clone() - &column21_row39))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[146].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv.
    value = (column22_row0.clone()
        * &(column21_row7.clone() - &global_values.ecdsa_generator_points_x).clone()
        - &F::one())
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[147].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/copy_point/x.
    value = (ecdsa_signature0_exponentiate_generator_bit_neg_0.clone()
        * &(column21_row39.clone() - &column21_row7))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[148].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/copy_point/y.
    value = (ecdsa_signature0_exponentiate_generator_bit_neg_0.clone()
        * &(column21_row55.clone() - &column21_row23))
        .clone()
        * &domain15.field_div(&(domain5));
    total_sum += constraint_coefficients[149].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/booleanity_test.
    value = (ecdsa_signature0_exponentiate_key_bit_0.clone()
        * &(ecdsa_signature0_exponentiate_key_bit_0.clone() - &F::one()))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[150].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/bit_extraction_end.
    value = (column21_row5).field_div(&(domain13));
    total_sum += constraint_coefficients[151].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/zeros_tail.
    value = (column21_row5).field_div(&(domain12));
    total_sum += constraint_coefficients[152].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/slope.
    value = (ecdsa_signature0_exponentiate_key_bit_0.clone()
        * &(column21_row9.clone() - &column21_row14).clone()
        - column21_row3.clone() * &(column21_row1.clone() - &column21_row6))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[153].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/x.
    value = (column21_row3.clone() * &column21_row3.clone()
        - ecdsa_signature0_exponentiate_key_bit_0.clone()
            * &(column21_row1.clone() + column21_row6.clone() + &column21_row17))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[154].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/y.
    value = (ecdsa_signature0_exponentiate_key_bit_0.clone()
        * &(column21_row9.clone() + &column21_row25).clone()
        - column21_row3.clone() * &(column21_row1.clone() - &column21_row17))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[155].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/x_diff_inv.
    value = (column21_row11.clone() * &(column21_row1.clone() - &column21_row6).clone()
        - &F::one())
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[156].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/copy_point/x.
    value = (ecdsa_signature0_exponentiate_key_bit_neg_0.clone()
        * &(column21_row17.clone() - &column21_row1))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[157].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/copy_point/y.
    value = (ecdsa_signature0_exponentiate_key_bit_neg_0.clone()
        * &(column21_row25.clone() - &column21_row9))
        .clone()
        * &domain12.field_div(&(domain4));
    total_sum += constraint_coefficients[158].clone() * &value;

    // Constraint: ecdsa/signature0/init_gen/x.
    value = (column21_row7.clone() - &global_values.ecdsa_sig_config.shift_point.x)
        .field_div(&(domain17));
    total_sum += constraint_coefficients[159].clone() * &value;

    // Constraint: ecdsa/signature0/init_gen/y.
    value = (column21_row23.clone() + &global_values.ecdsa_sig_config.shift_point.y)
        .field_div(&(domain17));
    total_sum += constraint_coefficients[160].clone() * &value;

    // Constraint: ecdsa/signature0/init_key/x.
    value = (column21_row1.clone() - &global_values.ecdsa_sig_config.shift_point.x)
        .field_div(&(domain14));
    total_sum += constraint_coefficients[161].clone() * &value;

    // Constraint: ecdsa/signature0/init_key/y.
    value = (column21_row9.clone() - &global_values.ecdsa_sig_config.shift_point.y)
        .field_div(&(domain14));
    total_sum += constraint_coefficients[162].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/slope.
    value = (column21_row8183.clone()
        - &(column21_row4089.clone()
            + column21_row8191.clone() * &(column21_row8167.clone() - &column21_row4081)))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[163].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/x.
    value = (column21_row8191.clone() * &column21_row8191.clone()
        - &(column21_row8167.clone() + column21_row4081.clone() + &column21_row4102))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[164].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/y.
    value = (column21_row8183.clone() + &column21_row4110.clone()
        - column21_row8191.clone() * &(column21_row8167.clone() - &column21_row4102))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[165].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/x_diff_inv.
    value = (column22_row8160.clone() * &(column21_row8167.clone() - &column21_row4081).clone()
        - &F::one())
        .field_div(&(domain17));
    total_sum += constraint_coefficients[166].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/slope.
    value = (column21_row8185.clone() + &global_values.ecdsa_sig_config.shift_point.y.clone()
        - column21_row4083.clone()
            * &(column21_row8177.clone() - &global_values.ecdsa_sig_config.shift_point.x))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[167].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/x.
    value = (column21_row4083.clone() * &column21_row4083.clone()
        - &(column21_row8177.clone()
            + global_values.ecdsa_sig_config.shift_point.x.clone()
            + &column21_row5))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[168].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/x_diff_inv.
    value = (column21_row8179.clone()
        * &(column21_row8177.clone() - &global_values.ecdsa_sig_config.shift_point.x).clone()
        - &F::one())
        .field_div(&(domain17));
    total_sum += constraint_coefficients[169].clone() * &value;

    // Constraint: ecdsa/signature0/z_nonzero.
    value = (column21_row15.clone() * column21_row4091.clone() - &F::one()).field_div(&(domain17));
    total_sum += constraint_coefficients[170].clone() * &value;

    // Constraint: ecdsa/signature0/r_and_w_nonzero.
    value = (column21_row5.clone() * column21_row4093.clone() - &F::one()).field_div(&(domain14));
    total_sum += constraint_coefficients[171].clone() * &value;

    // Constraint: ecdsa/signature0/q_on_curve/x_squared.
    value =
        (column21_row8187.clone() - column21_row6.clone() * &column21_row6).field_div(&(domain17));
    total_sum += constraint_coefficients[172].clone() * &value;

    // Constraint: ecdsa/signature0/q_on_curve/on_curve.
    value = (column21_row14.clone() * &column21_row14.clone()
        - &(column21_row6.clone() * &column21_row8187.clone()
            + global_values.ecdsa_sig_config.alpha.clone() * &column21_row6.clone()
            + &global_values.ecdsa_sig_config.beta))
        .field_div(&(domain17));
    total_sum += constraint_coefficients[173].clone() * &value;

    // Constraint: ecdsa/init_addr.
    value = (column19_row22.clone() - &global_values.initial_ecdsa_addr).field_div(&(domain19));
    total_sum += constraint_coefficients[174].clone() * &value;

    // Constraint: ecdsa/message_addr.
    value =
        (column19_row4118.clone() - &(column19_row22.clone() + &F::one())).field_div(&(domain17));
    total_sum += constraint_coefficients[175].clone() * &value;

    // Constraint: ecdsa/pubkey_addr.
    value = (column19_row8214.clone() - &(column19_row4118.clone() + &F::one())).clone()
        * &domain23.field_div(&(domain17));
    total_sum += constraint_coefficients[176].clone() * &value;

    // Constraint: ecdsa/message_value0.
    value = (column19_row4119.clone() - &column21_row15).field_div(&(domain17));
    total_sum += constraint_coefficients[177].clone() * &value;

    // Constraint: ecdsa/pubkey_value0.
    value = (column19_row23.clone() - &column21_row6).field_div(&(domain17));
    total_sum += constraint_coefficients[178].clone() * &value;

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
    let pow1 = trace_generator.powers([8160_u64]);
    let pow2 = trace_generator.powers([4081_u64]);
    let pow3 = trace_generator.powers([1_u64]);
    let pow4 = pow3.clone() * &pow3; // pow(trace_generator, 2).
    let pow5 = pow2.clone() * &pow4; // pow(trace_generator, 4083).
    let pow6 = pow3.clone() * &pow4; // pow(trace_generator, 3).
    let pow7 = pow3.clone() * &pow6; // pow(trace_generator, 4).
    let pow8 = pow3.clone() * &pow7; // pow(trace_generator, 5).
    let pow9 = pow3.clone() * &pow8; // pow(trace_generator, 6).
    let pow10 = pow3.clone() * &pow9; // pow(trace_generator, 7).
    let pow11 = pow1.clone() * &pow10; // pow(trace_generator, 8167).
    let pow12 = pow3.clone() * &pow10; // pow(trace_generator, 8).
    let pow13 = pow2.clone() * &pow12; // pow(trace_generator, 4089).
    let pow14 = pow3.clone() * &pow12; // pow(trace_generator, 9).
    let pow15 = pow3.clone() * &pow14; // pow(trace_generator, 10).
    let pow16 = pow2.clone() * &pow15; // pow(trace_generator, 4091).
    let pow17 = pow3.clone() * &pow15; // pow(trace_generator, 11).
    let pow18 = pow3.clone() * &pow17; // pow(trace_generator, 12).
    let pow19 = pow3.clone() * &pow18; // pow(trace_generator, 13).
    let pow20 = pow3.clone() * &pow19; // pow(trace_generator, 14).
    let pow21 = pow3.clone() * &pow20; // pow(trace_generator, 15).
    let pow22 = pow2.clone() * &pow18; // pow(trace_generator, 4093).
    let pow23 = pow3.clone() * &pow21; // pow(trace_generator, 16).
    let pow24 = pow3.clone() * &pow23; // pow(trace_generator, 17).
    let pow25 = pow7.clone() * &pow24; // pow(trace_generator, 21).
    let pow26 = pow2.clone() * &pow25; // pow(trace_generator, 4102).
    let pow27 = pow1.clone() * &pow24; // pow(trace_generator, 8177).
    let pow28 = pow4.clone() * &pow27; // pow(trace_generator, 8179).
    let pow29 = pow12.clone() * &pow26; // pow(trace_generator, 4110).
    let pow30 = pow3.clone() * &pow25; // pow(trace_generator, 22).
    let pow31 = pow3.clone() * &pow30; // pow(trace_generator, 23).
    let pow32 = pow3.clone() * &pow31; // pow(trace_generator, 24).
    let pow33 = pow3.clone() * &pow32; // pow(trace_generator, 25).
    let pow34 = pow12.clone() * &pow29; // pow(trace_generator, 4118).
    let pow35 = pow1.clone() * &pow31; // pow(trace_generator, 8183).
    let pow36 = pow1.clone() * &pow33; // pow(trace_generator, 8185).
    let pow37 = pow4.clone() * &pow36; // pow(trace_generator, 8187).
    let pow38 = pow6.clone() * &pow33; // pow(trace_generator, 28).
    let pow39 = pow4.clone() * &pow38; // pow(trace_generator, 30).
    let pow40 = pow3.clone() * &pow39; // pow(trace_generator, 31).
    let pow41 = pow1.clone() * &pow40; // pow(trace_generator, 8191).
    let pow42 = pow10.clone() * &pow40; // pow(trace_generator, 38).
    let pow43 = pow2.clone() * &pow42; // pow(trace_generator, 4119).
    let pow44 = pow3.clone() * &pow42; // pow(trace_generator, 39).
    let pow45 = pow8.clone() * &pow44; // pow(trace_generator, 44).
    let pow46 = pow6.clone() * &pow45; // pow(trace_generator, 47).
    let pow47 = pow12.clone() * &pow46; // pow(trace_generator, 55).
    let pow48 = pow11.clone() * &pow46; // pow(trace_generator, 8214).
    let pow49 = pow8.clone() * &pow47; // pow(trace_generator, 60).
    let pow50 = pow15.clone() * &pow49; // pow(trace_generator, 70).
    let pow51 = pow3.clone() * &pow50; // pow(trace_generator, 71).
    let pow52 = pow8.clone() * &pow51; // pow(trace_generator, 76).
    let pow53 = pow7.clone() * &pow52; // pow(trace_generator, 80).
    let pow54 = pow18.clone() * &pow53; // pow(trace_generator, 92).
    let pow55 = pow15.clone() * &pow54; // pow(trace_generator, 102).
    let pow56 = pow3.clone() * &pow55; // pow(trace_generator, 103).
    let pow57 = pow8.clone() * &pow56; // pow(trace_generator, 108).
    let pow58 = pow23.clone() * &pow57; // pow(trace_generator, 124).
    let pow59 = pow15.clone() * &pow58; // pow(trace_generator, 134).
    let pow60 = pow3.clone() * &pow59; // pow(trace_generator, 135).
    let pow61 = pow14.clone() * &pow60; // pow(trace_generator, 144).
    let pow62 = pow31.clone() * &pow61; // pow(trace_generator, 167).
    let pow63 = pow33.clone() * &pow62; // pow(trace_generator, 192).
    let pow64 = pow3.clone() * &pow63; // pow(trace_generator, 193).
    let pow65 = pow6.clone() * &pow64; // pow(trace_generator, 196).
    let pow66 = pow3.clone() * &pow65; // pow(trace_generator, 197).
    let pow67 = pow4.clone() * &pow66; // pow(trace_generator, 199).
    let pow68 = pow14.clone() * &pow67; // pow(trace_generator, 208).
    let pow69 = pow30.clone() * &pow68; // pow(trace_generator, 230).
    let pow70 = pow25.clone() * &pow69; // pow(trace_generator, 251).
    let pow71 = pow3.clone() * &pow70; // pow(trace_generator, 252).
    let pow72 = pow6.clone() * &pow71; // pow(trace_generator, 255).
    let pow73 = pow3.clone() * &pow72; // pow(trace_generator, 256).
    let pow74 = pow72.clone() * &pow73; // pow(trace_generator, 511).
    let pow75 = pow44.clone() * &pow73; // pow(trace_generator, 295).
    let pow76 = pow10.clone() * &pow73; // pow(trace_generator, 263).
    let pow77 = pow63.clone() * &pow76; // pow(trace_generator, 455).
    let pow78 = pow62.clone() * &pow73; // pow(trace_generator, 423).
    let pow79 = pow60.clone() * &pow73; // pow(trace_generator, 391).
    let pow80 = pow51.clone() * &pow73; // pow(trace_generator, 327).

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
    let column10 = column_values[10].clone();
    let column11 = column_values[11].clone();
    let column12 = column_values[12].clone();
    let column13 = column_values[13].clone();
    let column14 = column_values[14].clone();
    let column15 = column_values[15].clone();
    let column16 = column_values[16].clone();
    let column17 = column_values[17].clone();
    let column18 = column_values[18].clone();
    let column19 = column_values[19].clone();
    let column20 = column_values[20].clone();
    let column21 = column_values[21].clone();
    let column22 = column_values[22].clone();
    let column23 = column_values[23].clone();
    let column24 = column_values[24].clone();

    // Sum the OODS constraints on the trace polynomials.
    let mut total_sum = F::zero();

    let mut value =
        (column0.clone() - &oods_values[0]).field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[0].clone() * &value;

    value =
        (column0.clone() - &oods_values[1]).field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[1].clone() * &value;

    value =
        (column0.clone() - &oods_values[2]).field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[2].clone() * &value;

    value = (column0.clone() - &oods_values[3])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[3].clone() * &value;

    value = (column0.clone() - &oods_values[4])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[4].clone() * &value;

    value = (column0.clone() - &oods_values[5])
        .field_div(&(point.clone() - pow38.clone() * oods_point));
    total_sum += constraint_coefficients[5].clone() * &value;

    value = (column0.clone() - &oods_values[6])
        .field_div(&(point.clone() - pow45.clone() * oods_point));
    total_sum += constraint_coefficients[6].clone() * &value;

    value = (column0.clone() - &oods_values[7])
        .field_div(&(point.clone() - pow49.clone() * oods_point));
    total_sum += constraint_coefficients[7].clone() * &value;

    value = (column0.clone() - &oods_values[8])
        .field_div(&(point.clone() - pow52.clone() * oods_point));
    total_sum += constraint_coefficients[8].clone() * &value;

    value = (column0.clone() - &oods_values[9])
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[9].clone() * &value;

    value = (column0.clone() - &oods_values[10])
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[10].clone() * &value;

    value = (column0.clone() - &oods_values[11])
        .field_div(&(point.clone() - pow58.clone() * oods_point));
    total_sum += constraint_coefficients[11].clone() * &value;

    value = (column1.clone() - &oods_values[12])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[12].clone() * &value;

    value = (column1.clone() - &oods_values[13])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[13].clone() * &value;

    value = (column1.clone() - &oods_values[14])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[14].clone() * &value;

    value = (column1.clone() - &oods_values[15])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[15].clone() * &value;

    value = (column1.clone() - &oods_values[16])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[16].clone() * &value;

    value = (column1.clone() - &oods_values[17])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[17].clone() * &value;

    value = (column1.clone() - &oods_values[18])
        .field_div(&(point.clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[18].clone() * &value;

    value = (column1.clone() - &oods_values[19])
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[19].clone() * &value;

    value = (column1.clone() - &oods_values[20])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[20].clone() * &value;

    value = (column1.clone() - &oods_values[21])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[21].clone() * &value;

    value = (column1.clone() - &oods_values[22])
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[22].clone() * &value;

    value = (column1.clone() - &oods_values[23])
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[23].clone() * &value;

    value = (column1.clone() - &oods_values[24])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[24].clone() * &value;

    value = (column1.clone() - &oods_values[25])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[25].clone() * &value;

    value = (column1.clone() - &oods_values[26])
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[26].clone() * &value;

    value = (column1.clone() - &oods_values[27])
        .field_div(&(point.clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[27].clone() * &value;

    value = (column2.clone() - &oods_values[28])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[28].clone() * &value;

    value = (column2.clone() - &oods_values[29])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[29].clone() * &value;

    value = (column3.clone() - &oods_values[30])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[30].clone() * &value;

    value = (column3.clone() - &oods_values[31])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[31].clone() * &value;

    value = (column3.clone() - &oods_values[32])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[32].clone() * &value;

    value = (column3.clone() - &oods_values[33])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[33].clone() * &value;

    value = (column3.clone() - &oods_values[34])
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[34].clone() * &value;

    value = (column4.clone() - &oods_values[35])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[35].clone() * &value;

    value = (column4.clone() - &oods_values[36])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[36].clone() * &value;

    value = (column4.clone() - &oods_values[37])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[37].clone() * &value;

    value = (column4.clone() - &oods_values[38])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[38].clone() * &value;

    value = (column5.clone() - &oods_values[39])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[39].clone() * &value;

    value = (column5.clone() - &oods_values[40])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[40].clone() * &value;

    value = (column5.clone() - &oods_values[41])
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[41].clone() * &value;

    value = (column5.clone() - &oods_values[42])
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[42].clone() * &value;

    value = (column5.clone() - &oods_values[43])
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[43].clone() * &value;

    value = (column5.clone() - &oods_values[44])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[44].clone() * &value;

    value = (column5.clone() - &oods_values[45])
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[45].clone() * &value;

    value = (column5.clone() - &oods_values[46])
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[46].clone() * &value;

    value = (column5.clone() - &oods_values[47])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[47].clone() * &value;

    value = (column6.clone() - &oods_values[48])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[48].clone() * &value;

    value = (column6.clone() - &oods_values[49])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[49].clone() * &value;

    value = (column6.clone() - &oods_values[50])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[50].clone() * &value;

    value = (column6.clone() - &oods_values[51])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[51].clone() * &value;

    value = (column6.clone() - &oods_values[52])
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[52].clone() * &value;

    value = (column7.clone() - &oods_values[53])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[53].clone() * &value;

    value = (column7.clone() - &oods_values[54])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[54].clone() * &value;

    value = (column7.clone() - &oods_values[55])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[55].clone() * &value;

    value = (column7.clone() - &oods_values[56])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[56].clone() * &value;

    value = (column8.clone() - &oods_values[57])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[57].clone() * &value;

    value = (column8.clone() - &oods_values[58])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[58].clone() * &value;

    value = (column8.clone() - &oods_values[59])
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[59].clone() * &value;

    value = (column8.clone() - &oods_values[60])
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[60].clone() * &value;

    value = (column8.clone() - &oods_values[61])
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[61].clone() * &value;

    value = (column8.clone() - &oods_values[62])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[62].clone() * &value;

    value = (column8.clone() - &oods_values[63])
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[63].clone() * &value;

    value = (column8.clone() - &oods_values[64])
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[64].clone() * &value;

    value = (column8.clone() - &oods_values[65])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[65].clone() * &value;

    value = (column9.clone() - &oods_values[66])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[66].clone() * &value;

    value = (column9.clone() - &oods_values[67])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[67].clone() * &value;

    value = (column9.clone() - &oods_values[68])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[68].clone() * &value;

    value = (column9.clone() - &oods_values[69])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[69].clone() * &value;

    value = (column9.clone() - &oods_values[70])
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[70].clone() * &value;

    value = (column10.clone() - &oods_values[71])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[71].clone() * &value;

    value = (column10.clone() - &oods_values[72])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[72].clone() * &value;

    value = (column10.clone() - &oods_values[73])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[73].clone() * &value;

    value = (column10.clone() - &oods_values[74])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[74].clone() * &value;

    value = (column11.clone() - &oods_values[75])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[75].clone() * &value;

    value = (column11.clone() - &oods_values[76])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[76].clone() * &value;

    value = (column11.clone() - &oods_values[77])
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[77].clone() * &value;

    value = (column11.clone() - &oods_values[78])
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[78].clone() * &value;

    value = (column11.clone() - &oods_values[79])
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[79].clone() * &value;

    value = (column11.clone() - &oods_values[80])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[80].clone() * &value;

    value = (column11.clone() - &oods_values[81])
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[81].clone() * &value;

    value = (column11.clone() - &oods_values[82])
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[82].clone() * &value;

    value = (column11.clone() - &oods_values[83])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[83].clone() * &value;

    value = (column12.clone() - &oods_values[84])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[84].clone() * &value;

    value = (column12.clone() - &oods_values[85])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[85].clone() * &value;

    value = (column12.clone() - &oods_values[86])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[86].clone() * &value;

    value = (column12.clone() - &oods_values[87])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[87].clone() * &value;

    value = (column12.clone() - &oods_values[88])
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[88].clone() * &value;

    value = (column13.clone() - &oods_values[89])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[89].clone() * &value;

    value = (column13.clone() - &oods_values[90])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[90].clone() * &value;

    value = (column13.clone() - &oods_values[91])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[91].clone() * &value;

    value = (column13.clone() - &oods_values[92])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[92].clone() * &value;

    value = (column14.clone() - &oods_values[93])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[93].clone() * &value;

    value = (column14.clone() - &oods_values[94])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[94].clone() * &value;

    value = (column14.clone() - &oods_values[95])
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[95].clone() * &value;

    value = (column14.clone() - &oods_values[96])
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[96].clone() * &value;

    value = (column14.clone() - &oods_values[97])
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[97].clone() * &value;

    value = (column14.clone() - &oods_values[98])
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[98].clone() * &value;

    value = (column14.clone() - &oods_values[99])
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[99].clone() * &value;

    value = (column14.clone() - &oods_values[100])
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[100].clone() * &value;

    value = (column14.clone() - &oods_values[101])
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[101].clone() * &value;

    value = (column15.clone() - &oods_values[102])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[102].clone() * &value;

    value = (column15.clone() - &oods_values[103])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[103].clone() * &value;

    value = (column16.clone() - &oods_values[104])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[104].clone() * &value;

    value = (column16.clone() - &oods_values[105])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[105].clone() * &value;

    value = (column17.clone() - &oods_values[106])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[106].clone() * &value;

    value = (column17.clone() - &oods_values[107])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[107].clone() * &value;

    value = (column18.clone() - &oods_values[108])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[108].clone() * &value;

    value = (column18.clone() - &oods_values[109])
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[109].clone() * &value;

    value = (column19.clone() - &oods_values[110])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[110].clone() * &value;

    value = (column19.clone() - &oods_values[111])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[111].clone() * &value;

    value = (column19.clone() - &oods_values[112])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[112].clone() * &value;

    value = (column19.clone() - &oods_values[113])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[113].clone() * &value;

    value = (column19.clone() - &oods_values[114])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[114].clone() * &value;

    value = (column19.clone() - &oods_values[115])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[115].clone() * &value;

    value = (column19.clone() - &oods_values[116])
        .field_div(&(point.clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[116].clone() * &value;

    value = (column19.clone() - &oods_values[117])
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[117].clone() * &value;

    value = (column19.clone() - &oods_values[118])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[118].clone() * &value;

    value = (column19.clone() - &oods_values[119])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[119].clone() * &value;

    value = (column19.clone() - &oods_values[120])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[120].clone() * &value;

    value = (column19.clone() - &oods_values[121])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[121].clone() * &value;

    value = (column19.clone() - &oods_values[122])
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[122].clone() * &value;

    value = (column19.clone() - &oods_values[123])
        .field_div(&(point.clone() - pow30.clone() * oods_point));
    total_sum += constraint_coefficients[123].clone() * &value;

    value = (column19.clone() - &oods_values[124])
        .field_div(&(point.clone() - pow31.clone() * oods_point));
    total_sum += constraint_coefficients[124].clone() * &value;

    value = (column19.clone() - &oods_values[125])
        .field_div(&(point.clone() - pow42.clone() * oods_point));
    total_sum += constraint_coefficients[125].clone() * &value;

    value = (column19.clone() - &oods_values[126])
        .field_div(&(point.clone() - pow44.clone() * oods_point));
    total_sum += constraint_coefficients[126].clone() * &value;

    value = (column19.clone() - &oods_values[127])
        .field_div(&(point.clone() - pow50.clone() * oods_point));
    total_sum += constraint_coefficients[127].clone() * &value;

    value = (column19.clone() - &oods_values[128])
        .field_div(&(point.clone() - pow51.clone() * oods_point));
    total_sum += constraint_coefficients[128].clone() * &value;

    value = (column19.clone() - &oods_values[129])
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[129].clone() * &value;

    value = (column19.clone() - &oods_values[130])
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[130].clone() * &value;

    value = (column19.clone() - &oods_values[131])
        .field_div(&(point.clone() - pow59.clone() * oods_point));
    total_sum += constraint_coefficients[131].clone() * &value;

    value = (column19.clone() - &oods_values[132])
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[132].clone() * &value;

    value = (column19.clone() - &oods_values[133])
        .field_div(&(point.clone() - pow62.clone() * oods_point));
    total_sum += constraint_coefficients[133].clone() * &value;

    value = (column19.clone() - &oods_values[134])
        .field_div(&(point.clone() - pow67.clone() * oods_point));
    total_sum += constraint_coefficients[134].clone() * &value;

    value = (column19.clone() - &oods_values[135])
        .field_div(&(point.clone() - pow69.clone() * oods_point));
    total_sum += constraint_coefficients[135].clone() * &value;

    value = (column19.clone() - &oods_values[136])
        .field_div(&(point.clone() - pow76.clone() * oods_point));
    total_sum += constraint_coefficients[136].clone() * &value;

    value = (column19.clone() - &oods_values[137])
        .field_div(&(point.clone() - pow75.clone() * oods_point));
    total_sum += constraint_coefficients[137].clone() * &value;

    value = (column19.clone() - &oods_values[138])
        .field_div(&(point.clone() - pow80.clone() * oods_point));
    total_sum += constraint_coefficients[138].clone() * &value;

    value = (column19.clone() - &oods_values[139])
        .field_div(&(point.clone() - pow79.clone() * oods_point));
    total_sum += constraint_coefficients[139].clone() * &value;

    value = (column19.clone() - &oods_values[140])
        .field_div(&(point.clone() - pow78.clone() * oods_point));
    total_sum += constraint_coefficients[140].clone() * &value;

    value = (column19.clone() - &oods_values[141])
        .field_div(&(point.clone() - pow77.clone() * oods_point));
    total_sum += constraint_coefficients[141].clone() * &value;

    value = (column19.clone() - &oods_values[142])
        .field_div(&(point.clone() - pow34.clone() * oods_point));
    total_sum += constraint_coefficients[142].clone() * &value;

    value = (column19.clone() - &oods_values[143])
        .field_div(&(point.clone() - pow43.clone() * oods_point));
    total_sum += constraint_coefficients[143].clone() * &value;

    value = (column19.clone() - &oods_values[144])
        .field_div(&(point.clone() - pow48.clone() * oods_point));
    total_sum += constraint_coefficients[144].clone() * &value;

    value = (column20.clone() - &oods_values[145])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[145].clone() * &value;

    value = (column20.clone() - &oods_values[146])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[146].clone() * &value;

    value = (column20.clone() - &oods_values[147])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[147].clone() * &value;

    value = (column20.clone() - &oods_values[148])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[148].clone() * &value;

    value = (column21.clone() - &oods_values[149])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[149].clone() * &value;

    value = (column21.clone() - &oods_values[150])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[150].clone() * &value;

    value = (column21.clone() - &oods_values[151])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[151].clone() * &value;

    value = (column21.clone() - &oods_values[152])
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[152].clone() * &value;

    value = (column21.clone() - &oods_values[153])
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[153].clone() * &value;

    value = (column21.clone() - &oods_values[154])
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[154].clone() * &value;

    value = (column21.clone() - &oods_values[155])
        .field_div(&(point.clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[155].clone() * &value;

    value = (column21.clone() - &oods_values[156])
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[156].clone() * &value;

    value = (column21.clone() - &oods_values[157])
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[157].clone() * &value;

    value = (column21.clone() - &oods_values[158])
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[158].clone() * &value;

    value = (column21.clone() - &oods_values[159])
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[159].clone() * &value;

    value = (column21.clone() - &oods_values[160])
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[160].clone() * &value;

    value = (column21.clone() - &oods_values[161])
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[161].clone() * &value;

    value = (column21.clone() - &oods_values[162])
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[162].clone() * &value;

    value = (column21.clone() - &oods_values[163])
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[163].clone() * &value;

    value = (column21.clone() - &oods_values[164])
        .field_div(&(point.clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[164].clone() * &value;

    value = (column21.clone() - &oods_values[165])
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[165].clone() * &value;

    value = (column21.clone() - &oods_values[166])
        .field_div(&(point.clone() - pow24.clone() * oods_point));
    total_sum += constraint_coefficients[166].clone() * &value;

    value = (column21.clone() - &oods_values[167])
        .field_div(&(point.clone() - pow25.clone() * oods_point));
    total_sum += constraint_coefficients[167].clone() * &value;

    value = (column21.clone() - &oods_values[168])
        .field_div(&(point.clone() - pow30.clone() * oods_point));
    total_sum += constraint_coefficients[168].clone() * &value;

    value = (column21.clone() - &oods_values[169])
        .field_div(&(point.clone() - pow31.clone() * oods_point));
    total_sum += constraint_coefficients[169].clone() * &value;

    value = (column21.clone() - &oods_values[170])
        .field_div(&(point.clone() - pow32.clone() * oods_point));
    total_sum += constraint_coefficients[170].clone() * &value;

    value = (column21.clone() - &oods_values[171])
        .field_div(&(point.clone() - pow33.clone() * oods_point));
    total_sum += constraint_coefficients[171].clone() * &value;

    value = (column21.clone() - &oods_values[172])
        .field_div(&(point.clone() - pow39.clone() * oods_point));
    total_sum += constraint_coefficients[172].clone() * &value;

    value = (column21.clone() - &oods_values[173])
        .field_div(&(point.clone() - pow40.clone() * oods_point));
    total_sum += constraint_coefficients[173].clone() * &value;

    value = (column21.clone() - &oods_values[174])
        .field_div(&(point.clone() - pow44.clone() * oods_point));
    total_sum += constraint_coefficients[174].clone() * &value;

    value = (column21.clone() - &oods_values[175])
        .field_div(&(point.clone() - pow46.clone() * oods_point));
    total_sum += constraint_coefficients[175].clone() * &value;

    value = (column21.clone() - &oods_values[176])
        .field_div(&(point.clone() - pow47.clone() * oods_point));
    total_sum += constraint_coefficients[176].clone() * &value;

    value = (column21.clone() - &oods_values[177])
        .field_div(&(point.clone() - pow2.clone() * oods_point));
    total_sum += constraint_coefficients[177].clone() * &value;

    value = (column21.clone() - &oods_values[178])
        .field_div(&(point.clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[178].clone() * &value;

    value = (column21.clone() - &oods_values[179])
        .field_div(&(point.clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[179].clone() * &value;

    value = (column21.clone() - &oods_values[180])
        .field_div(&(point.clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[180].clone() * &value;

    value = (column21.clone() - &oods_values[181])
        .field_div(&(point.clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[181].clone() * &value;

    value = (column21.clone() - &oods_values[182])
        .field_div(&(point.clone() - pow26.clone() * oods_point));
    total_sum += constraint_coefficients[182].clone() * &value;

    value = (column21.clone() - &oods_values[183])
        .field_div(&(point.clone() - pow29.clone() * oods_point));
    total_sum += constraint_coefficients[183].clone() * &value;

    value = (column21.clone() - &oods_values[184])
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[184].clone() * &value;

    value = (column21.clone() - &oods_values[185])
        .field_div(&(point.clone() - pow27.clone() * oods_point));
    total_sum += constraint_coefficients[185].clone() * &value;

    value = (column21.clone() - &oods_values[186])
        .field_div(&(point.clone() - pow28.clone() * oods_point));
    total_sum += constraint_coefficients[186].clone() * &value;

    value = (column21.clone() - &oods_values[187])
        .field_div(&(point.clone() - pow35.clone() * oods_point));
    total_sum += constraint_coefficients[187].clone() * &value;

    value = (column21.clone() - &oods_values[188])
        .field_div(&(point.clone() - pow36.clone() * oods_point));
    total_sum += constraint_coefficients[188].clone() * &value;

    value = (column21.clone() - &oods_values[189])
        .field_div(&(point.clone() - pow37.clone() * oods_point));
    total_sum += constraint_coefficients[189].clone() * &value;

    value = (column21.clone() - &oods_values[190])
        .field_div(&(point.clone() - pow41.clone() * oods_point));
    total_sum += constraint_coefficients[190].clone() * &value;

    value = (column22.clone() - &oods_values[191])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[191].clone() * &value;

    value = (column22.clone() - &oods_values[192])
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[192].clone() * &value;

    value = (column22.clone() - &oods_values[193])
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[193].clone() * &value;

    value = (column22.clone() - &oods_values[194])
        .field_div(&(point.clone() - pow61.clone() * oods_point));
    total_sum += constraint_coefficients[194].clone() * &value;

    value = (column22.clone() - &oods_values[195])
        .field_div(&(point.clone() - pow68.clone() * oods_point));
    total_sum += constraint_coefficients[195].clone() * &value;

    value = (column22.clone() - &oods_values[196])
        .field_div(&(point.clone() - pow1.clone() * oods_point));
    total_sum += constraint_coefficients[196].clone() * &value;

    value = (column23.clone() - &oods_values[197])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[197].clone() * &value;

    value = (column23.clone() - &oods_values[198])
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[198].clone() * &value;

    value = (column24.clone() - &oods_values[199])
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[199].clone() * &value;

    value = (column24.clone() - &oods_values[200])
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[200].clone() * &value;

    // Sum the OODS boundary constraints on the composition polynomials.
    let oods_point_to_deg = oods_point.powers([Layout::CONSTRAINT_DEGREE as u64]);

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND]
        .clone()
        - &oods_values[201])
        .field_div(&(point.clone() - &oods_point_to_deg));
    total_sum += constraint_coefficients[201].clone() * &value;

    value = (column_values
        [Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND.clone() + &1]
        .clone()
        - &oods_values[202])
        .field_div(&(point.clone() - &oods_point_to_deg));
    total_sum += constraint_coefficients[202].clone() * &value;

    total_sum
}
