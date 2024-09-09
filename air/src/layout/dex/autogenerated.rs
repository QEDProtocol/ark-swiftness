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
    let pow0 = point.powers_felt(
        &global_values.trace_length.rsh(13),
    );
    let pow1 = pow0.clone() * &pow0; // pow(point, (safe_div(global_values.trace_length, 4096))).
    let pow2 = point.powers_felt(
        &global_values.trace_length.rsh(9),
    );
    let pow3 = pow2.clone() * &pow2; // pow(point, (safe_div(global_values.trace_length, 256))).
    let pow4 = pow3.clone() * &pow3; // pow(point, (safe_div(global_values.trace_length, 128))).
    let pow5 = point.powers_felt(
        &global_values.trace_length.rsh(5),
    );
    let pow6 = pow5.clone() * &pow5; // pow(point, (safe_div(global_values.trace_length, 16))).
    let pow7 = pow6.clone() * &pow6; // pow(point, (safe_div(global_values.trace_length, 8))).
    let pow8 = pow7.clone() * &pow7; // pow(point, (safe_div(global_values.trace_length, 4))).
    let pow9 = pow8.clone() * &pow8; // pow(point, (safe_div(global_values.trace_length, 2))).
    let pow10 = pow9.clone() * &pow9; // pow(point, global_values.trace_length).
    let pow11 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(8192 as u64)));
    let pow12 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(128  as u64)));
    let pow13 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(4    as u64)));
    let pow14 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(2    as u64)));
    let pow15 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(16   as u64)));
    let pow16 = trace_generator.powers_felt(
        &(F::from_constant(251 as u64)
           .clone() * &global_values
                .trace_length
                .rsh(8)),
    );
    let pow17 = trace_generator.powers_felt(
        &(global_values.trace_length.rsh(1)),
    );
    let pow18 = trace_generator.powers_felt(
        &(F::from_constant(63 as u64)
           .clone() * &global_values
                .trace_length
                .rsh(6)),
    );
    let pow19 = trace_generator.powers_felt(
        &(F::from_constant(255 as u64)
           .clone() * &global_values
                .trace_length
                .rsh(8)),
    );
    let pow20 = trace_generator.powers_felt(
        &(F::from_constant(15 as u64)
           .clone() * &global_values
                .trace_length
                .rsh(4)),
    );

    // Compute domains.
    let domain0 = pow10.clone() - &F::one();
    let domain1 = pow9.clone() - &F::one();
    let domain2 = pow8.clone() - &F::one();
    let domain3 = pow7.clone() - &F::one();
    let domain4 = pow6.clone() - &pow20;
    let domain5 = pow6.clone() - &F::one();
    let domain6 = pow5.clone() - &F::one();
    let domain7 = pow4.clone() - &F::one();
    let domain8 = pow3.clone() - &F::one();
    let domain9 = pow3.clone() - &pow19;
    let domain10 = pow3.clone() - &pow18;
    let domain11 = pow2.clone() - &pow17;
    let domain12 = pow2.clone() - &F::one();
    let domain13 = pow1.clone() - &pow19;
    let domain14 = pow1.clone() - &pow16;
    let domain15 = pow1.clone() - &F::one();
    let domain16 = pow0.clone() - &pow19;
    let domain17 = pow0.clone() - &pow16;
    let domain18 = pow0.clone() - &F::one();
    let domain19 = point.clone() - &pow15;
    let domain20 = point.clone() - &F::one();
    let domain21 = point.clone() - &pow14;
    let domain22 = point.clone() - &pow13;
    let domain23 = point.clone() - &pow12;
    let domain24 = point.clone() - &pow11;

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
    let column1_row255 = mask_values[18].clone();
    let column1_row256 = mask_values[19].clone();
    let column1_row511 = mask_values[20].clone();
    let column2_row0 = mask_values[21].clone();
    let column2_row1 = mask_values[22].clone();
    let column2_row255 = mask_values[23].clone();
    let column2_row256 = mask_values[24].clone();
    let column3_row0 = mask_values[25].clone();
    let column3_row1 = mask_values[26].clone();
    let column3_row192 = mask_values[27].clone();
    let column3_row193 = mask_values[28].clone();
    let column3_row196 = mask_values[29].clone();
    let column3_row197 = mask_values[30].clone();
    let column3_row251 = mask_values[31].clone();
    let column3_row252 = mask_values[32].clone();
    let column3_row256 = mask_values[33].clone();
    let column4_row0 = mask_values[34].clone();
    let column4_row1 = mask_values[35].clone();
    let column4_row255 = mask_values[36].clone();
    let column4_row256 = mask_values[37].clone();
    let column4_row511 = mask_values[38].clone();
    let column5_row0 = mask_values[39].clone();
    let column5_row1 = mask_values[40].clone();
    let column5_row255 = mask_values[41].clone();
    let column5_row256 = mask_values[42].clone();
    let column6_row0 = mask_values[43].clone();
    let column6_row1 = mask_values[44].clone();
    let column6_row192 = mask_values[45].clone();
    let column6_row193 = mask_values[46].clone();
    let column6_row196 = mask_values[47].clone();
    let column6_row197 = mask_values[48].clone();
    let column6_row251 = mask_values[49].clone();
    let column6_row252 = mask_values[50].clone();
    let column6_row256 = mask_values[51].clone();
    let column7_row0 = mask_values[52].clone();
    let column7_row1 = mask_values[53].clone();
    let column7_row255 = mask_values[54].clone();
    let column7_row256 = mask_values[55].clone();
    let column7_row511 = mask_values[56].clone();
    let column8_row0 = mask_values[57].clone();
    let column8_row1 = mask_values[58].clone();
    let column8_row255 = mask_values[59].clone();
    let column8_row256 = mask_values[60].clone();
    let column9_row0 = mask_values[61].clone();
    let column9_row1 = mask_values[62].clone();
    let column9_row192 = mask_values[63].clone();
    let column9_row193 = mask_values[64].clone();
    let column9_row196 = mask_values[65].clone();
    let column9_row197 = mask_values[66].clone();
    let column9_row251 = mask_values[67].clone();
    let column9_row252 = mask_values[68].clone();
    let column9_row256 = mask_values[69].clone();
    let column10_row0 = mask_values[70].clone();
    let column10_row1 = mask_values[71].clone();
    let column10_row255 = mask_values[72].clone();
    let column10_row256 = mask_values[73].clone();
    let column10_row511 = mask_values[74].clone();
    let column11_row0 = mask_values[75].clone();
    let column11_row1 = mask_values[76].clone();
    let column11_row255 = mask_values[77].clone();
    let column11_row256 = mask_values[78].clone();
    let column12_row0 = mask_values[79].clone();
    let column12_row1 = mask_values[80].clone();
    let column12_row192 = mask_values[81].clone();
    let column12_row193 = mask_values[82].clone();
    let column12_row196 = mask_values[83].clone();
    let column12_row197 = mask_values[84].clone();
    let column12_row251 = mask_values[85].clone();
    let column12_row252 = mask_values[86].clone();
    let column12_row256 = mask_values[87].clone();
    let column13_row0 = mask_values[88].clone();
    let column13_row255 = mask_values[89].clone();
    let column14_row0 = mask_values[90].clone();
    let column14_row255 = mask_values[91].clone();
    let column15_row0 = mask_values[92].clone();
    let column15_row255 = mask_values[93].clone();
    let column16_row0 = mask_values[94].clone();
    let column16_row255 = mask_values[95].clone();
    let column17_row0 = mask_values[96].clone();
    let column17_row1 = mask_values[97].clone();
    let column17_row2 = mask_values[98].clone();
    let column17_row3 = mask_values[99].clone();
    let column17_row4 = mask_values[100].clone();
    let column17_row5 = mask_values[101].clone();
    let column17_row6 = mask_values[102].clone();
    let column17_row7 = mask_values[103].clone();
    let column17_row8 = mask_values[104].clone();
    let column17_row9 = mask_values[105].clone();
    let column17_row12 = mask_values[106].clone();
    let column17_row13 = mask_values[107].clone();
    let column17_row16 = mask_values[108].clone();
    let column17_row22 = mask_values[109].clone();
    let column17_row23 = mask_values[110].clone();
    let column17_row38 = mask_values[111].clone();
    let column17_row39 = mask_values[112].clone();
    let column17_row70 = mask_values[113].clone();
    let column17_row71 = mask_values[114].clone();
    let column17_row102 = mask_values[115].clone();
    let column17_row103 = mask_values[116].clone();
    let column17_row134 = mask_values[117].clone();
    let column17_row135 = mask_values[118].clone();
    let column17_row167 = mask_values[119].clone();
    let column17_row199 = mask_values[120].clone();
    let column17_row230 = mask_values[121].clone();
    let column17_row263 = mask_values[122].clone();
    let column17_row295 = mask_values[123].clone();
    let column17_row327 = mask_values[124].clone();
    let column17_row391 = mask_values[125].clone();
    let column17_row423 = mask_values[126].clone();
    let column17_row455 = mask_values[127].clone();
    let column17_row4118 = mask_values[128].clone();
    let column17_row4119 = mask_values[129].clone();
    let column17_row8214 = mask_values[130].clone();
    let column18_row0 = mask_values[131].clone();
    let column18_row1 = mask_values[132].clone();
    let column18_row2 = mask_values[133].clone();
    let column18_row3 = mask_values[134].clone();
    let column19_row0 = mask_values[135].clone();
    let column19_row1 = mask_values[136].clone();
    let column19_row2 = mask_values[137].clone();
    let column19_row3 = mask_values[138].clone();
    let column19_row4 = mask_values[139].clone();
    let column19_row5 = mask_values[140].clone();
    let column19_row6 = mask_values[141].clone();
    let column19_row7 = mask_values[142].clone();
    let column19_row8 = mask_values[143].clone();
    let column19_row9 = mask_values[144].clone();
    let column19_row11 = mask_values[145].clone();
    let column19_row12 = mask_values[146].clone();
    let column19_row13 = mask_values[147].clone();
    let column19_row15 = mask_values[148].clone();
    let column19_row17 = mask_values[149].clone();
    let column19_row23 = mask_values[150].clone();
    let column19_row25 = mask_values[151].clone();
    let column19_row28 = mask_values[152].clone();
    let column19_row31 = mask_values[153].clone();
    let column19_row44 = mask_values[154].clone();
    let column19_row60 = mask_values[155].clone();
    let column19_row76 = mask_values[156].clone();
    let column19_row92 = mask_values[157].clone();
    let column19_row108 = mask_values[158].clone();
    let column19_row124 = mask_values[159].clone();
    let column19_row4103 = mask_values[160].clone();
    let column19_row4111 = mask_values[161].clone();
    let column20_row0 = mask_values[162].clone();
    let column20_row1 = mask_values[163].clone();
    let column20_row2 = mask_values[164].clone();
    let column20_row4 = mask_values[165].clone();
    let column20_row6 = mask_values[166].clone();
    let column20_row8 = mask_values[167].clone();
    let column20_row10 = mask_values[168].clone();
    let column20_row12 = mask_values[169].clone();
    let column20_row14 = mask_values[170].clone();
    let column20_row16 = mask_values[171].clone();
    let column20_row17 = mask_values[172].clone();
    let column20_row20 = mask_values[173].clone();
    let column20_row22 = mask_values[174].clone();
    let column20_row24 = mask_values[175].clone();
    let column20_row30 = mask_values[176].clone();
    let column20_row38 = mask_values[177].clone();
    let column20_row46 = mask_values[178].clone();
    let column20_row54 = mask_values[179].clone();
    let column20_row81 = mask_values[180].clone();
    let column20_row145 = mask_values[181].clone();
    let column20_row209 = mask_values[182].clone();
    let column20_row4080 = mask_values[183].clone();
    let column20_row4082 = mask_values[184].clone();
    let column20_row4088 = mask_values[185].clone();
    let column20_row4090 = mask_values[186].clone();
    let column20_row4092 = mask_values[187].clone();
    let column20_row8161 = mask_values[188].clone();
    let column20_row8166 = mask_values[189].clone();
    let column20_row8176 = mask_values[190].clone();
    let column20_row8178 = mask_values[191].clone();
    let column20_row8182 = mask_values[192].clone();
    let column20_row8184 = mask_values[193].clone();
    let column20_row8186 = mask_values[194].clone();
    let column20_row8190 = mask_values[195].clone();
    let column21_inter1_row0 = mask_values[196].clone();
    let column21_inter1_row1 = mask_values[197].clone();
    let column21_inter1_row2 = mask_values[198].clone();
    let column21_inter1_row5 = mask_values[199].clone();

    // Compute intermediate values.
    // Compute intermediate values.
    let cpu_decode_opcode_range_check_bit_0 = column0_row0.clone() - (column0_row1.clone() + &column0_row1);
    let cpu_decode_opcode_range_check_bit_2 = column0_row2.clone() - (column0_row3.clone() + &column0_row3);
    let cpu_decode_opcode_range_check_bit_4 = column0_row4.clone() - (column0_row5.clone() + &column0_row5);
    let cpu_decode_opcode_range_check_bit_3 = column0_row3.clone() - (column0_row4.clone() + &column0_row4);
    let cpu_decode_flag_op1_base_op0_0 = F::one()
       .clone() - (cpu_decode_opcode_range_check_bit_2
           .clone() + &cpu_decode_opcode_range_check_bit_4
           .clone() + cpu_decode_opcode_range_check_bit_3.clone());
    let cpu_decode_opcode_range_check_bit_5 = column0_row5.clone() - (column0_row6.clone() +  &column0_row6);
    let cpu_decode_opcode_range_check_bit_6 = column0_row6.clone() - (column0_row7.clone() +  &column0_row7);
    let cpu_decode_opcode_range_check_bit_9 = column0_row9.clone() - (column0_row10.clone() + &column0_row10);
    let cpu_decode_flag_res_op1_0 = F::one()
       .clone() - (cpu_decode_opcode_range_check_bit_5
           .clone() + &cpu_decode_opcode_range_check_bit_6
           .clone() + cpu_decode_opcode_range_check_bit_9.clone());
    let cpu_decode_opcode_range_check_bit_7 = column0_row7.clone() - (column0_row8.clone() + &column0_row8);
    let cpu_decode_opcode_range_check_bit_8 = column0_row8.clone() - (column0_row9.clone() + &column0_row9);
    let cpu_decode_flag_pc_update_regular_0 = F::one()
       .clone() - (cpu_decode_opcode_range_check_bit_7
           .clone() + &cpu_decode_opcode_range_check_bit_8
           .clone() + cpu_decode_opcode_range_check_bit_9.clone());
    let cpu_decode_opcode_range_check_bit_12 = column0_row12.clone() - (column0_row13.clone() + &column0_row13);
    let cpu_decode_opcode_range_check_bit_13 = column0_row13.clone() - (column0_row14.clone() + &column0_row14);
    let cpu_decode_fp_update_regular_0 =
        F::one() - (cpu_decode_opcode_range_check_bit_12.clone() + &cpu_decode_opcode_range_check_bit_13);
    let cpu_decode_opcode_range_check_bit_1 = column0_row1.clone() - (column0_row2.clone() + &column0_row2);
    let npc_reg_0 = column17_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one();
    let cpu_decode_opcode_range_check_bit_10 = column0_row10.clone() - (column0_row11.clone() + column0_row11.clone());
    let cpu_decode_opcode_range_check_bit_11 = column0_row11.clone() - (column0_row12.clone() + &column0_row12);
    let cpu_decode_opcode_range_check_bit_14 = column0_row14.clone() - (column0_row15.clone() + &column0_row15);
    let memory_address_diff_0 = column18_row2.clone() - &column18_row0;
    let range_check16_diff_0 = column19_row6.clone() - &column19_row2;
    let pedersen_hash0_ec_subset_sum_bit_0 = column3_row0.clone() - (column3_row1.clone() + &column3_row1);
    let pedersen_hash0_ec_subset_sum_bit_neg_0 = F::one() - &pedersen_hash0_ec_subset_sum_bit_0;
    let pedersen_hash1_ec_subset_sum_bit_0 = column6_row0.clone() - (column6_row1.clone() + &column6_row1);
    let pedersen_hash1_ec_subset_sum_bit_neg_0 = F::one() - &pedersen_hash1_ec_subset_sum_bit_0;
    let pedersen_hash2_ec_subset_sum_bit_0 = column9_row0.clone() - (column9_row1.clone() + &column9_row1);
    let pedersen_hash2_ec_subset_sum_bit_neg_0 = F::one() - &pedersen_hash2_ec_subset_sum_bit_0;
    let pedersen_hash3_ec_subset_sum_bit_0 = column12_row0.clone() - (column12_row1.clone() + &column12_row1);
    let pedersen_hash3_ec_subset_sum_bit_neg_0 = F::one() - &pedersen_hash3_ec_subset_sum_bit_0;
    let range_check_builtin_value0_0 = column19_row12;
    let range_check_builtin_value1_0 =
        range_check_builtin_value0_0.clone() * &global_values.offset_size.clone() + &column19_row28;
    let range_check_builtin_value2_0 =
        range_check_builtin_value1_0.clone() * &global_values.offset_size.clone() + &column19_row44;
    let range_check_builtin_value3_0 =
        range_check_builtin_value2_0.clone() * &global_values.offset_size.clone() + &column19_row60;
    let range_check_builtin_value4_0 =
        range_check_builtin_value3_0.clone() * &global_values.offset_size.clone() + &column19_row76;
    let range_check_builtin_value5_0 =
        range_check_builtin_value4_0.clone() * &global_values.offset_size.clone() + &column19_row92;
    let range_check_builtin_value6_0 =
        range_check_builtin_value5_0.clone() * &global_values.offset_size.clone() + &column19_row108;
    let range_check_builtin_value7_0 =
        range_check_builtin_value6_0.clone() * &global_values.offset_size.clone() + &column19_row124;
    let ecdsa_signature0_doubling_key_x_squared = column19_row7.clone() * &column19_row7;
    let ecdsa_signature0_exponentiate_generator_bit_0 =
        column20_row14.clone() - (column20_row46.clone() + &column20_row46);
    let ecdsa_signature0_exponentiate_generator_bit_neg_0 =
        F::one() - &ecdsa_signature0_exponentiate_generator_bit_0;
    let ecdsa_signature0_exponentiate_key_bit_0 = column20_row4.clone() - (column20_row20.clone() + &column20_row20);
    let ecdsa_signature0_exponentiate_key_bit_neg_0 =
        F::one() - &ecdsa_signature0_exponentiate_key_bit_0;

    // Sum constraints.
    let mut total_sum = F::zero();

    // Constraint: cpu/decode/opcode_range_check/bit.
    let mut value = (cpu_decode_opcode_range_check_bit_0.clone() * &cpu_decode_opcode_range_check_bit_0
       .clone() - cpu_decode_opcode_range_check_bit_0.clone())
       .clone() * &domain4.field_div(&domain0);
    total_sum += constraint_coefficients[0].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check/zero.
    value = (column0_row0).field_div(&domain4);
    total_sum += constraint_coefficients[1].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check_input.
    value = (column17_row1
       .clone() - (((column0_row0.clone() * &global_values.offset_size.clone() + column19_row4.clone())
           .clone() * &global_values.offset_size
           .clone() + column19_row8.clone())
           .clone() * &global_values.offset_size
           .clone() + column19_row0.clone()))
        .field_div(&domain5);
    total_sum += constraint_coefficients[2].clone() * &value;

    // Constraint: cpu/decode/flag_op1_base_op0_bit.
    value = (cpu_decode_flag_op1_base_op0_0.clone() * &cpu_decode_flag_op1_base_op0_0
       .clone() - cpu_decode_flag_op1_base_op0_0.clone())
        .field_div(&domain5);
    total_sum += constraint_coefficients[3].clone() * &value;

    // Constraint: cpu/decode/flag_res_op1_bit.
    value = (cpu_decode_flag_res_op1_0.clone() * cpu_decode_flag_res_op1_0.clone() - &cpu_decode_flag_res_op1_0)
        .field_div(&domain5);
    total_sum += constraint_coefficients[4].clone() * &value;

    // Constraint: cpu/decode/flag_pc_update_regular_bit.
    value = (cpu_decode_flag_pc_update_regular_0.clone() * &cpu_decode_flag_pc_update_regular_0
       .clone() - &cpu_decode_flag_pc_update_regular_0)
        .field_div(&domain5);
    total_sum += constraint_coefficients[5].clone() * &value;

    // Constraint: cpu/decode/fp_update_regular_bit.
    value = (cpu_decode_fp_update_regular_0.clone() * &cpu_decode_fp_update_regular_0
       .clone() - &cpu_decode_fp_update_regular_0)
        .field_div(&domain5);
    total_sum += constraint_coefficients[6].clone() * &value;

    // Constraint: cpu/operands/mem_dst_addr.
    value = (column17_row8.clone() + &global_values.half_offset_size
       .clone() - (cpu_decode_opcode_range_check_bit_0.clone() * &column19_row9
           .clone() + (F::one() - &cpu_decode_opcode_range_check_bit_0).clone() * &column19_row1
           .clone() + column19_row0.clone()))
        .field_div(&domain5);
    total_sum += constraint_coefficients[7].clone() * &value;

    // Constraint: cpu/operands/mem0_addr.
    value = (column17_row4.clone() + &global_values.half_offset_size
       .clone() - (cpu_decode_opcode_range_check_bit_1.clone() * &column19_row9
           .clone() + (F::one() - &cpu_decode_opcode_range_check_bit_1).clone() * &column19_row1
           .clone() + column19_row8.clone()))
        .field_div(&domain5);
    total_sum += constraint_coefficients[8].clone() * &value;

    // Constraint: cpu/operands/mem1_addr.
    value = (column17_row12.clone() + &global_values.half_offset_size
       .clone() - (cpu_decode_opcode_range_check_bit_2.clone() * &column17_row0
           .clone() + cpu_decode_opcode_range_check_bit_4.clone() * &column19_row1
           .clone() + cpu_decode_opcode_range_check_bit_3.clone() * &column19_row9
           .clone() + cpu_decode_flag_op1_base_op0_0.clone() * &column17_row5
           .clone() + &column19_row4))
        .field_div(&domain5);
    total_sum += constraint_coefficients[9].clone() * &value;

    // Constraint: cpu/operands/ops_mul.
    value = (column19_row5.clone() - column17_row5.clone() * &column17_row13)
        .field_div(&domain5);
    total_sum += constraint_coefficients[10].clone() * &value;

    // Constraint: cpu/operands/res.
    value = ((F::one() - &cpu_decode_opcode_range_check_bit_9).clone() * &column19_row13
       .clone() - (cpu_decode_opcode_range_check_bit_5.clone() * (column17_row5.clone() + &column17_row13)
           .clone() + cpu_decode_opcode_range_check_bit_6.clone() * &column19_row5
           .clone() + cpu_decode_flag_res_op1_0.clone() * &column17_row13))
        .field_div(&domain5);
    total_sum += constraint_coefficients[11].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp0.
    value = (column19_row3.clone() - cpu_decode_opcode_range_check_bit_9.clone() * &column17_row9)
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[12].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp1.
    value = (column19_row11.clone() - column19_row3.clone() * &column19_row13)
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[13].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_negative.
    value = ((F::one() - &cpu_decode_opcode_range_check_bit_9).clone() * &column17_row16
       .clone() + column19_row3.clone() * (column17_row16.clone() - (column17_row0.clone() + &column17_row13))
       .clone() - (cpu_decode_flag_pc_update_regular_0.clone() * &npc_reg_0
           .clone() + cpu_decode_opcode_range_check_bit_7.clone() * &column19_row13
           .clone() + cpu_decode_opcode_range_check_bit_8.clone() * (column17_row0.clone() + &column19_row13)))
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[14].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_positive.
    value = ((column19_row11.clone() - &cpu_decode_opcode_range_check_bit_9).clone() * (column17_row16.clone() - &npc_reg_0))
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[15].clone() * &value;

    // Constraint: cpu/update_registers/update_ap/ap_update.
    value = (column19_row17
       .clone() - (column19_row1
           .clone() + cpu_decode_opcode_range_check_bit_10.clone() * &column19_row13
           .clone() + &cpu_decode_opcode_range_check_bit_11
           .clone() + cpu_decode_opcode_range_check_bit_12.clone() * &F::two()))
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[16].clone() * &value;

    // Constraint: cpu/update_registers/update_fp/fp_update.
    value = (column19_row25
       .clone() - (cpu_decode_fp_update_regular_0.clone() * &column19_row9
           .clone() + cpu_decode_opcode_range_check_bit_13.clone() * &column17_row9
           .clone() + cpu_decode_opcode_range_check_bit_12.clone() * (column19_row1.clone() + &F::two())))
       .clone() * &domain19.field_div(&domain5);
    total_sum += constraint_coefficients[17].clone() * &value;

    // Constraint: cpu/opcodes/call/push_fp.
    value = (cpu_decode_opcode_range_check_bit_12.clone() * (column17_row9.clone() - &column19_row9))
        .field_div(&domain5);
    total_sum += constraint_coefficients[18].clone() * &value;

    // Constraint: cpu/opcodes/call/push_pc.
    value = (cpu_decode_opcode_range_check_bit_12
       .clone() * (column17_row5.clone() - (column17_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one())))
        .field_div(&domain5);
    total_sum += constraint_coefficients[19].clone() * &value;

    // Constraint: cpu/opcodes/call/off0.
    value = (cpu_decode_opcode_range_check_bit_12
       .clone() * (column19_row0.clone() - &global_values.half_offset_size))
        .field_div(&domain5);
    total_sum += constraint_coefficients[20].clone() * &value;

    // Constraint: cpu/opcodes/call/off1.
    value = (cpu_decode_opcode_range_check_bit_12
       .clone() * (column19_row8.clone() - (global_values.half_offset_size.clone() + &F::one())))
        .field_div(&domain5);
    total_sum += constraint_coefficients[21].clone() * &value;

    // Constraint: cpu/opcodes/call/flags.
    value = (cpu_decode_opcode_range_check_bit_12
       .clone() * (cpu_decode_opcode_range_check_bit_12.clone() + cpu_decode_opcode_range_check_bit_12.clone() + &F::one() + &F::one()
           .clone() - (cpu_decode_opcode_range_check_bit_0.clone() + cpu_decode_opcode_range_check_bit_1.clone() + &F::two() + &F::two())))
        .field_div(&domain5);
    total_sum += constraint_coefficients[22].clone() * &value;

    // Constraint: cpu/opcodes/ret/off0.
    value = (cpu_decode_opcode_range_check_bit_13
       .clone() * (column19_row0.clone() + &F::two() - &global_values.half_offset_size))
        .field_div(&domain5);
    total_sum += constraint_coefficients[23].clone() * &value;

    // Constraint: cpu/opcodes/ret/off2.
    value = (cpu_decode_opcode_range_check_bit_13
       .clone() * (column19_row4.clone() + &F::one() - &global_values.half_offset_size))
        .field_div(&domain5);
    total_sum += constraint_coefficients[24].clone() * &value;

    // Constraint: cpu/opcodes/ret/flags.
    value = (cpu_decode_opcode_range_check_bit_13
       .clone() * (cpu_decode_opcode_range_check_bit_7
           .clone() + &cpu_decode_opcode_range_check_bit_0
           .clone() + &cpu_decode_opcode_range_check_bit_3
           .clone() + &cpu_decode_flag_res_op1_0
           .clone() - &F::two() - &F::two()))
        .field_div(&domain5);
    total_sum += constraint_coefficients[25].clone() * &value;

    // Constraint: cpu/opcodes/assert_eq/assert_eq.
    value = (cpu_decode_opcode_range_check_bit_14.clone() * (column17_row9.clone() - &column19_row13))
        .field_div(&domain5);
    total_sum += constraint_coefficients[26].clone() * &value;

    // Constraint: initial_ap.
    value = (column19_row1.clone() - &global_values.initial_ap)
        .field_div(&domain20);
    total_sum += constraint_coefficients[27].clone() * &value;

    // Constraint: initial_fp.
    value = (column19_row9.clone() - &global_values.initial_ap)
        .field_div(&domain20);
    total_sum += constraint_coefficients[28].clone() * &value;

    // Constraint: initial_pc.
    value = (column17_row0.clone() - &global_values.initial_pc)
        .field_div(&domain20);
    total_sum += constraint_coefficients[29].clone() * &value;

    // Constraint: final_ap.
    value = (column19_row1.clone() - &global_values.final_ap)
        .field_div(&domain19);
    total_sum += constraint_coefficients[30].clone() * &value;

    // Constraint: final_fp.
    value = (column19_row9.clone() - &global_values.initial_ap)
        .field_div(&domain19);
    total_sum += constraint_coefficients[31].clone() * &value;

    // Constraint: final_pc.
    value = (column17_row0.clone() - &global_values.final_pc)
        .field_div(&domain19);
    total_sum += constraint_coefficients[32].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/init0.
    value = ((global_values.memory_multi_column_perm_perm_interaction_elm
       .clone() - (column18_row0
           .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column18_row1))
       .clone() * &column21_inter1_row0
       .clone() + &column17_row0
       .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column17_row1
       .clone() - &global_values.memory_multi_column_perm_perm_interaction_elm)
        .field_div(&domain20);
    total_sum += constraint_coefficients[33].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/step0.
    value = ((global_values.memory_multi_column_perm_perm_interaction_elm
       .clone() - (column18_row2
           .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column18_row3))
       .clone() * &column21_inter1_row2
       .clone() - (global_values.memory_multi_column_perm_perm_interaction_elm
           .clone() - (column17_row2
               .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column17_row3))
           .clone() * &column21_inter1_row0)
       .clone() * &domain21.field_div(&domain1);
    total_sum += constraint_coefficients[34].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/last.
    value = (column21_inter1_row0.clone() - &global_values.memory_multi_column_perm_perm_public_memory_prod)
        .field_div(&domain21);
    total_sum += constraint_coefficients[35].clone() * &value;

    // Constraint: memory/diff_is_bit.
    value = (memory_address_diff_0.clone() * memory_address_diff_0.clone() - &memory_address_diff_0)
       .clone() * &domain21.field_div(&domain1);
    total_sum += constraint_coefficients[36].clone() * &value;

    // Constraint: memory/is_func.
    value = ((memory_address_diff_0.clone() - &F::one()).clone() * (column18_row1.clone() - &column18_row3))
       .clone() * &domain21.field_div(&domain1);
    total_sum += constraint_coefficients[37].clone() * &value;

    // Constraint: memory/initial_addr.
    value = (column18_row0.clone() - &F::one()).field_div(&domain20);
    total_sum += constraint_coefficients[38].clone() * &value;

    // Constraint: public_memory_addr_zero.
    value = (column17_row2).field_div(&domain3);
    total_sum += constraint_coefficients[39].clone() * &value;

    // Constraint: public_memory_value_zero.
    value = (column17_row3).field_div(&domain3);
    total_sum += constraint_coefficients[40].clone() * &value;

    // Constraint: range_check16/perm/init0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column19_row2)
       .clone() * &column21_inter1_row1
       .clone() + &column19_row0
       .clone() - &global_values.range_check16_perm_interaction_elm)
        .field_div(&domain20);
    total_sum += constraint_coefficients[41].clone() * &value;

    // Constraint: range_check16/perm/step0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column19_row6)
       .clone() * &column21_inter1_row5
       .clone() - (global_values.range_check16_perm_interaction_elm.clone() - &column19_row4)
           .clone() * &column21_inter1_row1)
       .clone() * &domain22.field_div(&domain2);
    total_sum += constraint_coefficients[42].clone() * &value;

    // Constraint: range_check16/perm/last.
    value = (column21_inter1_row1.clone() - &global_values.range_check16_perm_public_memory_prod)
        .field_div(&domain22);
    total_sum += constraint_coefficients[43].clone() * &value;

    // Constraint: range_check16/diff_is_bit.
    value = (range_check16_diff_0.clone() * range_check16_diff_0.clone() - &range_check16_diff_0)
       .clone() * &domain22.field_div(&domain2);
    total_sum += constraint_coefficients[44].clone() * &value;

    // Constraint: range_check16/minimum.
    value = (column19_row2.clone() - &global_values.range_check_min)
        .field_div(&domain20);
    total_sum += constraint_coefficients[45].clone() * &value;

    // Constraint: range_check16/maximum.
    value = (column19_row2.clone() - &global_values.range_check_max)
        .field_div(&domain22);
    total_sum += constraint_coefficients[46].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column14_row255.clone() * (column3_row0.clone() - (column3_row1.clone() + &column3_row1)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[47].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column14_row255
       .clone() * (column3_row1
           .clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000000000000000000"))
               .clone() * &column3_row192))
        .field_div(&domain8);
    total_sum += constraint_coefficients[48].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column14_row255
       .clone() - column13_row255.clone() * (column3_row192.clone() - (column3_row193.clone() + &column3_row193)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[49].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column13_row255.clone() * (column3_row193.clone() - F::from_constant(8 as u64).clone() * &column3_row196))
        .field_div(&domain8);
    total_sum += constraint_coefficients[50].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column13_row255
       .clone() - (column3_row251.clone() - (column3_row252.clone() + &column3_row252))
           .clone() * (column3_row196.clone() - (column3_row197.clone() + &column3_row197)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[51].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column3_row251.clone() - (column3_row252.clone() + &column3_row252))
       .clone() * (column3_row197.clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone() * &column3_row251))
        .field_div(&domain8);
    total_sum += constraint_coefficients[52].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/booleanity_test.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone() * (pedersen_hash0_ec_subset_sum_bit_0.clone() - &F::one()))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[53].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_extraction_end.
    value = (column3_row0).field_div(&domain10);
    total_sum += constraint_coefficients[54].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/zeros_tail.
    value = (column3_row0).field_div(&domain9);
    total_sum += constraint_coefficients[55].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/slope.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone() * (column2_row0.clone() - &global_values.pedersen_points_y)
       .clone() - column13_row0.clone() * (column1_row0.clone() - &global_values.pedersen_points_x))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[56].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/x.
    value = (column13_row0.clone() * &column13_row0
       .clone() - pedersen_hash0_ec_subset_sum_bit_0
           .clone() * (column1_row0.clone() + &global_values.pedersen_points_x.clone() + &column1_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[57].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/y.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone() * (column2_row0.clone() + &column2_row1)
       .clone() - column13_row0.clone() * (column1_row0.clone() - &column1_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[58].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/x.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone() * (column1_row1.clone() - &column1_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[59].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/y.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone() * (column2_row1.clone() - &column2_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[60].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/x.
    value = (column1_row256.clone() - &column1_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[61].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/y.
    value = (column2_row256.clone() - &column2_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[62].clone() * &value;

    // Constraint: pedersen/hash0/init/x.
    value = (column1_row0.clone() - &global_values.pedersen_shift_point.x)
        .field_div(&domain12);
    total_sum += constraint_coefficients[63].clone() * &value;

    // Constraint: pedersen/hash0/init/y.
    value = (column2_row0.clone() - &global_values.pedersen_shift_point.y)
        .field_div(&domain12);
    total_sum += constraint_coefficients[64].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column16_row255.clone() * (column6_row0.clone() - (column6_row1.clone() + &column6_row1)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[65].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column16_row255
       .clone() * (column6_row1
           .clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000000000000000000"))
               .clone() * &column6_row192))
        .field_div(&domain8);
    total_sum += constraint_coefficients[66].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column16_row255
       .clone() - column15_row255.clone() * (column6_row192.clone() - (column6_row193.clone() + &column6_row193)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[67].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column15_row255.clone() * (column6_row193.clone() - F::from_constant(8 as u64).clone() * &column6_row196))
        .field_div(&domain8);
    total_sum += constraint_coefficients[68].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column15_row255
       .clone() - (column6_row251.clone() - (column6_row252.clone() + &column6_row252))
           .clone() * (column6_row196.clone() - (column6_row197.clone() + &column6_row197)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[69].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column6_row251.clone() - (column6_row252.clone() + &column6_row252))
       .clone() * (column6_row197.clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone() * &column6_row251))
        .field_div(&domain8);
    total_sum += constraint_coefficients[70].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/booleanity_test.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone() * (pedersen_hash1_ec_subset_sum_bit_0.clone() - &F::one()))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[71].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/bit_extraction_end.
    value = (column6_row0).field_div(&domain10);
    total_sum += constraint_coefficients[72].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/zeros_tail.
    value = (column6_row0).field_div(&domain9);
    total_sum += constraint_coefficients[73].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/slope.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone() * (column5_row0.clone() - &global_values.pedersen_points_y)
       .clone() - column14_row0.clone() * (column4_row0.clone() - &global_values.pedersen_points_x))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[74].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/x.
    value = (column14_row0.clone() * &column14_row0
       .clone() - pedersen_hash1_ec_subset_sum_bit_0
           .clone() * (column4_row0.clone() + &global_values.pedersen_points_x.clone() + &column4_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[75].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/add_points/y.
    value = (pedersen_hash1_ec_subset_sum_bit_0.clone() * (column5_row0.clone() + &column5_row1)
       .clone() - column14_row0.clone() * (column4_row0.clone() - &column4_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[76].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/copy_point/x.
    value = (pedersen_hash1_ec_subset_sum_bit_neg_0.clone() * (column4_row1.clone() - &column4_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[77].clone() * &value;

    // Constraint: pedersen/hash1/ec_subset_sum/copy_point/y.
    value = (pedersen_hash1_ec_subset_sum_bit_neg_0.clone() * (column5_row1.clone() - &column5_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[78].clone() * &value;

    // Constraint: pedersen/hash1/copy_point/x.
    value = (column4_row256.clone() - &column4_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[79].clone() * &value;

    // Constraint: pedersen/hash1/copy_point/y.
    value = (column5_row256.clone() - &column5_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[80].clone() * &value;

    // Constraint: pedersen/hash1/init/x.
    value = (column4_row0.clone() - &global_values.pedersen_shift_point.x)
        .field_div(&domain12);
    total_sum += constraint_coefficients[81].clone() * &value;

    // Constraint: pedersen/hash1/init/y.
    value = (column5_row0.clone() - &global_values.pedersen_shift_point.y)
        .field_div(&domain12);
    total_sum += constraint_coefficients[82].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column20_row145.clone() * (column9_row0.clone() - (column9_row1.clone() + &column9_row1)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[83].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column20_row145
       .clone() * (column9_row1
           .clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000000000000000000"))
               .clone() * &column9_row192))
        .field_div(&domain8);
    total_sum += constraint_coefficients[84].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column20_row145
       .clone() - column20_row17.clone() * (column9_row192.clone() - (column9_row193.clone() + &column9_row193)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[85].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column20_row17.clone() * (column9_row193.clone() - F::from_constant(8 as u64).clone() * &column9_row196))
        .field_div(&domain8);
    total_sum += constraint_coefficients[86].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column20_row17
       .clone() - (column9_row251.clone() - (column9_row252.clone() + &column9_row252))
           .clone() * (column9_row196.clone() - (column9_row197.clone() + &column9_row197)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[87].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column9_row251.clone() - (column9_row252.clone() + &column9_row252))
       .clone() * (column9_row197.clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone() * &column9_row251))
        .field_div(&domain8);
    total_sum += constraint_coefficients[88].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/booleanity_test.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone() * (pedersen_hash2_ec_subset_sum_bit_0.clone() - &F::one()))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[89].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/bit_extraction_end.
    value = (column9_row0).field_div(&domain10);
    total_sum += constraint_coefficients[90].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/zeros_tail.
    value = (column9_row0).field_div(&domain9);
    total_sum += constraint_coefficients[91].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/slope.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone() * (column8_row0.clone() - &global_values.pedersen_points_y)
       .clone() - column15_row0.clone() * (column7_row0.clone() - &global_values.pedersen_points_x))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[92].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/x.
    value = (column15_row0.clone() * &column15_row0
       .clone() - pedersen_hash2_ec_subset_sum_bit_0
           .clone() * (column7_row0.clone() + &global_values.pedersen_points_x.clone() + &column7_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[93].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/add_points/y.
    value = (pedersen_hash2_ec_subset_sum_bit_0.clone() * (column8_row0.clone() + &column8_row1)
       .clone() - column15_row0.clone() * (column7_row0.clone() - &column7_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[94].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/copy_point/x.
    value = (pedersen_hash2_ec_subset_sum_bit_neg_0.clone() * (column7_row1.clone() - &column7_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[95].clone() * &value;

    // Constraint: pedersen/hash2/ec_subset_sum/copy_point/y.
    value = (pedersen_hash2_ec_subset_sum_bit_neg_0.clone() * (column8_row1.clone() - &column8_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[96].clone() * &value;

    // Constraint: pedersen/hash2/copy_point/x.
    value = (column7_row256.clone() - &column7_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[97].clone() * &value;

    // Constraint: pedersen/hash2/copy_point/y.
    value = (column8_row256.clone() - &column8_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[98].clone() * &value;

    // Constraint: pedersen/hash2/init/x.
    value = (column7_row0.clone() - &global_values.pedersen_shift_point.x)
        .field_div(&domain12);
    total_sum += constraint_coefficients[99].clone() * &value;

    // Constraint: pedersen/hash2/init/y.
    value = (column8_row0.clone() - &global_values.pedersen_shift_point.y)
        .field_div(&domain12);
    total_sum += constraint_coefficients[100].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column20_row209.clone() * (column12_row0.clone() - (column12_row1.clone() + &column12_row1)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[101].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column20_row209
       .clone() * (column12_row1
           .clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000000000000000000"))
               .clone() * &column12_row192))
        .field_div(&domain8);
    total_sum += constraint_coefficients[102].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column20_row209
       .clone() - column20_row81.clone() * (column12_row192.clone() - (column12_row193.clone() + &column12_row193)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[103].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column20_row81.clone() * (column12_row193.clone() - F::from_constant(8 as u64).clone() * &column12_row196))
        .field_div(&domain8);
    total_sum += constraint_coefficients[104].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column20_row81
       .clone() - (column12_row251.clone() - (column12_row252.clone() + &column12_row252))
           .clone() * (column12_row196.clone() - (column12_row197.clone() + &column12_row197)))
        .field_div(&domain8);
    total_sum += constraint_coefficients[105].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column12_row251.clone() - (column12_row252.clone() + &column12_row252))
       .clone() * (column12_row197.clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone() * &column12_row251))
        .field_div(&domain8);
    total_sum += constraint_coefficients[106].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/booleanity_test.
    value = (pedersen_hash3_ec_subset_sum_bit_0.clone() * (pedersen_hash3_ec_subset_sum_bit_0.clone() - &F::one()))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[107].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/bit_extraction_end.
    value = (column12_row0).field_div(&domain10);
    total_sum += constraint_coefficients[108].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/zeros_tail.
    value = (column12_row0).field_div(&domain9);
    total_sum += constraint_coefficients[109].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/slope.
    value = (pedersen_hash3_ec_subset_sum_bit_0
       .clone() * (column11_row0.clone() - &global_values.pedersen_points_y)
       .clone() - column16_row0.clone() * (column10_row0.clone() - &global_values.pedersen_points_x))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[110].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/x.
    value = (column16_row0.clone() * &column16_row0
       .clone() - pedersen_hash3_ec_subset_sum_bit_0
           .clone() * (column10_row0.clone() + &global_values.pedersen_points_x.clone() + &column10_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[111].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/add_points/y.
    value = (pedersen_hash3_ec_subset_sum_bit_0.clone() * (column11_row0.clone() + &column11_row1)
       .clone() - column16_row0.clone() * (column10_row0.clone() - &column10_row1))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[112].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/copy_point/x.
    value = (pedersen_hash3_ec_subset_sum_bit_neg_0.clone() * (column10_row1.clone() - &column10_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[113].clone() * &value;

    // Constraint: pedersen/hash3/ec_subset_sum/copy_point/y.
    value = (pedersen_hash3_ec_subset_sum_bit_neg_0.clone() * (column11_row1.clone() - &column11_row0))
       .clone() * &domain9.field_div(&domain0);
    total_sum += constraint_coefficients[114].clone() * &value;

    // Constraint: pedersen/hash3/copy_point/x.
    value = (column10_row256.clone() - &column10_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[115].clone() * &value;

    // Constraint: pedersen/hash3/copy_point/y.
    value = (column11_row256.clone() - &column11_row255)
       .clone() * &domain11.field_div(&domain8);
    total_sum += constraint_coefficients[116].clone() * &value;

    // Constraint: pedersen/hash3/init/x.
    value = (column10_row0.clone() - &global_values.pedersen_shift_point.x)
        .field_div(&domain12);
    total_sum += constraint_coefficients[117].clone() * &value;

    // Constraint: pedersen/hash3/init/y.
    value = (column11_row0.clone() - &global_values.pedersen_shift_point.y)
        .field_div(&domain12);
    total_sum += constraint_coefficients[118].clone() * &value;

    // Constraint: pedersen/input0_value0.
    value = (column17_row7.clone() - &column3_row0).field_div(&domain12);
    total_sum += constraint_coefficients[119].clone() * &value;

    // Constraint: pedersen/input0_value1.
    value = (column17_row135.clone() - &column6_row0).field_div(&domain12);
    total_sum += constraint_coefficients[120].clone() * &value;

    // Constraint: pedersen/input0_value2.
    value = (column17_row263.clone() - &column9_row0).field_div(&domain12);
    total_sum += constraint_coefficients[121].clone() * &value;

    // Constraint: pedersen/input0_value3.
    value =
        (column17_row391.clone() - &column12_row0).field_div(&domain12);
    total_sum += constraint_coefficients[122].clone() * &value;

    // Constraint: pedersen/input0_addr.
    value = (column17_row134.clone() - (column17_row38.clone() + &F::one()))
       .clone() * &domain23.field_div(&domain7);
    total_sum += constraint_coefficients[123].clone() * &value;

    // Constraint: pedersen/init_addr.
    value = (column17_row6.clone() - &global_values.initial_pedersen_addr)
        .field_div(&domain20);
    total_sum += constraint_coefficients[124].clone() * &value;

    // Constraint: pedersen/input1_value0.
    value =
        (column17_row71.clone() - &column3_row256).field_div(&domain12);
    total_sum += constraint_coefficients[125].clone() * &value;

    // Constraint: pedersen/input1_value1.
    value =
        (column17_row199.clone() - &column6_row256).field_div(&domain12);
    total_sum += constraint_coefficients[126].clone() * &value;

    // Constraint: pedersen/input1_value2.
    value =
        (column17_row327.clone() - &column9_row256).field_div(&domain12);
    total_sum += constraint_coefficients[127].clone() * &value;

    // Constraint: pedersen/input1_value3.
    value =
        (column17_row455.clone() - &column12_row256).field_div(&domain12);
    total_sum += constraint_coefficients[128].clone() * &value;

    // Constraint: pedersen/input1_addr.
    value = (column17_row70.clone() - (column17_row6.clone() + &F::one()))
        .field_div(&domain7);
    total_sum += constraint_coefficients[129].clone() * &value;

    // Constraint: pedersen/output_value0.
    value =
        (column17_row39.clone() - &column1_row511).field_div(&domain12);
    total_sum += constraint_coefficients[130].clone() * &value;

    // Constraint: pedersen/output_value1.
    value =
        (column17_row167.clone() - &column4_row511).field_div(&domain12);
    total_sum += constraint_coefficients[131].clone() * &value;

    // Constraint: pedersen/output_value2.
    value =
        (column17_row295.clone() - &column7_row511).field_div(&domain12);
    total_sum += constraint_coefficients[132].clone() * &value;

    // Constraint: pedersen/output_value3.
    value =
        (column17_row423.clone() - &column10_row511).field_div(&domain12);
    total_sum += constraint_coefficients[133].clone() * &value;

    // Constraint: pedersen/output_addr.
    value = (column17_row38.clone() - (column17_row70.clone() + &F::one()))
        .field_div(&domain7);
    total_sum += constraint_coefficients[134].clone() * &value;

    // Constraint: range_check_builtin/value.
    value = (range_check_builtin_value7_0.clone() - &column17_row103)
        .field_div(&domain7);
    total_sum += constraint_coefficients[135].clone() * &value;

    // Constraint: range_check_builtin/addr_step.
    value = (column17_row230.clone() - (column17_row102.clone() + &F::one()))
       .clone() * &domain23.field_div(&domain7);
    total_sum += constraint_coefficients[136].clone() * &value;

    // Constraint: range_check_builtin/init_addr.
    value = (column17_row102.clone() - &global_values.initial_range_check_addr)
        .field_div(&domain20);
    total_sum += constraint_coefficients[137].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/slope.
    value = (ecdsa_signature0_doubling_key_x_squared
       .clone() + &ecdsa_signature0_doubling_key_x_squared
       .clone() + &ecdsa_signature0_doubling_key_x_squared
       .clone() + &global_values.ecdsa_sig_config.alpha
       .clone() - (column19_row15.clone() + &column19_row15).clone() * &column20_row12)
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[138].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/x.
    value = (column20_row12.clone() * column20_row12.clone() - (column19_row7.clone() + column19_row7.clone() + &column19_row23))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[139].clone() * &value;

    // Constraint: ecdsa/signature0/doubling_key/y.
    value = (column19_row15.clone() + column19_row31.clone() - column20_row12.clone() * (column19_row7.clone() - &column19_row23))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[140].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/booleanity_test.
    value = (ecdsa_signature0_exponentiate_generator_bit_0
       .clone() * (ecdsa_signature0_exponentiate_generator_bit_0.clone() - &F::one()))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[141].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/bit_extraction_end.
    value = (column20_row14).field_div(&domain17);
    total_sum += constraint_coefficients[142].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/zeros_tail.
    value = (column20_row14).field_div(&domain16);
    total_sum += constraint_coefficients[143].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/slope.
    value = (ecdsa_signature0_exponentiate_generator_bit_0
       .clone() * (column20_row22.clone() - &global_values.ecdsa_generator_points_y)
       .clone() - column20_row30.clone() * (column20_row6.clone() - &global_values.ecdsa_generator_points_x))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[144].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/x.
    value = (column20_row30.clone() * &column20_row30
       .clone() - ecdsa_signature0_exponentiate_generator_bit_0
           .clone() * (column20_row6.clone() + &global_values.ecdsa_generator_points_x.clone() + &column20_row38))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[145].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/y.
    value = (ecdsa_signature0_exponentiate_generator_bit_0.clone() * (column20_row22.clone() + &column20_row54)
       .clone() - column20_row30.clone() * (column20_row6.clone() - &column20_row38))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[146].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/add_points/x_diff_inv.
    value = (column20_row1.clone() * (column20_row6.clone() - &global_values.ecdsa_generator_points_x).clone() - &F::one())
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[147].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/copy_point/x.
    value = (ecdsa_signature0_exponentiate_generator_bit_neg_0.clone() * (column20_row38.clone() - &column20_row6))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[148].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_generator/copy_point/y.
    value = (ecdsa_signature0_exponentiate_generator_bit_neg_0.clone() * (column20_row54.clone() - &column20_row22))
       .clone() * &domain16.field_div(&domain6);
    total_sum += constraint_coefficients[149].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/booleanity_test.
    value = (ecdsa_signature0_exponentiate_key_bit_0
       .clone() * (ecdsa_signature0_exponentiate_key_bit_0.clone() - &F::one()))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[150].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/bit_extraction_end.
    value = (column20_row4).field_div(&domain14);
    total_sum += constraint_coefficients[151].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/zeros_tail.
    value = (column20_row4).field_div(&domain13);
    total_sum += constraint_coefficients[152].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/slope.
    value = (ecdsa_signature0_exponentiate_key_bit_0.clone() * (column20_row8.clone() - &column19_row15)
       .clone() - column20_row2.clone() * (column20_row0.clone() - &column19_row7))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[153].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/x.
    value = (column20_row2.clone() * &column20_row2
       .clone() - ecdsa_signature0_exponentiate_key_bit_0
           .clone() * (column20_row0.clone() + column19_row7.clone() + &column20_row16))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[154].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/y.
    value = (ecdsa_signature0_exponentiate_key_bit_0.clone() * (column20_row8.clone() + &column20_row24)
       .clone() - column20_row2.clone() * (column20_row0.clone() - &column20_row16))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[155].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/add_points/x_diff_inv.
    value = (column20_row10.clone() * (column20_row0.clone() - &column19_row7).clone() - &F::one())
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[156].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/copy_point/x.
    value = (ecdsa_signature0_exponentiate_key_bit_neg_0.clone() * (column20_row16.clone() - &column20_row0))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[157].clone() * &value;

    // Constraint: ecdsa/signature0/exponentiate_key/copy_point/y.
    value = (ecdsa_signature0_exponentiate_key_bit_neg_0.clone() * (column20_row24.clone() - &column20_row8))
       .clone() * &domain13.field_div(&domain5);
    total_sum += constraint_coefficients[158].clone() * &value;

    // Constraint: ecdsa/signature0/init_gen/x.
    value = (column20_row6.clone() - &global_values.ecdsa_sig_config.shift_point.x)
        .field_div(&domain18);
    total_sum += constraint_coefficients[159].clone() * &value;

    // Constraint: ecdsa/signature0/init_gen/y.
    value = (column20_row22.clone() + &global_values.ecdsa_sig_config.shift_point.y)
        .field_div(&domain18);
    total_sum += constraint_coefficients[160].clone() * &value;

    // Constraint: ecdsa/signature0/init_key/x.
    value = (column20_row0.clone() - &global_values.ecdsa_sig_config.shift_point.x)
        .field_div(&domain15);
    total_sum += constraint_coefficients[161].clone() * &value;

    // Constraint: ecdsa/signature0/init_key/y.
    value = (column20_row8.clone() - &global_values.ecdsa_sig_config.shift_point.y)
        .field_div(&domain15);
    total_sum += constraint_coefficients[162].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/slope.
    value = (column20_row8182
       .clone() - (column20_row4088.clone() + column20_row8190.clone() * (column20_row8166.clone() - &column20_row4080)))
        .field_div(&domain18);
    total_sum += constraint_coefficients[163].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/x.
    value = (column20_row8190.clone() * &column20_row8190
       .clone() - (column20_row8166.clone() + column20_row4080.clone() + &column19_row4103))
        .field_div(&domain18);
    total_sum += constraint_coefficients[164].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/y.
    value = (column20_row8182.clone() + &column19_row4111
       .clone() - column20_row8190.clone() * (column20_row8166.clone() - &column19_row4103))
        .field_div(&domain18);
    total_sum += constraint_coefficients[165].clone() * &value;

    // Constraint: ecdsa/signature0/add_results/x_diff_inv.
    value = (column20_row8161.clone() * (column20_row8166.clone() - &column20_row4080).clone() - &F::one())
        .field_div(&domain18);
    total_sum += constraint_coefficients[166].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/slope.
    value = (column20_row8184.clone() + &global_values.ecdsa_sig_config.shift_point.y
       .clone() - column20_row4082.clone() * (column20_row8176.clone() - &global_values.ecdsa_sig_config.shift_point.x))
        .field_div(&domain18);
    total_sum += constraint_coefficients[167].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/x.
    value = (column20_row4082.clone() * &column20_row4082
       .clone() - (column20_row8176.clone() + &global_values.ecdsa_sig_config.shift_point.x.clone() + &column20_row4))
        .field_div(&domain18);
    total_sum += constraint_coefficients[168].clone() * &value;

    // Constraint: ecdsa/signature0/extract_r/x_diff_inv.
    value = (column20_row8178.clone() * (column20_row8176.clone() - &global_values.ecdsa_sig_config.shift_point.x)
       .clone() - &F::one())
    .field_div(&domain18);
    total_sum += constraint_coefficients[169].clone() * &value;

    // Constraint: ecdsa/signature0/z_nonzero.
    value = (column20_row14.clone() * column20_row4090.clone() - &F::one())
        .field_div(&domain18);
    total_sum += constraint_coefficients[170].clone() * &value;

    // Constraint: ecdsa/signature0/r_and_w_nonzero.
    value = (column20_row4.clone() * column20_row4092.clone() - &F::one())
        .field_div(&domain15);
    total_sum += constraint_coefficients[171].clone() * &value;

    // Constraint: ecdsa/signature0/q_on_curve/x_squared.
    value = (column20_row8186.clone() - column19_row7.clone() * &column19_row7)
        .field_div(&domain18);
    total_sum += constraint_coefficients[172].clone() * &value;

    // Constraint: ecdsa/signature0/q_on_curve/on_curve.
    value = (column19_row15.clone() * &column19_row15
       .clone() - (column19_row7.clone() * &column20_row8186
           .clone() + global_values.ecdsa_sig_config.alpha.clone() * &column19_row7
           .clone() + &global_values.ecdsa_sig_config.beta))
        .field_div(&domain18);
    total_sum += constraint_coefficients[173].clone() * &value;

    // Constraint: ecdsa/init_addr.
    value = (column17_row22.clone() - &global_values.initial_ecdsa_addr)
        .field_div(&domain20);
    total_sum += constraint_coefficients[174].clone() * &value;

    // Constraint: ecdsa/message_addr.
    value = (column17_row4118.clone() - (column17_row22.clone() + &F::one()))
        .field_div(&domain18);
    total_sum += constraint_coefficients[175].clone() * &value;

    // Constraint: ecdsa/pubkey_addr.
    value = (column17_row8214.clone() - (column17_row4118.clone() + &F::one()))
       .clone() * &domain24.field_div(&domain18);
    total_sum += constraint_coefficients[176].clone() * &value;

    // Constraint: ecdsa/message_value0.
    value =
        (column17_row4119.clone() - &column20_row14).field_div(&domain18);
    total_sum += constraint_coefficients[177].clone() * &value;

    // Constraint: ecdsa/pubkey_value0.
    value = (column17_row23.clone() - &column19_row7).field_div(&domain18);
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
    let pow0 = trace_generator.powers([0]);
    let pow1 = trace_generator.powers([8161]);
    let pow2 = trace_generator.powers([4080]);
    let pow3 = trace_generator.powers([1]);
    let pow4 = pow3.clone() *  &pow3; // pow(trace_generator, 2).
    let pow5 = pow2.clone() *  &pow4; // pow(trace_generator, 4082).
    let pow6 = pow3.clone() *  &pow4; // pow(trace_generator, 3).
    let pow7 = pow3.clone() *  &pow6; // pow(trace_generator, 4).
    let pow8 = pow3.clone() *  &pow7; // pow(trace_generator, 5).
    let pow9 = pow1.clone() *  &pow8; // pow(trace_generator, 8166).
    let pow10 = pow3.clone() * &pow8; // pow(trace_generator, 6).
    let pow11 = pow3.clone() * &pow10; // pow(trace_generator, 7).
    let pow12 = pow3.clone() * &pow11; // pow(trace_generator, 8).
    let pow13 = pow2.clone() * &pow12; // pow(trace_generator, 4088).
    let pow14 = pow3.clone() * &pow12; // pow(trace_generator, 9).
    let pow15 = pow3.clone() * &pow14; // pow(trace_generator, 10).
    let pow16 = pow2.clone() * &pow15; // pow(trace_generator, 4090).
    let pow17 = pow3.clone() * &pow15; // pow(trace_generator, 11).
    let pow18 = pow3.clone() * &pow17; // pow(trace_generator, 12).
    let pow19 = pow3.clone() * &pow18; // pow(trace_generator, 13).
    let pow20 = pow3.clone() * &pow19; // pow(trace_generator, 14).
    let pow21 = pow3.clone() * &pow20; // pow(trace_generator, 15).
    let pow22 = pow3.clone() * &pow21; // pow(trace_generator, 16).
    let pow23 = pow3.clone() * &pow22; // pow(trace_generator, 17).
    let pow24 = pow6.clone() * &pow23; // pow(trace_generator, 20).
    let pow25 = pow4.clone() * &pow24; // pow(trace_generator, 22).
    let pow26 = pow3.clone() * &pow25; // pow(trace_generator, 23).
    let pow27 = pow3.clone() * &pow26; // pow(trace_generator, 24).
    let pow28 = pow3.clone() * &pow27; // pow(trace_generator, 25).
    let pow29 = pow6.clone() * &pow28; // pow(trace_generator, 28).
    let pow30 = pow4.clone() * &pow29; // pow(trace_generator, 30).
    let pow31 = pow3.clone() * &pow30; // pow(trace_generator, 31).
    let pow32 = pow1.clone() * &pow21; // pow(trace_generator, 8176).
    let pow33 = pow1.clone() * &pow23; // pow(trace_generator, 8178).
    let pow34 = pow11.clone() * &pow31; // pow(trace_generator, 38).
    let pow35 = pow3.clone() *  &pow34; // pow(trace_generator, 39).
    let pow36 = pow8.clone() *  &pow35; // pow(trace_generator, 44).
    let pow37 = pow4.clone() *  &pow36; // pow(trace_generator, 46).
    let pow38 = pow12.clone() * &pow37; // pow(trace_generator, 54).
    let pow39 = pow10.clone() * &pow38; // pow(trace_generator, 60).
    let pow40 = pow15.clone() * &pow39; // pow(trace_generator, 70).
    let pow41 = pow3.clone() *  &pow40; // pow(trace_generator, 71).
    let pow42 = pow8.clone() *  &pow41; // pow(trace_generator, 76).
    let pow43 = pow8.clone() *  &pow42; // pow(trace_generator, 81).
    let pow44 = pow17.clone() * &pow43; // pow(trace_generator, 92).
    let pow45 = pow15.clone() * &pow44; // pow(trace_generator, 102).
    let pow46 = pow3.clone() *  &pow45; // pow(trace_generator, 103).
    let pow47 = pow8.clone() *  &pow46; // pow(trace_generator, 108).
    let pow48 = pow22.clone() * &pow47; // pow(trace_generator, 124).
    let pow49 = pow15.clone() * &pow48; // pow(trace_generator, 134).
    let pow50 = pow3.clone() *  &pow49; // pow(trace_generator, 135).
    let pow51 = pow15.clone() * &pow50; // pow(trace_generator, 145).
    let pow52 = pow25.clone() * &pow51; // pow(trace_generator, 167).
    let pow53 = pow28.clone() * &pow52; // pow(trace_generator, 192).
    let pow54 = pow3.clone() *  &pow53; // pow(trace_generator, 193).
    let pow55 = pow6.clone() *  &pow54; // pow(trace_generator, 196).
    let pow56 = pow3.clone() *  &pow55; // pow(trace_generator, 197).
    let pow57 = pow38.clone() * &pow56; // pow(trace_generator, 251).
    let pow58 = pow4.clone() *  &pow56; // pow(trace_generator, 199).
    let pow59 = pow31.clone() * &pow58; // pow(trace_generator, 230).
    let pow60 = pow3.clone() *  &pow57; // pow(trace_generator, 252).
    let pow61 = pow2.clone() *  &pow18; // pow(trace_generator, 4092).
    let pow62 = pow7.clone() *  &pow33; // pow(trace_generator, 8182).
    let pow63 = pow1.clone() *  &pow26; // pow(trace_generator, 8184).
    let pow64 = pow1.clone() *  &pow28; // pow(trace_generator, 8186).
    let pow65 = pow7.clone() *  &pow64; // pow(trace_generator, 8190).
    let pow66 = pow2.clone() *  &pow26; // pow(trace_generator, 4103).
    let pow67 = pow2.clone() *  &pow31; // pow(trace_generator, 4111).
    let pow68 = pow27.clone() * &pow65; // pow(trace_generator, 8214).
    let pow69 = pow2.clone() * &pow34; // pow(trace_generator, 4118).
    let pow70 = pow2.clone() * &pow35; // pow(trace_generator, 4119).
    let pow71 = pow15.clone() * &pow58; // pow(trace_generator, 209).
    let pow72 = pow6.clone() * &pow60; // pow(trace_generator, 255).
    let pow73 = pow3.clone() * &pow72; // pow(trace_generator, 256).
    let pow74 = pow72.clone() * &pow73; // pow(trace_generator, 511).
    let pow75 = pow52.clone() * &pow73; // pow(trace_generator, 423).
    let pow76 = pow50.clone() * &pow73; // pow(trace_generator, 391).
    let pow77 = pow41.clone() * &pow73; // pow(trace_generator, 327).
    let pow78 = pow35.clone() * &pow73; // pow(trace_generator, 295).
    let pow79 = pow11.clone() * &pow73; // pow(trace_generator, 263).
    let pow80 = pow53.clone() * &pow79; // pow(trace_generator, 455).

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

    // Sum the OODS constraints on the trace polynomials.
    let mut value: F;
    let mut total_sum = F::zero();

    value = (column0.clone() - &oods_values[0].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[0].clone() * &value;

    value = (column0.clone() - &oods_values[1].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[1].clone() * &value;

    value = (column0.clone() - &oods_values[2].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[2].clone() * &value;

    value = (column0.clone() - &oods_values[3].clone())
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[3].clone() * &value;

    value = (column0.clone() - &oods_values[4].clone())
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[4].clone() * &value;

    value = (column0.clone() - &oods_values[5].clone())
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[5].clone() * &value;

    value = (column0.clone() - &oods_values[6].clone())
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[6].clone() * &value;

    value = (column0.clone() - &oods_values[7].clone())
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[7].clone() * &value;

    value = (column0.clone() - &oods_values[8].clone())
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[8].clone() * &value;

    value = (column0.clone() - &oods_values[9].clone())
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[9].clone() * &value;

    value = (column0.clone() - &oods_values[10].clone())
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[10].clone() * &value;

    value = (column0.clone() - &oods_values[11].clone())
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[11].clone() * &value;

    value = (column0.clone() - &oods_values[12].clone())
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[12].clone() * &value;

    value = (column0.clone() - &oods_values[13].clone())
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[13].clone() * &value;

    value = (column0.clone() - &oods_values[14].clone())
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[14].clone() * &value;

    value = (column0.clone() - &oods_values[15].clone())
        .field_div(&(point.clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[15].clone() * &value;

    value = (column1.clone() - &oods_values[16].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[16].clone() * &value;

    value = (column1.clone() - &oods_values[17].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[17].clone() * &value;

    value = (column1.clone() - &oods_values[18].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[18].clone() * &value;

    value = (column1.clone() - &oods_values[19].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[19].clone() * &value;

    value = (column1.clone() - &oods_values[20].clone())
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[20].clone() * &value;

    value = (column2.clone() - &oods_values[21].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[21].clone() * &value;

    value = (column2.clone() - &oods_values[22].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[22].clone() * &value;

    value = (column2.clone() - &oods_values[23].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[23].clone() * &value;

    value = (column2.clone() - &oods_values[24].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[24].clone() * &value;

    value = (column3.clone() - &oods_values[25].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[25].clone() * &value;

    value = (column3.clone() - &oods_values[26].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[26].clone() * &value;

    value = (column3.clone() - &oods_values[27].clone())
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[27].clone() * &value;

    value = (column3.clone() - &oods_values[28].clone())
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[28].clone() * &value;

    value = (column3.clone() - &oods_values[29].clone())
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[29].clone() * &value;

    value = (column3.clone() - &oods_values[30].clone())
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[30].clone() * &value;

    value = (column3.clone() - &oods_values[31].clone())
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[31].clone() * &value;

    value = (column3.clone() - &oods_values[32].clone())
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[32].clone() * &value;

    value = (column3.clone() - &oods_values[33].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[33].clone() * &value;

    value = (column4.clone() - &oods_values[34].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[34].clone() * &value;

    value = (column4.clone() - &oods_values[35].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[35].clone() * &value;

    value = (column4.clone() - &oods_values[36].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[36].clone() * &value;

    value = (column4.clone() - &oods_values[37].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[37].clone() * &value;

    value = (column4.clone() - &oods_values[38].clone())
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[38].clone() * &value;

    value = (column5.clone() - &oods_values[39].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[39].clone() * &value;

    value = (column5.clone() - &oods_values[40].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[40].clone() * &value;

    value = (column5.clone() - &oods_values[41].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[41].clone() * &value;

    value = (column5.clone() - &oods_values[42].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[42].clone() * &value;

    value = (column6.clone() - &oods_values[43].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[43].clone() * &value;

    value = (column6.clone() - &oods_values[44].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[44].clone() * &value;

    value = (column6.clone() - &oods_values[45].clone())
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[45].clone() * &value;

    value = (column6.clone() - &oods_values[46].clone())
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[46].clone() * &value;

    value = (column6.clone() - &oods_values[47].clone())
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[47].clone() * &value;

    value = (column6.clone() - &oods_values[48].clone())
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[48].clone() * &value;

    value = (column6.clone() - &oods_values[49].clone())
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[49].clone() * &value;

    value = (column6.clone() - &oods_values[50].clone())
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[50].clone() * &value;

    value = (column6.clone() - &oods_values[51].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[51].clone() * &value;

    value = (column7.clone() - &oods_values[52].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[52].clone() * &value;

    value = (column7.clone() - &oods_values[53].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[53].clone() * &value;

    value = (column7.clone() - &oods_values[54].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[54].clone() * &value;

    value = (column7.clone() - &oods_values[55].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[55].clone() * &value;

    value = (column7.clone() - &oods_values[56].clone())
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[56].clone() * &value;

    value = (column8.clone() - &oods_values[57].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[57].clone() * &value;

    value = (column8.clone() - &oods_values[58].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[58].clone() * &value;

    value = (column8.clone() - &oods_values[59].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[59].clone() * &value;

    value = (column8.clone() - &oods_values[60].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[60].clone() * &value;

    value = (column9.clone() - &oods_values[61].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[61].clone() * &value;

    value = (column9.clone() - &oods_values[62].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[62].clone() * &value;

    value = (column9.clone() - &oods_values[63].clone())
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[63].clone() * &value;

    value = (column9.clone() - &oods_values[64].clone())
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[64].clone() * &value;

    value = (column9.clone() - &oods_values[65].clone())
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[65].clone() * &value;

    value = (column9.clone() - &oods_values[66].clone())
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[66].clone() * &value;

    value = (column9.clone() - &oods_values[67].clone())
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[67].clone() * &value;

    value = (column9.clone() - &oods_values[68].clone())
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[68].clone() * &value;

    value = (column9.clone() - &oods_values[69].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[69].clone() * &value;

    value = (column10.clone() - &oods_values[70].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[70].clone() * &value;

    value = (column10.clone() - &oods_values[71].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[71].clone() * &value;

    value = (column10.clone() - &oods_values[72].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[72].clone() * &value;

    value = (column10.clone() - &oods_values[73].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[73].clone() * &value;

    value = (column10.clone() - &oods_values[74].clone())
        .field_div(&(point.clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[74].clone() * &value;

    value = (column11.clone() - &oods_values[75].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[75].clone() * &value;

    value = (column11.clone() - &oods_values[76].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[76].clone() * &value;

    value = (column11.clone() - &oods_values[77].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[77].clone() * &value;

    value = (column11.clone() - &oods_values[78].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[78].clone() * &value;

    value = (column12.clone() - &oods_values[79].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[79].clone() * &value;

    value = (column12.clone() - &oods_values[80].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[80].clone() * &value;

    value = (column12.clone() - &oods_values[81].clone())
        .field_div(&(point.clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[81].clone() * &value;

    value = (column12.clone() - &oods_values[82].clone())
        .field_div(&(point.clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[82].clone() * &value;

    value = (column12.clone() - &oods_values[83].clone())
        .field_div(&(point.clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[83].clone() * &value;

    value = (column12.clone() - &oods_values[84].clone())
        .field_div(&(point.clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[84].clone() * &value;

    value = (column12.clone() - &oods_values[85].clone())
        .field_div(&(point.clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[85].clone() * &value;

    value = (column12.clone() - &oods_values[86].clone())
        .field_div(&(point.clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[86].clone() * &value;

    value = (column12.clone() - &oods_values[87].clone())
        .field_div(&(point.clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[87].clone() * &value;

    value = (column13.clone() - &oods_values[88].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[88].clone() * &value;

    value = (column13.clone() - &oods_values[89].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[89].clone() * &value;

    value = (column14.clone() - &oods_values[90].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[90].clone() * &value;

    value = (column14.clone() - &oods_values[91].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[91].clone() * &value;

    value = (column15.clone() - &oods_values[92].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[92].clone() * &value;

    value = (column15.clone() - &oods_values[93].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[93].clone() * &value;

    value = (column16.clone() - &oods_values[94].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[94].clone() * &value;

    value = (column16.clone() - &oods_values[95].clone())
        .field_div(&(point.clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[95].clone() * &value;

    value = (column17.clone() - &oods_values[96].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[96].clone() * &value;

    value = (column17.clone() - &oods_values[97].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[97].clone() * &value;

    value = (column17.clone() - &oods_values[98].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[98].clone() * &value;

    value = (column17.clone() - &oods_values[99].clone())
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[99].clone() * &value;

    value = (column17.clone() - &oods_values[100].clone())
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[100].clone() * &value;

    value = (column17.clone() - &oods_values[101].clone())
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[101].clone() * &value;

    value = (column17.clone() - &oods_values[102].clone())
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[102].clone() * &value;

    value = (column17.clone() - &oods_values[103].clone())
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[103].clone() * &value;

    value = (column17.clone() - &oods_values[104].clone())
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[104].clone() * &value;

    value = (column17.clone() - &oods_values[105].clone())
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[105].clone() * &value;

    value = (column17.clone() - &oods_values[106].clone())
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[106].clone() * &value;

    value = (column17.clone() - &oods_values[107].clone())
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[107].clone() * &value;

    value = (column17.clone() - &oods_values[108].clone())
        .field_div(&(point.clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[108].clone() * &value;

    value = (column17.clone() - &oods_values[109].clone())
        .field_div(&(point.clone() - pow25.clone() * oods_point));
    total_sum += constraint_coefficients[109].clone() * &value;

    value = (column17.clone() - &oods_values[110].clone())
        .field_div(&(point.clone() - pow26.clone() * oods_point));
    total_sum += constraint_coefficients[110].clone() * &value;

    value = (column17.clone() - &oods_values[111].clone())
        .field_div(&(point.clone() - pow34.clone() * oods_point));
    total_sum += constraint_coefficients[111].clone() * &value;

    value = (column17.clone() - &oods_values[112].clone())
        .field_div(&(point.clone() - pow35.clone() * oods_point));
    total_sum += constraint_coefficients[112].clone() * &value;

    value = (column17.clone() - &oods_values[113].clone())
        .field_div(&(point.clone() - pow40.clone() * oods_point));
    total_sum += constraint_coefficients[113].clone() * &value;

    value = (column17.clone() - &oods_values[114].clone())
        .field_div(&(point.clone() - pow41.clone() * oods_point));
    total_sum += constraint_coefficients[114].clone() * &value;

    value = (column17.clone() - &oods_values[115].clone())
        .field_div(&(point.clone() - pow45.clone() * oods_point));
    total_sum += constraint_coefficients[115].clone() * &value;

    value = (column17.clone() - &oods_values[116].clone())
        .field_div(&(point.clone() - pow46.clone() * oods_point));
    total_sum += constraint_coefficients[116].clone() * &value;

    value = (column17.clone() - &oods_values[117].clone())
        .field_div(&(point.clone() - pow49.clone() * oods_point));
    total_sum += constraint_coefficients[117].clone() * &value;

    value = (column17.clone() - &oods_values[118].clone())
        .field_div(&(point.clone() - pow50.clone() * oods_point));
    total_sum += constraint_coefficients[118].clone() * &value;

    value = (column17.clone() - &oods_values[119].clone())
        .field_div(&(point.clone() - pow52.clone() * oods_point));
    total_sum += constraint_coefficients[119].clone() * &value;

    value = (column17.clone() - &oods_values[120].clone())
        .field_div(&(point.clone() - pow58.clone() * oods_point));
    total_sum += constraint_coefficients[120].clone() * &value;

    value = (column17.clone() - &oods_values[121].clone())
        .field_div(&(point.clone() - pow59.clone() * oods_point));
    total_sum += constraint_coefficients[121].clone() * &value;

    value = (column17.clone() - &oods_values[122].clone())
        .field_div(&(point.clone() - pow79.clone() * oods_point));
    total_sum += constraint_coefficients[122].clone() * &value;

    value = (column17.clone() - &oods_values[123].clone())
        .field_div(&(point.clone() - pow78.clone() * oods_point));
    total_sum += constraint_coefficients[123].clone() * &value;

    value = (column17.clone() - &oods_values[124].clone())
        .field_div(&(point.clone() - pow77.clone() * oods_point));
    total_sum += constraint_coefficients[124].clone() * &value;

    value = (column17.clone() - &oods_values[125].clone())
        .field_div(&(point.clone() - pow76.clone() * oods_point));
    total_sum += constraint_coefficients[125].clone() * &value;

    value = (column17.clone() - &oods_values[126].clone())
        .field_div(&(point.clone() - pow75.clone() * oods_point));
    total_sum += constraint_coefficients[126].clone() * &value;

    value = (column17.clone() - &oods_values[127].clone())
        .field_div(&(point.clone() - pow80.clone() * oods_point));
    total_sum += constraint_coefficients[127].clone() * &value;

    value = (column17.clone() - &oods_values[128].clone())
        .field_div(&(point.clone() - pow69.clone() * oods_point));
    total_sum += constraint_coefficients[128].clone() * &value;

    value = (column17.clone() - &oods_values[129].clone())
        .field_div(&(point.clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[129].clone() * &value;

    value = (column17.clone() - &oods_values[130].clone())
        .field_div(&(point.clone() - pow68.clone() * oods_point));
    total_sum += constraint_coefficients[130].clone() * &value;

    value = (column18.clone() - &oods_values[131].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[131].clone() * &value;

    value = (column18.clone() - &oods_values[132].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[132].clone() * &value;

    value = (column18.clone() - &oods_values[133].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[133].clone() * &value;

    value = (column18.clone() - &oods_values[134].clone())
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[134].clone() * &value;

    value = (column19.clone() - &oods_values[135].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[135].clone() * &value;

    value = (column19.clone() - &oods_values[136].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[136].clone() * &value;

    value = (column19.clone() - &oods_values[137].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[137].clone() * &value;

    value = (column19.clone() - &oods_values[138].clone())
        .field_div(&(point.clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[138].clone() * &value;

    value = (column19.clone() - &oods_values[139].clone())
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[139].clone() * &value;

    value = (column19.clone() - &oods_values[140].clone())
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[140].clone() * &value;

    value = (column19.clone() - &oods_values[141].clone())
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[141].clone() * &value;

    value = (column19.clone() - &oods_values[142].clone())
        .field_div(&(point.clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[142].clone() * &value;

    value = (column19.clone() - &oods_values[143].clone())
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[143].clone() * &value;

    value = (column19.clone() - &oods_values[144].clone())
        .field_div(&(point.clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[144].clone() * &value;

    value = (column19.clone() - &oods_values[145].clone())
        .field_div(&(point.clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[145].clone() * &value;

    value = (column19.clone() - &oods_values[146].clone())
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[146].clone() * &value;

    value = (column19.clone() - &oods_values[147].clone())
        .field_div(&(point.clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[147].clone() * &value;

    value = (column19.clone() - &oods_values[148].clone())
        .field_div(&(point.clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[148].clone() * &value;

    value = (column19.clone() - &oods_values[149].clone())
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[149].clone() * &value;

    value = (column19.clone() - &oods_values[150].clone())
        .field_div(&(point.clone() - pow26.clone() * oods_point));
    total_sum += constraint_coefficients[150].clone() * &value;

    value = (column19.clone() - &oods_values[151].clone())
        .field_div(&(point.clone() - pow28.clone() * oods_point));
    total_sum += constraint_coefficients[151].clone() * &value;

    value = (column19.clone() - &oods_values[152].clone())
        .field_div(&(point.clone() - pow29.clone() * oods_point));
    total_sum += constraint_coefficients[152].clone() * &value;

    value = (column19.clone() - &oods_values[153].clone())
        .field_div(&(point.clone() - pow31.clone() * oods_point));
    total_sum += constraint_coefficients[153].clone() * &value;

    value = (column19.clone() - &oods_values[154].clone())
        .field_div(&(point.clone() - pow36.clone() * oods_point));
    total_sum += constraint_coefficients[154].clone() * &value;

    value = (column19.clone() - &oods_values[155].clone())
        .field_div(&(point.clone() - pow39.clone() * oods_point));
    total_sum += constraint_coefficients[155].clone() * &value;

    value = (column19.clone() - &oods_values[156].clone())
        .field_div(&(point.clone() - pow42.clone() * oods_point));
    total_sum += constraint_coefficients[156].clone() * &value;

    value = (column19.clone() - &oods_values[157].clone())
        .field_div(&(point.clone() - pow44.clone() * oods_point));
    total_sum += constraint_coefficients[157].clone() * &value;

    value = (column19.clone() - &oods_values[158].clone())
        .field_div(&(point.clone() - pow47.clone() * oods_point));
    total_sum += constraint_coefficients[158].clone() * &value;

    value = (column19.clone() - &oods_values[159].clone())
        .field_div(&(point.clone() - pow48.clone() * oods_point));
    total_sum += constraint_coefficients[159].clone() * &value;

    value = (column19.clone() - &oods_values[160].clone())
        .field_div(&(point.clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[160].clone() * &value;

    value = (column19.clone() - &oods_values[161].clone())
        .field_div(&(point.clone() - pow67.clone() * oods_point));
    total_sum += constraint_coefficients[161].clone() * &value;

    value = (column20.clone() - &oods_values[162].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[162].clone() * &value;

    value = (column20.clone() - &oods_values[163].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[163].clone() * &value;

    value = (column20.clone() - &oods_values[164].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[164].clone() * &value;

    value = (column20.clone() - &oods_values[165].clone())
        .field_div(&(point.clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[165].clone() * &value;

    value = (column20.clone() - &oods_values[166].clone())
        .field_div(&(point.clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[166].clone() * &value;

    value = (column20.clone() - &oods_values[167].clone())
        .field_div(&(point.clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[167].clone() * &value;

    value = (column20.clone() - &oods_values[168].clone())
        .field_div(&(point.clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[168].clone() * &value;

    value = (column20.clone() - &oods_values[169].clone())
        .field_div(&(point.clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[169].clone() * &value;

    value = (column20.clone() - &oods_values[170].clone())
        .field_div(&(point.clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[170].clone() * &value;

    value = (column20.clone() - &oods_values[171].clone())
        .field_div(&(point.clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[171].clone() * &value;

    value = (column20.clone() - &oods_values[172].clone())
        .field_div(&(point.clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[172].clone() * &value;

    value = (column20.clone() - &oods_values[173].clone())
        .field_div(&(point.clone() - pow24.clone() * oods_point));
    total_sum += constraint_coefficients[173].clone() * &value;

    value = (column20.clone() - &oods_values[174].clone())
        .field_div(&(point.clone() - pow25.clone() * oods_point));
    total_sum += constraint_coefficients[174].clone() * &value;

    value = (column20.clone() - &oods_values[175].clone())
        .field_div(&(point.clone() - pow27.clone() * oods_point));
    total_sum += constraint_coefficients[175].clone() * &value;

    value = (column20.clone() - &oods_values[176].clone())
        .field_div(&(point.clone() - pow30.clone() * oods_point));
    total_sum += constraint_coefficients[176].clone() * &value;

    value = (column20.clone() - &oods_values[177].clone())
        .field_div(&(point.clone() - pow34.clone() * oods_point));
    total_sum += constraint_coefficients[177].clone() * &value;

    value = (column20.clone() - &oods_values[178].clone())
        .field_div(&(point.clone() - pow37.clone() * oods_point));
    total_sum += constraint_coefficients[178].clone() * &value;

    value = (column20.clone() - &oods_values[179].clone())
        .field_div(&(point.clone() - pow38.clone() * oods_point));
    total_sum += constraint_coefficients[179].clone() * &value;

    value = (column20.clone() - &oods_values[180].clone())
        .field_div(&(point.clone() - pow43.clone() * oods_point));
    total_sum += constraint_coefficients[180].clone() * &value;

    value = (column20.clone() - &oods_values[181].clone())
        .field_div(&(point.clone() - pow51.clone() * oods_point));
    total_sum += constraint_coefficients[181].clone() * &value;

    value = (column20.clone() - &oods_values[182].clone())
        .field_div(&(point.clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[182].clone() * &value;

    value = (column20.clone() - &oods_values[183].clone())
        .field_div(&(point.clone() - pow2.clone() * oods_point));
    total_sum += constraint_coefficients[183].clone() * &value;

    value = (column20.clone() - &oods_values[184].clone())
        .field_div(&(point.clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[184].clone() * &value;

    value = (column20.clone() - &oods_values[185].clone())
        .field_div(&(point.clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[185].clone() * &value;

    value = (column20.clone() - &oods_values[186].clone())
        .field_div(&(point.clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[186].clone() * &value;

    value = (column20.clone() - &oods_values[187].clone())
        .field_div(&(point.clone() - pow61.clone() * oods_point));
    total_sum += constraint_coefficients[187].clone() * &value;

    value = (column20.clone() - &oods_values[188].clone())
        .field_div(&(point.clone() - pow1.clone() * oods_point));
    total_sum += constraint_coefficients[188].clone() * &value;

    value = (column20.clone() - &oods_values[189].clone())
        .field_div(&(point.clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[189].clone() * &value;

    value = (column20.clone() - &oods_values[190].clone())
        .field_div(&(point.clone() - pow32.clone() * oods_point));
    total_sum += constraint_coefficients[190].clone() * &value;

    value = (column20.clone() - &oods_values[191].clone())
        .field_div(&(point.clone() - pow33.clone() * oods_point));
    total_sum += constraint_coefficients[191].clone() * &value;

    value = (column20.clone() - &oods_values[192].clone())
        .field_div(&(point.clone() - pow62.clone() * oods_point));
    total_sum += constraint_coefficients[192].clone() * &value;

    value = (column20.clone() - &oods_values[193].clone())
        .field_div(&(point.clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[193].clone() * &value;

    value = (column20.clone() - &oods_values[194].clone())
        .field_div(&(point.clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[194].clone() * &value;

    value = (column20.clone() - &oods_values[195].clone())
        .field_div(&(point.clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[195].clone() * &value;

    value = (column21.clone() - &oods_values[196].clone())
        .field_div(&(point.clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[196].clone() * &value;

    value = (column21.clone() - &oods_values[197].clone())
        .field_div(&(point.clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[197].clone() * &value;

    value = (column21.clone() - &oods_values[198].clone())
        .field_div(&(point.clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[198].clone() * &value;

    value = (column21.clone() - &oods_values[199].clone())
        .field_div(&(point.clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[199].clone() * &value;

    // Sum the OODS boundary constraints on the composition polynomials.
    let oods_point_to_deg = oods_point.powers([Layout::CONSTRAINT_DEGREE as u64]);

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND]
       .clone() - &oods_values[200].clone())
        .field_div(&(point.clone() - oods_point_to_deg.clone()));
    total_sum += constraint_coefficients[200].clone() * &value;

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND.clone() + &1]
       .clone() - &oods_values[201].clone())
        .field_div(&(point.clone() - oods_point_to_deg));
    total_sum += constraint_coefficients[201].clone() * &value;

    total_sum
}
