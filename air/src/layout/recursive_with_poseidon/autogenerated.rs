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
        &global_values.trace_length.rsh(12),
    );
    let pow1 = pow0.clone() * &pow0; // pow(point, (safe_div(global_values.trace_length, 2048))).
    let pow2 = pow1.clone() * &pow1; // pow(point, (safe_div(global_values.trace_length, 1024))).
    let pow3 = pow2.clone() * &pow2; // pow(point, (safe_div(global_values.trace_length, 512))).
    let pow4 = pow3.clone() * &pow3; // pow(point, (safe_div(global_values.trace_length, 256))).
    let pow5 = pow4.clone() * &pow4; // pow(point, (safe_div(global_values.trace_length, 128))).
    let pow6 = pow5.clone() * &pow5; // pow(point, (safe_div(global_values.trace_length, 64))).
    let pow7 = pow6.clone() * &pow6; // pow(point, (safe_div(global_values.trace_length, 32))).
    let pow8 = pow7.clone() * &pow7; // pow(point, (safe_div(global_values.trace_length, 16))).
    let pow9 = pow8.clone() * &pow8; // pow(point, (safe_div(global_values.trace_length, 8))).
    let pow10 = pow9.clone() * &pow9; // pow(point, (safe_div(global_values.trace_length, 4))).
    let pow11 = pow10.clone() * &pow10; // pow(point, (safe_div(global_values.trace_length, 2))).
    let pow12 = pow11.clone() * &pow11; // pow(point, global_values.trace_length).
    let pow13 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(512 as u64)));
    let pow14 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(256 as u64)));
    let pow15 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(4096 as u64)));
    let pow16 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(4   as u64)));
    let pow17 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(2   as u64)));
    let pow18 = trace_generator.powers_felt(&(global_values.trace_length.clone() - &F::from_constant(16  as u64)));
    let pow19 = trace_generator.powers_felt(
        &(global_values.trace_length.rsh(1)),
    );
    let pow20 = trace_generator.powers_felt(
        &(F::from_constant(255 as u64)
           .clone() * &global_values
                .trace_length
                .rsh(8)),
    );
    let pow21 = trace_generator.powers_felt(
        &(global_values.trace_length.rsh(6)),
    );
    let pow22 = pow21.clone() * &pow21; // pow(trace_generator, (safe_div(global_values.trace_length, 32))).
    let pow23 = pow21.clone() * &pow22; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 64))).
    let pow24 = pow21.clone() * &pow23; // pow(trace_generator, (safe_div(global_values.trace_length, 16))).
    let pow25 = pow21.clone() * &pow24; // pow(trace_generator, (safe_div((safe_mult(5, global_values.trace_length)), 64))).
    let pow26 = pow21.clone() * &pow25; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 32))).
    let pow27 = pow19.clone() * &pow26; // pow(trace_generator, (safe_div((safe_mult(19, global_values.trace_length)), 32))).
    let pow28 = pow21.clone() * &pow26; // pow(trace_generator, (safe_div((safe_mult(7, global_values.trace_length)), 64))).
    let pow29 = pow21.clone() * &pow28; // pow(trace_generator, (safe_div(global_values.trace_length, 8))).
    let pow30 = pow19.clone() * &pow29; // pow(trace_generator, (safe_div((safe_mult(5, global_values.trace_length)), 8))).
    let pow31 = pow21.clone() * &pow29; // pow(trace_generator, (safe_div((safe_mult(9, global_values.trace_length)), 64))).
    let pow32 = pow21.clone() * &pow31; // pow(trace_generator, (safe_div((safe_mult(5, global_values.trace_length)), 32))).
    let pow33 = pow19.clone() * &pow32; // pow(trace_generator, (safe_div((safe_mult(21, global_values.trace_length)), 32))).
    let pow34 = pow21.clone() * &pow32; // pow(trace_generator, (safe_div((safe_mult(11, global_values.trace_length)), 64))).
    let pow35 = pow21.clone() * &pow34; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 16))).
    let pow36 = pow19.clone() * &pow35; // pow(trace_generator, (safe_div((safe_mult(11, global_values.trace_length)), 16))).
    let pow37 = pow21.clone() * &pow35; // pow(trace_generator, (safe_div((safe_mult(13, global_values.trace_length)), 64))).
    let pow38 = pow21.clone() * &pow37; // pow(trace_generator, (safe_div((safe_mult(7, global_values.trace_length)), 32))).
    let pow39 = pow19.clone() * &pow38; // pow(trace_generator, (safe_div((safe_mult(23, global_values.trace_length)), 32))).
    let pow40 = pow21.clone() * &pow38; // pow(trace_generator, (safe_div((safe_mult(15, global_values.trace_length)), 64))).
    let pow41 = pow22.clone() * &pow39; // pow(trace_generator, (safe_div((safe_mult(3, global_values.trace_length)), 4))).
    let pow42 = pow22.clone() * &pow41; // pow(trace_generator, (safe_div((safe_mult(25, global_values.trace_length)), 32))).
    let pow43 = pow22.clone() * &pow42; // pow(trace_generator, (safe_div((safe_mult(13, global_values.trace_length)), 16))).
    let pow44 = pow22.clone() * &pow43; // pow(trace_generator, (safe_div((safe_mult(27, global_values.trace_length)), 32))).
    let pow45 = pow22.clone() * &pow44; // pow(trace_generator, (safe_div((safe_mult(7, global_values.trace_length)), 8))).
    let pow46 = pow22.clone() * &pow45; // pow(trace_generator, (safe_div((safe_mult(29, global_values.trace_length)), 32))).
    let pow47 = pow22.clone() * &pow46; // pow(trace_generator, (safe_div((safe_mult(15, global_values.trace_length)), 16))).
    let pow48 = pow21.clone() * &pow47; // pow(trace_generator, (safe_div((safe_mult(61, global_values.trace_length)), 64))).
    let pow49 = pow21.clone() * &pow48; // pow(trace_generator, (safe_div((safe_mult(31, global_values.trace_length)), 32))).
    let pow50 = pow21.clone() * &pow49; // pow(trace_generator, (safe_div((safe_mult(63, global_values.trace_length)), 64))).

    // Compute domains.
    let domain0 = pow12.clone() - &F::one();
    let domain1 = pow11.clone() - &F::one();
    let domain2 = pow10.clone() - &F::one();
    let domain3 = pow9.clone() - &F::one();
    let domain4 = pow8.clone() - &pow47;
    let domain5 = pow8.clone() - &F::one();
    let domain6 = pow7.clone() - &F::one();
    let domain7 = pow6.clone() - &F::one();
    let domain8 = pow5.clone() - &F::one();
    let domain9 = pow4.clone() - &F::one();
    let domain10 = pow4.clone() - &pow41;
    let temp = pow4.clone() - &pow21;
    let temp = temp * (pow4.clone() - &pow22);
    let temp = temp * (pow4.clone() - &pow23);
    let temp = temp * (pow4.clone() - &pow24);
    let temp = temp * (pow4.clone() - &pow25);
    let temp = temp * (pow4.clone() - &pow26);
    let temp = temp * (pow4.clone() - &pow28);
    let temp = temp * (pow4.clone() - &pow29);
    let temp = temp * (pow4.clone() - &pow31);
    let temp = temp * (pow4.clone() - &pow32);
    let temp = temp * (pow4.clone() - &pow34);
    let temp = temp * (pow4.clone() - &pow35);
    let temp = temp * (pow4.clone() - &pow37);
    let temp = temp * (pow4.clone() - &pow38);
    let temp = temp * (pow4.clone() - &pow40);
    let domain11 = temp * &(domain9);
    let domain12 = pow3.clone() - &F::one();
    let domain13 = pow3.clone() - &pow41;
    let domain14 = pow2.clone() - &pow49;
    let temp = pow2.clone() - &pow36;
    let temp = temp * (pow2.clone() - &pow39);
    let temp = temp * (pow2.clone() - &pow41);
    let temp = temp * (pow2.clone() - &pow42);
    let temp = temp * (pow2.clone() - &pow43);
    let temp = temp * (pow2.clone() - &pow44);
    let temp = temp * (pow2.clone() - &pow45);
    let temp = temp * (pow2.clone() - &pow46);
    let temp = temp * (pow2.clone() - &pow47);
    let domain15 = temp * &(domain14);
    let domain16 = pow2.clone() - &F::one();
    let temp = pow2.clone() - &pow48;
    let temp = temp * (pow2.clone() - &pow50);
    let domain17 = temp * &(domain14);
    let temp = pow2.clone() - &pow27;
    let temp = temp * (pow2.clone() - &pow30);
    let temp = temp * (pow2.clone() - &pow33);
    let domain18 = temp * &(domain15);
    let domain19 = pow1.clone() - &F::one();
    let domain20 = pow1.clone() - &pow20;
    let domain21 = pow1.clone() - &pow50;
    let domain22 = pow0.clone() - &pow19;
    let domain23 = pow0.clone() - &F::one();
    let domain24 = point.clone() - &pow18;
    let domain25 = point.clone() - &F::one();
    let domain26 = point.clone() - &pow17;
    let domain27 = point.clone() - &pow16;
    let domain28 = point.clone() - &pow15;
    let domain29 = point.clone() - &pow14;
    let domain30 = point.clone() - &pow13;

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
    let column1_row3 = mask_values[19].clone();
    let column1_row4 = mask_values[20].clone();
    let column1_row5 = mask_values[21].clone();
    let column1_row8 = mask_values[22].clone();
    let column1_row9 = mask_values[23].clone();
    let column1_row10 = mask_values[24].clone();
    let column1_row11 = mask_values[25].clone();
    let column1_row12 = mask_values[26].clone();
    let column1_row13 = mask_values[27].clone();
    let column1_row16 = mask_values[28].clone();
    let column1_row42 = mask_values[29].clone();
    let column1_row43 = mask_values[30].clone();
    let column1_row74 = mask_values[31].clone();
    let column1_row75 = mask_values[32].clone();
    let column1_row106 = mask_values[33].clone();
    let column1_row138 = mask_values[34].clone();
    let column1_row139 = mask_values[35].clone();
    let column1_row171 = mask_values[36].clone();
    let column1_row202 = mask_values[37].clone();
    let column1_row203 = mask_values[38].clone();
    let column1_row234 = mask_values[39].clone();
    let column1_row235 = mask_values[40].clone();
    let column1_row266 = mask_values[41].clone();
    let column1_row267 = mask_values[42].clone();
    let column1_row298 = mask_values[43].clone();
    let column1_row394 = mask_values[44].clone();
    let column1_row458 = mask_values[45].clone();
    let column1_row459 = mask_values[46].clone();
    let column1_row714 = mask_values[47].clone();
    let column1_row715 = mask_values[48].clone();
    let column1_row778 = mask_values[49].clone();
    let column1_row779 = mask_values[50].clone();
    let column1_row970 = mask_values[51].clone();
    let column1_row971 = mask_values[52].clone();
    let column1_row1034 = mask_values[53].clone();
    let column1_row1035 = mask_values[54].clone();
    let column1_row2058 = mask_values[55].clone();
    let column1_row2059 = mask_values[56].clone();
    let column1_row4106 = mask_values[57].clone();
    let column2_row0 = mask_values[58].clone();
    let column2_row1 = mask_values[59].clone();
    let column2_row2 = mask_values[60].clone();
    let column2_row3 = mask_values[61].clone();
    let column3_row0 = mask_values[62].clone();
    let column3_row1 = mask_values[63].clone();
    let column3_row2 = mask_values[64].clone();
    let column3_row3 = mask_values[65].clone();
    let column3_row4 = mask_values[66].clone();
    let column3_row8 = mask_values[67].clone();
    let column3_row12 = mask_values[68].clone();
    let column3_row16 = mask_values[69].clone();
    let column3_row20 = mask_values[70].clone();
    let column3_row24 = mask_values[71].clone();
    let column3_row28 = mask_values[72].clone();
    let column3_row32 = mask_values[73].clone();
    let column3_row36 = mask_values[74].clone();
    let column3_row40 = mask_values[75].clone();
    let column3_row44 = mask_values[76].clone();
    let column3_row48 = mask_values[77].clone();
    let column3_row52 = mask_values[78].clone();
    let column3_row56 = mask_values[79].clone();
    let column3_row60 = mask_values[80].clone();
    let column3_row64 = mask_values[81].clone();
    let column3_row66 = mask_values[82].clone();
    let column3_row128 = mask_values[83].clone();
    let column3_row130 = mask_values[84].clone();
    let column3_row176 = mask_values[85].clone();
    let column3_row180 = mask_values[86].clone();
    let column3_row184 = mask_values[87].clone();
    let column3_row188 = mask_values[88].clone();
    let column3_row192 = mask_values[89].clone();
    let column3_row194 = mask_values[90].clone();
    let column3_row240 = mask_values[91].clone();
    let column3_row244 = mask_values[92].clone();
    let column3_row248 = mask_values[93].clone();
    let column3_row252 = mask_values[94].clone();
    let column4_row0 = mask_values[95].clone();
    let column4_row1 = mask_values[96].clone();
    let column4_row2 = mask_values[97].clone();
    let column4_row3 = mask_values[98].clone();
    let column4_row4 = mask_values[99].clone();
    let column4_row5 = mask_values[100].clone();
    let column4_row6 = mask_values[101].clone();
    let column4_row7 = mask_values[102].clone();
    let column4_row8 = mask_values[103].clone();
    let column4_row9 = mask_values[104].clone();
    let column4_row11 = mask_values[105].clone();
    let column4_row12 = mask_values[106].clone();
    let column4_row13 = mask_values[107].clone();
    let column4_row44 = mask_values[108].clone();
    let column4_row76 = mask_values[109].clone();
    let column4_row108 = mask_values[110].clone();
    let column4_row140 = mask_values[111].clone();
    let column4_row172 = mask_values[112].clone();
    let column4_row204 = mask_values[113].clone();
    let column4_row236 = mask_values[114].clone();
    let column4_row1539 = mask_values[115].clone();
    let column4_row1547 = mask_values[116].clone();
    let column4_row1571 = mask_values[117].clone();
    let column4_row1579 = mask_values[118].clone();
    let column4_row2011 = mask_values[119].clone();
    let column4_row2019 = mask_values[120].clone();
    let column4_row2041 = mask_values[121].clone();
    let column4_row2045 = mask_values[122].clone();
    let column4_row2047 = mask_values[123].clone();
    let column4_row2049 = mask_values[124].clone();
    let column4_row2051 = mask_values[125].clone();
    let column4_row2053 = mask_values[126].clone();
    let column4_row4089 = mask_values[127].clone();
    let column5_row0 = mask_values[128].clone();
    let column5_row1 = mask_values[129].clone();
    let column5_row2 = mask_values[130].clone();
    let column5_row4 = mask_values[131].clone();
    let column5_row6 = mask_values[132].clone();
    let column5_row8 = mask_values[133].clone();
    let column5_row9 = mask_values[134].clone();
    let column5_row10 = mask_values[135].clone();
    let column5_row12 = mask_values[136].clone();
    let column5_row14 = mask_values[137].clone();
    let column5_row16 = mask_values[138].clone();
    let column5_row17 = mask_values[139].clone();
    let column5_row22 = mask_values[140].clone();
    let column5_row24 = mask_values[141].clone();
    let column5_row25 = mask_values[142].clone();
    let column5_row30 = mask_values[143].clone();
    let column5_row33 = mask_values[144].clone();
    let column5_row38 = mask_values[145].clone();
    let column5_row41 = mask_values[146].clone();
    let column5_row46 = mask_values[147].clone();
    let column5_row49 = mask_values[148].clone();
    let column5_row54 = mask_values[149].clone();
    let column5_row57 = mask_values[150].clone();
    let column5_row65 = mask_values[151].clone();
    let column5_row73 = mask_values[152].clone();
    let column5_row81 = mask_values[153].clone();
    let column5_row89 = mask_values[154].clone();
    let column5_row97 = mask_values[155].clone();
    let column5_row105 = mask_values[156].clone();
    let column5_row137 = mask_values[157].clone();
    let column5_row169 = mask_values[158].clone();
    let column5_row201 = mask_values[159].clone();
    let column5_row393 = mask_values[160].clone();
    let column5_row409 = mask_values[161].clone();
    let column5_row425 = mask_values[162].clone();
    let column5_row457 = mask_values[163].clone();
    let column5_row473 = mask_values[164].clone();
    let column5_row489 = mask_values[165].clone();
    let column5_row521 = mask_values[166].clone();
    let column5_row553 = mask_values[167].clone();
    let column5_row585 = mask_values[168].clone();
    let column5_row609 = mask_values[169].clone();
    let column5_row625 = mask_values[170].clone();
    let column5_row641 = mask_values[171].clone();
    let column5_row657 = mask_values[172].clone();
    let column5_row673 = mask_values[173].clone();
    let column5_row689 = mask_values[174].clone();
    let column5_row905 = mask_values[175].clone();
    let column5_row921 = mask_values[176].clone();
    let column5_row937 = mask_values[177].clone();
    let column5_row969 = mask_values[178].clone();
    let column5_row982 = mask_values[179].clone();
    let column5_row985 = mask_values[180].clone();
    let column5_row998 = mask_values[181].clone();
    let column5_row1001 = mask_values[182].clone();
    let column5_row1014 = mask_values[183].clone();
    let column6_inter1_row0 = mask_values[184].clone();
    let column6_inter1_row1 = mask_values[185].clone();
    let column6_inter1_row2 = mask_values[186].clone();
    let column6_inter1_row3 = mask_values[187].clone();
    let column7_inter1_row0 = mask_values[188].clone();
    let column7_inter1_row1 = mask_values[189].clone();
    let column7_inter1_row2 = mask_values[190].clone();
    let column7_inter1_row5 = mask_values[191].clone();

    // Compute intermediate values.
    let cpu_decode_opcode_range_check_bit_0 = column0_row0.clone() - &(column0_row1.clone() + &column0_row1);
    let cpu_decode_opcode_range_check_bit_2 = column0_row2.clone() - &(column0_row3.clone() + &column0_row3);
    let cpu_decode_opcode_range_check_bit_4 = column0_row4.clone() - &(column0_row5.clone() + &column0_row5);
    let cpu_decode_opcode_range_check_bit_3 = column0_row3.clone() - &(column0_row4.clone() + &column0_row4);
    let cpu_decode_flag_op1_base_op0_0 = F::one()
       .clone() - &(cpu_decode_opcode_range_check_bit_2
           .clone() + &cpu_decode_opcode_range_check_bit_4
           .clone() + &cpu_decode_opcode_range_check_bit_3);
    let cpu_decode_opcode_range_check_bit_5 = column0_row5.clone() - &(column0_row6.clone() + &column0_row6);
    let cpu_decode_opcode_range_check_bit_6 = column0_row6.clone() - &(column0_row7.clone() + &column0_row7);
    let cpu_decode_opcode_range_check_bit_9 = column0_row9.clone() - &(column0_row10.clone() + &column0_row10);
    let cpu_decode_flag_res_op1_0 = F::one()
       .clone() - &(cpu_decode_opcode_range_check_bit_5
           .clone() + &cpu_decode_opcode_range_check_bit_6
           .clone() + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_7 = column0_row7.clone() - &(column0_row8.clone() + &column0_row8);
    let cpu_decode_opcode_range_check_bit_8 = column0_row8.clone() - &(column0_row9.clone() + &column0_row9);
    let cpu_decode_flag_pc_update_regular_0 = F::one()
       .clone() - &(cpu_decode_opcode_range_check_bit_7
           .clone() + &cpu_decode_opcode_range_check_bit_8
           .clone() + &cpu_decode_opcode_range_check_bit_9);
    let cpu_decode_opcode_range_check_bit_12 = column0_row12.clone() - &(column0_row13.clone() + &column0_row13);
    let cpu_decode_opcode_range_check_bit_13 = column0_row13.clone() - &(column0_row14.clone() + &column0_row14);
    let cpu_decode_fp_update_regular_0 =
        F::one().clone() - &(cpu_decode_opcode_range_check_bit_12.clone().clone() + &cpu_decode_opcode_range_check_bit_13.clone());
    let cpu_decode_opcode_range_check_bit_1 = column0_row1.clone() - &(column0_row2.clone() + &column0_row2);
    let npc_reg_0 = column1_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one();
    let cpu_decode_opcode_range_check_bit_10 = column0_row10.clone() - &(column0_row11.clone() + &column0_row11);
    let cpu_decode_opcode_range_check_bit_11 = column0_row11.clone() - &(column0_row12.clone() + &column0_row12);
    let cpu_decode_opcode_range_check_bit_14 = column0_row14.clone() - &(column0_row15.clone() + &column0_row15);
    let memory_address_diff_0 = column2_row2.clone() - &column2_row0;
    let range_check16_diff_0 = column4_row6.clone() - &column4_row2;
    let pedersen_hash0_ec_subset_sum_bit_0 = column4_row3.clone() - &(column4_row11.clone() + &column4_row11);
    let pedersen_hash0_ec_subset_sum_bit_neg_0 = F::one().clone() - &pedersen_hash0_ec_subset_sum_bit_0;
    let range_check_builtin_value0_0 = column4_row12;
    let range_check_builtin_value1_0 =
        range_check_builtin_value0_0.clone() * global_values.offset_size.clone() + &column4_row44;
    let range_check_builtin_value2_0 =
        range_check_builtin_value1_0.clone() * global_values.offset_size.clone() + &column4_row76;
    let range_check_builtin_value3_0 =
        range_check_builtin_value2_0.clone() * global_values.offset_size.clone() + &column4_row108;
    let range_check_builtin_value4_0 =
        range_check_builtin_value3_0.clone() * global_values.offset_size.clone() + &column4_row140;
    let range_check_builtin_value5_0 =
        range_check_builtin_value4_0.clone() * global_values.offset_size.clone() + &column4_row172;
    let range_check_builtin_value6_0 =
        range_check_builtin_value5_0.clone() * global_values.offset_size.clone() + &column4_row204;
    let range_check_builtin_value7_0 =
        range_check_builtin_value6_0.clone() * global_values.offset_size.clone() + &column4_row236;
    let bitwise_sum_var_0_0 = column3_row0
       .clone() + column3_row4.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x2"))
       .clone() + column3_row8.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x4"))
       .clone() + column3_row12.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x8"))
       .clone() + column3_row16.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x10000000000000000"))
       .clone() + column3_row20.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x20000000000000000"))
       .clone() + column3_row24.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000000"))
       .clone() + column3_row28.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x80000000000000000"));
    let bitwise_sum_var_8_0 = column3_row32
       .clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x100000000000000000000000000000000"))
       .clone() + column3_row36.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x200000000000000000000000000000000"))
       .clone() + column3_row40.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x400000000000000000000000000000000"))
       .clone() + column3_row44.clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000"))
       .clone() + column3_row48
           .clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x1000000000000000000000000000000000000000000000000"))
       .clone() + column3_row52
           .clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x2000000000000000000000000000000000000000000000000"))
       .clone() + column3_row56
           .clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x4000000000000000000000000000000000000000000000000"))
       .clone() + column3_row60
           .clone() * &F::from_stark_felt(Felt::from_hex_unchecked("0x8000000000000000000000000000000000000000000000000"));
    let poseidon_poseidon_full_rounds_state0_cubed_0 = column5_row9.clone() * &column5_row105;
    let poseidon_poseidon_full_rounds_state1_cubed_0 = column5_row73.clone() * &column5_row25;
    let poseidon_poseidon_full_rounds_state2_cubed_0 = column5_row41.clone() * &column5_row89;
    let poseidon_poseidon_full_rounds_state0_cubed_7 = column5_row905.clone() * &column5_row1001;
    let poseidon_poseidon_full_rounds_state1_cubed_7 = column5_row969.clone() * &column5_row921;
    let poseidon_poseidon_full_rounds_state2_cubed_7 = column5_row937.clone() * &column5_row985;
    let poseidon_poseidon_full_rounds_state0_cubed_3 = column5_row393.clone() * &column5_row489;
    let poseidon_poseidon_full_rounds_state1_cubed_3 = column5_row457.clone() * &column5_row409;
    let poseidon_poseidon_full_rounds_state2_cubed_3 = column5_row425.clone() * &column5_row473;
    let poseidon_poseidon_partial_rounds_state0_cubed_0 = column5_row6.clone() * &column5_row14;
    let poseidon_poseidon_partial_rounds_state0_cubed_1 = column5_row22.clone() * &column5_row30;
    let poseidon_poseidon_partial_rounds_state0_cubed_2 = column5_row38.clone() * &column5_row46;
    let poseidon_poseidon_partial_rounds_state1_cubed_0 = column5_row1.clone() * &column5_row17;
    let poseidon_poseidon_partial_rounds_state1_cubed_1 = column5_row33.clone() * &column5_row49;
    let poseidon_poseidon_partial_rounds_state1_cubed_2 = column5_row65.clone() * &column5_row81;
    let poseidon_poseidon_partial_rounds_state1_cubed_19 = column5_row609.clone() * &column5_row625;
    let poseidon_poseidon_partial_rounds_state1_cubed_20 = column5_row641.clone() * &column5_row657;
    let poseidon_poseidon_partial_rounds_state1_cubed_21 = column5_row673.clone() * &column5_row689;

    // Sum constraints.
    let mut total_sum = F::zero();

    // Constraint: cpu/decode/opcode_range_check/bit.
    let mut value = (cpu_decode_opcode_range_check_bit_0.clone() * &cpu_decode_opcode_range_check_bit_0
       .clone() - &cpu_decode_opcode_range_check_bit_0)
       .clone() * &domain4.field_div(&(domain0));
    total_sum += constraint_coefficients[0].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check/zero.
    value = (column0_row0).field_div(&(domain4));
    total_sum += constraint_coefficients[1].clone() * &value;

    // Constraint: cpu/decode/opcode_range_check_input.
    value = (column1_row1
       .clone() - &(((column0_row0.clone() * global_values.offset_size.clone() + &column4_row4)
           .clone() * &global_values.offset_size
           .clone() + &column4_row8)
           .clone() * &global_values.offset_size
           .clone() + &column4_row0))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[2].clone() * &value;

    // Constraint: cpu/decode/flag_op1_base_op0_bit.
    value = (cpu_decode_flag_op1_base_op0_0.clone() * &cpu_decode_flag_op1_base_op0_0
       .clone() - &cpu_decode_flag_op1_base_op0_0)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[3].clone() * &value;

    // Constraint: cpu/decode/flag_res_op1_bit.
    value = (cpu_decode_flag_res_op1_0.clone() * cpu_decode_flag_res_op1_0.clone() - &cpu_decode_flag_res_op1_0)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[4].clone() * &value;

    // Constraint: cpu/decode/flag_pc_update_regular_bit.
    value = (cpu_decode_flag_pc_update_regular_0.clone() * &cpu_decode_flag_pc_update_regular_0
       .clone() - &cpu_decode_flag_pc_update_regular_0)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[5].clone() * &value;

    // Constraint: cpu/decode/fp_update_regular_bit.
    value = (cpu_decode_fp_update_regular_0.clone() * &cpu_decode_fp_update_regular_0
       .clone() - &cpu_decode_fp_update_regular_0)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[6].clone() * &value;

    // Constraint: cpu/operands/mem_dst_addr.
    value = (column1_row8.clone() + &global_values.half_offset_size
       .clone() - &(cpu_decode_opcode_range_check_bit_0.clone() * &column5_row8
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_0).clone() * &column5_row0
           .clone() + &column4_row0))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[7].clone() * &value;

    // Constraint: cpu/operands/mem0_addr.
    value = (column1_row4.clone() + &global_values.half_offset_size
       .clone() - &(cpu_decode_opcode_range_check_bit_1.clone() * &column5_row8
            + (F::one().clone() - &cpu_decode_opcode_range_check_bit_1).clone() * &column5_row0
           .clone() + &column4_row8))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[8].clone() * &value;

    // Constraint: cpu/operands/mem1_addr.
    value = (column1_row12.clone() + &global_values.half_offset_size
       .clone() - &(cpu_decode_opcode_range_check_bit_2.clone() * &column1_row0
           .clone() + cpu_decode_opcode_range_check_bit_4.clone() * &column5_row0
           .clone() + cpu_decode_opcode_range_check_bit_3.clone() * &column5_row8
           .clone() + cpu_decode_flag_op1_base_op0_0.clone() * &column1_row5
           .clone() + &column4_row4))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[9].clone() * &value;

    // Constraint: cpu/operands/ops_mul.
    value = (column5_row4.clone().clone() - column1_row5.clone() * &column1_row13)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[10].clone() * &value;

    // Constraint: cpu/operands/res.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone() * &column5_row12
       .clone() - &(cpu_decode_opcode_range_check_bit_5 * (column1_row5.clone() + &column1_row13)
           .clone() + cpu_decode_opcode_range_check_bit_6.clone() * &column5_row4
           .clone() + cpu_decode_flag_res_op1_0.clone() * &column1_row13))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[11].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp0.
    value = (column5_row2.clone().clone() - cpu_decode_opcode_range_check_bit_9.clone() * &column1_row9)
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[12].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/tmp1.
    value = (column5_row10.clone().clone() - column5_row2.clone() * &column5_row12)
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[13].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_negative.
    value = ((F::one().clone() - &cpu_decode_opcode_range_check_bit_9).clone() * &column1_row16
       .clone() + column5_row2 * (column1_row16.clone() - &(column1_row0.clone() + &column1_row13))
       .clone() - &(cpu_decode_flag_pc_update_regular_0.clone() * &npc_reg_0
           .clone() + cpu_decode_opcode_range_check_bit_7.clone() * &column5_row12
           .clone() + cpu_decode_opcode_range_check_bit_8 * (column1_row0.clone() + &column5_row12)))
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[14].clone() * &value;

    // Constraint: cpu/update_registers/update_pc/pc_cond_positive.
    value = ((column5_row10.clone() - &cpu_decode_opcode_range_check_bit_9) * (column1_row16.clone() - &npc_reg_0))
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[15].clone() * &value;

    // Constraint: cpu/update_registers/update_ap/ap_update.
    value = (column5_row16
       .clone() - &(column5_row0
           .clone() + cpu_decode_opcode_range_check_bit_10.clone() * &column5_row12
           .clone() + &cpu_decode_opcode_range_check_bit_11
           .clone() + cpu_decode_opcode_range_check_bit_12.clone().clone() * &F::two()))
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[16].clone() * &value;

    // Constraint: cpu/update_registers/update_fp/fp_update.
    value = (column5_row24
       .clone() - &(cpu_decode_fp_update_regular_0.clone() * &column5_row8
           .clone() + cpu_decode_opcode_range_check_bit_13.clone().clone() * &column1_row9
           .clone() + cpu_decode_opcode_range_check_bit_12.clone().clone() * (column5_row0.clone() + &F::two())))
       .clone() * &domain24.field_div(&(domain5));
    total_sum += constraint_coefficients[17].clone() * &value;

    // Constraint: cpu/opcodes/call/push_fp.
    value = (cpu_decode_opcode_range_check_bit_12.clone() * (column1_row9.clone() - &column5_row8))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[18].clone() * &value;

    // Constraint: cpu/opcodes/call/push_pc.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column1_row5.clone() - &(column1_row0.clone() + cpu_decode_opcode_range_check_bit_2.clone() + &F::one())))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[19].clone() * &value;

    // Constraint: cpu/opcodes/call/off0.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column4_row0.clone() - &global_values.half_offset_size))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[20].clone() * &value;

    // Constraint: cpu/opcodes/call/off1.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (column4_row8.clone() - &(global_values.half_offset_size.clone() + &F::one())))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[21].clone() * &value;

    // Constraint: cpu/opcodes/call/flags.
    value = (cpu_decode_opcode_range_check_bit_12.clone()
        * (cpu_decode_opcode_range_check_bit_12.clone()
           .clone() + &cpu_decode_opcode_range_check_bit_12.clone()
           .clone() + &F::one()
           .clone() + &F::one()
           .clone() - &(cpu_decode_opcode_range_check_bit_0.clone() + cpu_decode_opcode_range_check_bit_1.clone() + &F::two().clone() + &F::two())))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[22].clone() * &value;

    // Constraint: cpu/opcodes/ret/off0.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (column4_row0.clone() + &F::two().clone() - &global_values.half_offset_size))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[23].clone() * &value;

    // Constraint: cpu/opcodes/ret/off2.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (column4_row4.clone() + &F::one().clone() - &global_values.half_offset_size))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[24].clone() * &value;

    // Constraint: cpu/opcodes/ret/flags.
    value = (cpu_decode_opcode_range_check_bit_13.clone()
        * (cpu_decode_opcode_range_check_bit_7
           .clone() + &cpu_decode_opcode_range_check_bit_0
           .clone() + &cpu_decode_opcode_range_check_bit_3
           .clone() + &cpu_decode_flag_res_op1_0
           .clone() - &F::two().clone() - &F::two()))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[25].clone() * &value;

    // Constraint: cpu/opcodes/assert_eq/assert_eq.
    value = (cpu_decode_opcode_range_check_bit_14 * (column1_row9.clone() - &column5_row12))
        .field_div(&(domain5));
    total_sum += constraint_coefficients[26].clone() * &value;

    // Constraint: initial_ap.
    value = (column5_row0.clone() - &global_values.initial_ap)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[27].clone() * &value;

    // Constraint: initial_fp.
    value = (column5_row8.clone() - &global_values.initial_ap)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[28].clone() * &value;

    // Constraint: initial_pc.
    value = (column1_row0.clone() - &global_values.initial_pc)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[29].clone() * &value;

    // Constraint: final_ap.
    value = (column5_row0.clone() - &global_values.final_ap)
        .field_div(&(domain24));
    total_sum += constraint_coefficients[30].clone() * &value;

    // Constraint: final_fp.
    value = (column5_row8.clone() - &global_values.initial_ap)
        .field_div(&(domain24));
    total_sum += constraint_coefficients[31].clone() * &value;

    // Constraint: final_pc.
    value = (column1_row0.clone() - &global_values.final_pc)
        .field_div(&(domain24));
    total_sum += constraint_coefficients[32].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/init0.
    value = ((global_values.memory_multi_column_perm_perm_interaction_elm
       .clone() - &(column2_row0
           .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column2_row1))
       .clone() * &column6_inter1_row0
       .clone() + &column1_row0
       .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column1_row1
       .clone() - &global_values.memory_multi_column_perm_perm_interaction_elm)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[33].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/step0.
    value = ((global_values.memory_multi_column_perm_perm_interaction_elm
       .clone() - &(column2_row2
           .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column2_row3))
       .clone() * &column6_inter1_row2
       .clone() - (global_values.memory_multi_column_perm_perm_interaction_elm
           .clone() - &(column1_row2
               .clone() + global_values.memory_multi_column_perm_hash_interaction_elm0.clone() * &column1_row3))
           .clone() * &column6_inter1_row0)
       .clone() * &domain26.field_div(&(domain1));
    total_sum += constraint_coefficients[34].clone() * &value;

    // Constraint: memory/multi_column_perm/perm/last.
    value = (column6_inter1_row0.clone() - &global_values.memory_multi_column_perm_perm_public_memory_prod)
        .field_div(&(domain26));
    total_sum += constraint_coefficients[35].clone() * &value;

    // Constraint: memory/diff_is_bit.
    value = (memory_address_diff_0.clone() * memory_address_diff_0.clone() - &memory_address_diff_0)
       .clone() * &domain26.field_div(&(domain1));
    total_sum += constraint_coefficients[36].clone() * &value;

    // Constraint: memory/is_func.
    value = ((memory_address_diff_0.clone() - &F::one()) * (column2_row1.clone() - &column2_row3))
       .clone() * &domain26.field_div(&(domain1));
    total_sum += constraint_coefficients[37].clone() * &value;

    // Constraint: memory/initial_addr.
    value = (column2_row0.clone() - &F::one()).field_div(&(domain25));
    total_sum += constraint_coefficients[38].clone() * &value;

    // Constraint: public_memory_addr_zero.
    value = (column1_row2).field_div(&(domain5));
    total_sum += constraint_coefficients[39].clone() * &value;

    // Constraint: public_memory_value_zero.
    value = (column1_row3).field_div(&(domain5));
    total_sum += constraint_coefficients[40].clone() * &value;

    // Constraint: range_check16/perm/init0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column4_row2)
       .clone() * &column7_inter1_row1
       .clone() + &column4_row0
       .clone() - &global_values.range_check16_perm_interaction_elm)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[41].clone() * &value;

    // Constraint: range_check16/perm/step0.
    value = ((global_values.range_check16_perm_interaction_elm.clone() - &column4_row6)
       .clone() * &column7_inter1_row5
       .clone() - (global_values.range_check16_perm_interaction_elm.clone() - &column4_row4).clone() * &column7_inter1_row1)
       .clone() * &domain27.field_div(&(domain2));
    total_sum += constraint_coefficients[42].clone() * &value;

    // Constraint: range_check16/perm/last.
    value = (column7_inter1_row1.clone() - &global_values.range_check16_perm_public_memory_prod)
        .field_div(&(domain27));
    total_sum += constraint_coefficients[43].clone() * &value;

    // Constraint: range_check16/diff_is_bit.
    value = (range_check16_diff_0.clone() * range_check16_diff_0.clone() - &range_check16_diff_0)
       .clone() * &domain27.field_div(&(domain2));
    total_sum += constraint_coefficients[44].clone() * &value;

    // Constraint: range_check16/minimum.
    value = (column4_row2.clone() - &global_values.range_check_min)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[45].clone() * &value;

    // Constraint: range_check16/maximum.
    value = (column4_row2.clone() - &global_values.range_check_max)
        .field_div(&(domain27));
    total_sum += constraint_coefficients[46].clone() * &value;

    // Constraint: diluted_check/permutation/init0.
    value = ((global_values.diluted_check_permutation_interaction_elm.clone() - &column3_row1)
       .clone() * &column7_inter1_row0
       .clone() + &column3_row0
       .clone() - &global_values.diluted_check_permutation_interaction_elm)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[47].clone() * &value;

    // Constraint: diluted_check/permutation/step0.
    value = ((global_values.diluted_check_permutation_interaction_elm.clone() - &column3_row3)
       .clone() * &column7_inter1_row2
       .clone() - (global_values.diluted_check_permutation_interaction_elm.clone() - &column3_row2)
           .clone() * &column7_inter1_row0)
       .clone() * &domain26.field_div(&(domain1));
    total_sum += constraint_coefficients[48].clone() * &value;

    // Constraint: diluted_check/permutation/last.
    value = (column7_inter1_row0.clone() - &global_values.diluted_check_permutation_public_memory_prod)
        .field_div(&(domain26));
    total_sum += constraint_coefficients[49].clone() * &value;

    // Constraint: diluted_check/init.
    value = (column6_inter1_row1.clone() - &F::one()).field_div(&(domain25));
    total_sum += constraint_coefficients[50].clone() * &value;

    // Constraint: diluted_check/first_element.
    value = (column3_row1.clone() - &global_values.diluted_check_first_elm)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[51].clone() * &value;

    // Constraint: diluted_check/step.
    value = (column6_inter1_row3
       .clone() - &(column6_inter1_row1.clone()
            * (F::one()
               .clone() + global_values.diluted_check_interaction_z.clone() * (column3_row3.clone() - &column3_row1))
           .clone() + global_values.diluted_check_interaction_alpha.clone()
                * (column3_row3.clone() - &column3_row1)
                * (column3_row3.clone() - &column3_row1)))
       .clone() * &domain26.field_div(&(domain1));
    total_sum += constraint_coefficients[52].clone() * &value;

    // Constraint: diluted_check/last.
    value = (column6_inter1_row1.clone() - &global_values.diluted_check_final_cum_val)
        .field_div(&(domain26));
    total_sum += constraint_coefficients[53].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/last_one_is_zero.
    value = (column5_row57.clone() * (column4_row3.clone() - &(column4_row11.clone() + &column4_row11)))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[54].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones0.
    value = (column5_row57.clone()
        * (column4_row11
           .clone().clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x800000000000000000000000000000000000000000000000"))
               .clone() * &column4_row1539))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[55].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit192.
    value = (column5_row57
       .clone().clone() - column4_row2047.clone() * (column4_row1539.clone() - &(column4_row1547.clone() + &column4_row1547)))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[56].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones192.
    value = (column4_row2047.clone() * (column4_row1547.clone().clone() - F::from_constant(8 as u64) * &column4_row1571))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[57].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/cumulative_bit196.
    value = (column4_row2047
       .clone() - (column4_row2011.clone() - &(column4_row2019.clone() + &column4_row2019))
            * (column4_row1571.clone() - &(column4_row1579.clone() + &column4_row1579)))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[58].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_unpacking/zeroes_between_ones196.
    value = ((column4_row2011.clone() - &(column4_row2019.clone() + &column4_row2019))
        * (column4_row1579.clone().clone() - F::from_stark_felt(Felt::from_hex_unchecked("0x40000000000000")).clone() * &column4_row2011))
        .field_div(&(domain19));
    total_sum += constraint_coefficients[59].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/booleanity_test.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone() * (pedersen_hash0_ec_subset_sum_bit_0.clone() - &F::one()))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[60].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/bit_extraction_end.
    value = (column4_row3).field_div(&(domain21));
    total_sum += constraint_coefficients[61].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/zeros_tail.
    value = (column4_row3).field_div(&(domain20));
    total_sum += constraint_coefficients[62].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/slope.
    value = (pedersen_hash0_ec_subset_sum_bit_0.clone() * (column4_row5.clone() - &global_values.pedersen_points_y)
       .clone().clone() - column4_row7.clone() * (column4_row1.clone() - &global_values.pedersen_points_x))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[63].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/x.
    value = (column4_row7.clone() * &column4_row7
       .clone().clone() - pedersen_hash0_ec_subset_sum_bit_0.clone()
            * (column4_row1.clone() + global_values.pedersen_points_x.clone() + &column4_row9))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[64].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/add_points/y.
    value = (pedersen_hash0_ec_subset_sum_bit_0 * (column4_row5.clone() + &column4_row13)
       .clone().clone() - column4_row7.clone() * (column4_row1.clone() - &column4_row9))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[65].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/x.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0.clone() * (column4_row9.clone() - &column4_row1))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[66].clone() * &value;

    // Constraint: pedersen/hash0/ec_subset_sum/copy_point/y.
    value = (pedersen_hash0_ec_subset_sum_bit_neg_0 * (column4_row13.clone() - &column4_row5))
       .clone() * &domain20.field_div(&(domain3));
    total_sum += constraint_coefficients[67].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/x.
    value = (column4_row2049.clone() - &column4_row2041)
       .clone() * &domain22.field_div(&(domain19));
    total_sum += constraint_coefficients[68].clone() * &value;

    // Constraint: pedersen/hash0/copy_point/y.
    value = (column4_row2053.clone() - &column4_row2045)
       .clone() * &domain22.field_div(&(domain19));
    total_sum += constraint_coefficients[69].clone() * &value;

    // Constraint: pedersen/hash0/init/x.
    value = (column4_row1.clone() - &global_values.pedersen_shift_point.x)
        .field_div(&(domain23));
    total_sum += constraint_coefficients[70].clone() * &value;

    // Constraint: pedersen/hash0/init/y.
    value = (column4_row5.clone() - &global_values.pedersen_shift_point.y)
        .field_div(&(domain23));
    total_sum += constraint_coefficients[71].clone() * &value;

    // Constraint: pedersen/input0_value0.
    value = (column1_row11.clone() - &column4_row3).field_div(&(domain23));
    total_sum += constraint_coefficients[72].clone() * &value;

    // Constraint: pedersen/input0_addr.
    value = (column1_row4106.clone() - &(column1_row1034.clone() + &F::one()))
       .clone() * &domain28.field_div(&(domain23));
    total_sum += constraint_coefficients[73].clone() * &value;

    // Constraint: pedersen/init_addr.
    value = (column1_row10.clone() - &global_values.initial_pedersen_addr)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[74].clone() * &value;

    // Constraint: pedersen/input1_value0.
    value =
        (column1_row2059.clone() - &column4_row2051).field_div(&(domain23));
    total_sum += constraint_coefficients[75].clone() * &value;

    // Constraint: pedersen/input1_addr.
    value = (column1_row2058.clone() - &(column1_row10.clone() + &F::one()))
        .field_div(&(domain23));
    total_sum += constraint_coefficients[76].clone() * &value;

    // Constraint: pedersen/output_value0.
    value =
        (column1_row1035.clone() - &column4_row4089).field_div(&(domain23));
    total_sum += constraint_coefficients[77].clone() * &value;

    // Constraint: pedersen/output_addr.
    value = (column1_row1034.clone() - &(column1_row2058.clone() + &F::one()))
        .field_div(&(domain23));
    total_sum += constraint_coefficients[78].clone() * &value;

    // Constraint: range_check_builtin/value.
    value = (range_check_builtin_value7_0.clone() - &column1_row139)
        .field_div(&(domain9));
    total_sum += constraint_coefficients[79].clone() * &value;

    // Constraint: range_check_builtin/addr_step.
    value = (column1_row394.clone() - &(column1_row138.clone() + &F::one()))
       .clone() * &domain29.field_div(&(domain9));
    total_sum += constraint_coefficients[80].clone() * &value;

    // Constraint: range_check_builtin/init_addr.
    value = (column1_row138.clone() - &global_values.initial_range_check_addr)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[81].clone() * &value;

    // Constraint: bitwise/init_var_pool_addr.
    value = (column1_row42.clone() - &global_values.initial_bitwise_addr)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[82].clone() * &value;

    // Constraint: bitwise/step_var_pool_addr.
    value = (column1_row106.clone() - &(column1_row42.clone() + &F::one()))
       .clone() * &domain10.field_div(&(domain7));
    total_sum += constraint_coefficients[83].clone() * &value;

    // Constraint: bitwise/x_or_y_addr.
    value = (column1_row74.clone() - &(column1_row234.clone() + &F::one()))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[84].clone() * &value;

    // Constraint: bitwise/next_var_pool_addr.
    value = (column1_row298.clone() - &(column1_row74.clone() + &F::one()))
       .clone() * &domain29.field_div(&(domain9));
    total_sum += constraint_coefficients[85].clone() * &value;

    // Constraint: bitwise/partition.
    value = (bitwise_sum_var_0_0.clone() + bitwise_sum_var_8_0.clone() - &column1_row43)
        .field_div(&(domain7));
    total_sum += constraint_coefficients[86].clone() * &value;

    // Constraint: bitwise/or_is_and_plus_xor.
    value = (column1_row75.clone() - &(column1_row171.clone() + &column1_row235))
        .field_div(&(domain9));
    total_sum += constraint_coefficients[87].clone() * &value;

    // Constraint: bitwise/addition_is_xor_with_and.
    value = (column3_row0.clone() + column3_row64.clone() - &(column3_row192.clone() + column3_row128.clone() + &column3_row128))
        .field_div(&(domain11));
    total_sum += constraint_coefficients[88].clone() * &value;

    // Constraint: bitwise/unique_unpacking192.
    value = ((column3_row176.clone() + &column3_row240).clone() * F::from_constant(16 as u64) - &column3_row2)
        .field_div(&(domain9));
    total_sum += constraint_coefficients[89].clone() * &value;

    // Constraint: bitwise/unique_unpacking193.
    value = ((column3_row180.clone() + &column3_row244).clone() * F::from_constant(16 as u64) - &column3_row130)
        .field_div(&(domain9));
    total_sum += constraint_coefficients[90].clone() * &value;

    // Constraint: bitwise/unique_unpacking194.
    value = ((column3_row184.clone() + &column3_row248).clone() * F::from_constant(16 as u64) - &column3_row66)
        .field_div(&(domain9));
    total_sum += constraint_coefficients[91].clone() * &value;

    // Constraint: bitwise/unique_unpacking195.
    value = ((column3_row188.clone() + &column3_row252).clone() * F::from_constant(256 as u64) - &column3_row194)
        .field_div(&(domain9));
    total_sum += constraint_coefficients[92].clone() * &value;

    // Constraint: poseidon/param_0/init_input_output_addr.
    value = (column1_row266.clone() - &global_values.initial_poseidon_addr)
        .field_div(&(domain25));
    total_sum += constraint_coefficients[93].clone() * &value;

    // Constraint: poseidon/param_0/addr_input_output_step.
    value = (column1_row778.clone() - &(column1_row266.clone() + &F::two().clone() + &F::one()))
       .clone() * &domain30.field_div(&(domain12));
    total_sum += constraint_coefficients[94].clone() * &value;

    // Constraint: poseidon/param_1/init_input_output_addr.
    value = (column1_row202.clone() - &(global_values.initial_poseidon_addr.clone() + &F::one()))
        .field_div(&(domain25));
    total_sum += constraint_coefficients[95].clone() * &value;

    // Constraint: poseidon/param_1/addr_input_output_step.
    value = (column1_row714.clone() - &(column1_row202.clone() + &F::two().clone() + &F::one()))
       .clone() * &domain30.field_div(&(domain12));
    total_sum += constraint_coefficients[96].clone() * &value;

    // Constraint: poseidon/param_2/init_input_output_addr.
    value = (column1_row458.clone() - &(global_values.initial_poseidon_addr.clone() + &F::two()))
        .field_div(&(domain25));
    total_sum += constraint_coefficients[97].clone() * &value;

    // Constraint: poseidon/param_2/addr_input_output_step.
    value = (column1_row970.clone() - &(column1_row458.clone() + &F::two().clone() + &F::one()))
       .clone() * &domain30.field_div(&(domain12));
    total_sum += constraint_coefficients[98].clone() * &value;

    // Constraint: poseidon/poseidon/full_rounds_state0_squaring.
    value = (column5_row9.clone() * column5_row9.clone() - &column5_row105)
        .field_div(&(domain8));
    total_sum += constraint_coefficients[99].clone() * &value;

    // Constraint: poseidon/poseidon/full_rounds_state1_squaring.
    value = (column5_row73.clone() * column5_row73.clone() - &column5_row25)
        .field_div(&(domain8));
    total_sum += constraint_coefficients[100].clone() * &value;

    // Constraint: poseidon/poseidon/full_rounds_state2_squaring.
    value = (column5_row41.clone() * column5_row41.clone() - &column5_row89)
        .field_div(&(domain8));
    total_sum += constraint_coefficients[101].clone() * &value;

    // Constraint: poseidon/poseidon/partial_rounds_state0_squaring.
    value = (column5_row6.clone() * column5_row6.clone() - &column5_row14)
        .field_div(&(domain5));
    total_sum += constraint_coefficients[102].clone() * &value;

    // Constraint: poseidon/poseidon/partial_rounds_state1_squaring.
    value = (column5_row1.clone() * column5_row1.clone() - &column5_row17)
       .clone() * &domain15.field_div(&(domain6));
    total_sum += constraint_coefficients[103].clone() * &value;

    // Constraint: poseidon/poseidon/add_first_round_key0.
    value = (column1_row267
       .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
            "0x6861759EA556A2339DD92F9562A30B9E58E2AD98109AE4780B7FD8EAC77FE6F",
    ))
       .clone() - &column5_row9)
        .field_div(&(domain16));
    total_sum += constraint_coefficients[104].clone() * &value;

    // Constraint: poseidon/poseidon/add_first_round_key1.
    value = (column1_row203
       .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
            "0x3827681995D5AF9FFC8397A3D00425A3DA43F76ABF28A64E4AB1A22F27508C4",
    ))
       .clone() - &column5_row73)
        .field_div(&(domain16));
    total_sum += constraint_coefficients[105].clone() * &value;

    // Constraint: poseidon/poseidon/add_first_round_key2.
    value = (column1_row459
       .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
            "0x3A3956D2FAD44D0E7F760A2277DC7CB2CAC75DC279B2D687A0DBE17704A8309",
    ))
       .clone() - &column5_row41)
        .field_div(&(domain16));
    total_sum += constraint_coefficients[106].clone() * &value;

    // Constraint: poseidon/poseidon/full_round0.
    value = (column5_row137
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state0_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state0_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state1_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state2_cubed_0
           .clone() + &global_values.poseidon_poseidon_full_round_key0))
       .clone() * &domain13.field_div(&(domain8));
    total_sum += constraint_coefficients[107].clone() * &value;

    // Constraint: poseidon/poseidon/full_round1.
    value = (column5_row201.clone() + &poseidon_poseidon_full_rounds_state1_cubed_0
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state2_cubed_0
           .clone() + &global_values.poseidon_poseidon_full_round_key1))
       .clone() * &domain13.field_div(&(domain8));
    total_sum += constraint_coefficients[108].clone() * &value;

    // Constraint: poseidon/poseidon/full_round2.
    value = (column5_row169
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_0
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_0
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_0
           .clone() + &poseidon_poseidon_full_rounds_state1_cubed_0
           .clone() + &global_values.poseidon_poseidon_full_round_key2))
       .clone() * &domain13.field_div(&(domain8));
    total_sum += constraint_coefficients[109].clone() * &value;

    // Constraint: poseidon/poseidon/last_full_round0.
    value = (column1_row779
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state0_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state0_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state1_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state2_cubed_7))
        .field_div(&(domain16));
    total_sum += constraint_coefficients[110].clone() * &value;

    // Constraint: poseidon/poseidon/last_full_round1.
    value = (column1_row715.clone() + &poseidon_poseidon_full_rounds_state1_cubed_7
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state2_cubed_7))
        .field_div(&(domain16));
    total_sum += constraint_coefficients[111].clone() * &value;

    // Constraint: poseidon/poseidon/last_full_round2.
    value = (column1_row971
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_7
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_7
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_7
           .clone() + &poseidon_poseidon_full_rounds_state1_cubed_7))
        .field_div(&(domain16));
    total_sum += constraint_coefficients[112].clone() * &value;

    // Constraint: poseidon/poseidon/copy_partial_rounds0_i0.
    value = (column5_row982.clone() - &column5_row1).field_div(&(domain16));
    total_sum += constraint_coefficients[113].clone() * &value;

    // Constraint: poseidon/poseidon/copy_partial_rounds0_i1.
    value = (column5_row998.clone() - &column5_row33).field_div(&(domain16));
    total_sum += constraint_coefficients[114].clone() * &value;

    // Constraint: poseidon/poseidon/copy_partial_rounds0_i2.
    value =
        (column5_row1014.clone() - &column5_row65).field_div(&(domain16));
    total_sum += constraint_coefficients[115].clone() * &value;

    // Constraint: poseidon/poseidon/margin_full_to_partial0.
    value = (column5_row6
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_3
       .clone() + &poseidon_poseidon_full_rounds_state2_cubed_3
       .clone() - &(poseidon_poseidon_full_rounds_state0_cubed_3
           .clone() + &poseidon_poseidon_full_rounds_state1_cubed_3
           .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x4B085EB1DF4258C3453CC97445954BF3433B6AB9DD5A99592864C00F54A3F9A",
    ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[116].clone() * &value;

    // Constraint: poseidon/poseidon/margin_full_to_partial1.
    value = (column5_row22
       .clone() - &(F::from_stark_felt(Felt::from_hex_unchecked(
            "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD",
        )).clone() * &poseidon_poseidon_full_rounds_state1_cubed_3
           .clone() + F::from_constant(10 as u64).clone() * &poseidon_poseidon_full_rounds_state2_cubed_3
           .clone() + F::from_constant(4 as u64).clone() * &column5_row6
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )).clone() * &poseidon_poseidon_partial_rounds_state0_cubed_0
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x46FB825257FEC76C50FE043684D4E6D2D2F2FDFE9B7C8D7128CA7ACC0F66F30",
            ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[117].clone() * &value;

    // Constraint: poseidon/poseidon/margin_full_to_partial2.
    value = (column5_row38
       .clone() - &(F::from_constant(8 as u64).clone() * &poseidon_poseidon_full_rounds_state2_cubed_3
           .clone() + F::from_constant(4 as u64) * &column5_row6
           .clone() + F::from_constant(6 as u64) * &poseidon_poseidon_partial_rounds_state0_cubed_0
           .clone() + &column5_row22
           .clone() + &column5_row22
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )).clone() * &poseidon_poseidon_partial_rounds_state0_cubed_1
           .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
                "0xF2193BA0C7EA33CE6222D9446C1E166202AE5461005292F4A2BCB93420151A",
            ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[118].clone() * &value;

    // Constraint: poseidon/poseidon/partial_round0.
    value = (column5_row54
       .clone() - &(F::from_constant(8 as u64).clone() * &poseidon_poseidon_partial_rounds_state0_cubed_0
           .clone() + F::from_constant(4 as u64) * &column5_row22
           .clone() + F::from_constant(6 as u64) * &poseidon_poseidon_partial_rounds_state0_cubed_1
           .clone() + &column5_row38
           .clone() + &column5_row38
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )).clone() * &poseidon_poseidon_partial_rounds_state0_cubed_2
           .clone() + &global_values.poseidon_poseidon_partial_round_key0))
       .clone() * &domain17.field_div(&(domain5));
    total_sum += constraint_coefficients[119].clone() * &value;

    // Constraint: poseidon/poseidon/partial_round1.
    value = (column5_row97
       .clone() - &(F::from_constant(8 as u64).clone() * &poseidon_poseidon_partial_rounds_state1_cubed_0
           .clone() + F::from_constant(4 as u64) * &column5_row33
           .clone() + F::from_constant(6 as u64) * &poseidon_poseidon_partial_rounds_state1_cubed_1
           .clone() + &column5_row65
           .clone() + &column5_row65
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )).clone() * &poseidon_poseidon_partial_rounds_state1_cubed_2
           .clone() + &global_values.poseidon_poseidon_partial_round_key1))
       .clone() * &domain18.field_div(&(domain6));
    total_sum += constraint_coefficients[120].clone() * &value;

    // Constraint: poseidon/poseidon/margin_partial_to_full0.
    value = (column5_row521
       .clone() - &(F::from_constant(16 as u64).clone() * &poseidon_poseidon_partial_rounds_state1_cubed_19
           .clone() + F::from_constant(8 as u64) * &column5_row641
           .clone() + F::from_constant(16 as u64) * &poseidon_poseidon_partial_rounds_state1_cubed_20
           .clone() + F::from_constant(6 as u64) * &column5_row673
           .clone() + &poseidon_poseidon_partial_rounds_state1_cubed_21
           .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x13D1B5CFD87693224F0AC561AB2C15CA53365D768311AF59CEFAF701BC53B37",
            ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[121].clone() * &value;

    // Constraint: poseidon/poseidon/margin_partial_to_full1.
    value = (column5_row585
       .clone() - &(F::from_constant(4 as u64).clone() * &poseidon_poseidon_partial_rounds_state1_cubed_20
           .clone() + &column5_row673
           .clone() + &column5_row673
           .clone() + &poseidon_poseidon_partial_rounds_state1_cubed_21
           .clone() + &F::from_stark_felt(Felt::from_hex_unchecked(
                "0x3195D6B2D930E71CEDE286D5B8B41D49296DDF222BCD3BF3717A12A9A6947FF",
            ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[122].clone() * &value;

    // Constraint: poseidon/poseidon/margin_partial_to_full2.
    value = (column5_row553
       .clone() - &(F::from_constant(8 as u64).clone() * &poseidon_poseidon_partial_rounds_state1_cubed_19
           .clone() + F::from_constant(4 as u64) * &column5_row641
           .clone() + F::from_constant(6 as u64) * &poseidon_poseidon_partial_rounds_state1_cubed_20
           .clone() + &column5_row673
           .clone() + &column5_row673
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x800000000000010FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )).clone() * poseidon_poseidon_partial_rounds_state1_cubed_21
           .clone() + F::from_stark_felt(Felt::from_hex_unchecked(
                "0x2C14FCCABC26929170CC7AC9989C823608B9008BEF3B8E16B6089A5D33CD72E",
            ))))
    .field_div(&(domain16));
    total_sum += constraint_coefficients[123].clone() * &value;

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
    let pow0 = trace_generator.powers([0_u64]   );
    let pow1 = trace_generator.powers([4089_u64]);
    let pow2 = trace_generator.powers([2011_u64]);
    let pow3 = trace_generator.powers([1539_u64]);
    let pow4 = trace_generator.powers([1_u64]   );
    let pow5 = pow4.clone() * &pow4; // pow(trace_generator, 2).
    let pow6 = pow4.clone() * &pow5; // pow(trace_generator, 3).
    let pow7 = pow4.clone() * &pow6; // pow(trace_generator, 4).
    let pow8 = pow4.clone() * &pow7; // pow(trace_generator, 5).
    let pow9 = pow4.clone() * &pow8; // pow(trace_generator, 6).
    let pow10 = pow4.clone() * &pow9; // pow(trace_generator, 7).
    let pow11 = pow4.clone() * &pow10; // pow(trace_generator, 8).
    let pow12 = pow3.clone() * &pow11; // pow(trace_generator, 1547).
    let pow13 = pow4.clone() * &pow11; // pow(trace_generator, 9).
    let pow14 = pow4.clone() * &pow13; // pow(trace_generator, 10).
    let pow15 = pow4.clone() * &pow14; // pow(trace_generator, 11).
    let pow16 = pow4.clone() * &pow15; // pow(trace_generator, 12).
    let pow17 = pow4.clone() * &pow16; // pow(trace_generator, 13).
    let pow18 = pow4.clone() * &pow17; // pow(trace_generator, 14).
    let pow19 = pow4.clone() * &pow18; // pow(trace_generator, 15).
    let pow20 = pow4.clone() * &pow19; // pow(trace_generator, 16).
    let pow21 = pow4.clone() * &pow20; // pow(trace_generator, 17).
    let pow22 = pow6.clone() * &pow21; // pow(trace_generator, 20).
    let pow23 = pow5.clone() * &pow22; // pow(trace_generator, 22).
    let pow24 = pow5.clone() * &pow23; // pow(trace_generator, 24).
    let pow25 = pow4.clone() * &pow24; // pow(trace_generator, 25).
    let pow26 = pow6.clone() * &pow25; // pow(trace_generator, 28).
    let pow27 = pow5.clone() * &pow26; // pow(trace_generator, 30).
    let pow28 = pow5.clone() * &pow27; // pow(trace_generator, 32).
    let pow29 = pow4.clone() * &pow28; // pow(trace_generator, 33).
    let pow30 = pow3.clone() * &pow28; // pow(trace_generator, 1571).
    let pow31 = pow6.clone() * &pow29; // pow(trace_generator, 36).
    let pow32 = pow5.clone() * &pow31; // pow(trace_generator, 38).
    let pow33 = pow5.clone() * &pow32; // pow(trace_generator, 40).
    let pow34 = pow4.clone() * &pow33; // pow(trace_generator, 41).
    let pow35 = pow4.clone() * &pow34; // pow(trace_generator, 42).
    let pow36 = pow4.clone() * &pow35; // pow(trace_generator, 43).
    let pow37 = pow4.clone() * &pow36; // pow(trace_generator, 44).
    let pow38 = pow5.clone() * &pow37; // pow(trace_generator, 46).
    let pow39 = pow5.clone() * &pow38; // pow(trace_generator, 48).
    let pow40 = pow4.clone() * &pow39; // pow(trace_generator, 49).
    let pow41 = pow6.clone() * &pow40; // pow(trace_generator, 52).
    let pow42 = pow5.clone() * &pow41; // pow(trace_generator, 54).
    let pow43 = pow5.clone() * &pow42; // pow(trace_generator, 56).
    let pow44 = pow4.clone() * &pow43; // pow(trace_generator, 57).
    let pow45 = pow6.clone() * &pow44; // pow(trace_generator, 60).
    let pow46 = pow7.clone() * &pow45; // pow(trace_generator, 64).
    let pow47 = pow4.clone() * &pow46; // pow(trace_generator, 65).
    let pow48 = pow4.clone() * &pow47; // pow(trace_generator, 66).
    let pow49 = pow10.clone() * &pow48; // pow(trace_generator, 73).
    let pow50 = pow4.clone() * &pow49; // pow(trace_generator, 74).
    let pow51 = pow4.clone() * &pow50; // pow(trace_generator, 75).
    let pow52 = pow4.clone() * &pow51; // pow(trace_generator, 76).
    let pow53 = pow8.clone() * &pow52; // pow(trace_generator, 81).
    let pow54 = pow11.clone() * &pow53; // pow(trace_generator, 89).
    let pow55 = pow11.clone() * &pow54; // pow(trace_generator, 97).
    let pow56 = pow11.clone() * &pow55; // pow(trace_generator, 105).
    let pow57 = pow4.clone() * &pow56; // pow(trace_generator, 106).
    let pow58 = pow5.clone() * &pow57; // pow(trace_generator, 108).
    let pow59 = pow22.clone() * &pow58; // pow(trace_generator, 128).
    let pow60 = pow5.clone() * &pow59; // pow(trace_generator, 130).
    let pow61 = pow10.clone() * &pow60; // pow(trace_generator, 137).
    let pow62 = pow4.clone() * &pow61; // pow(trace_generator, 138).
    let pow63 = pow4.clone() * &pow62; // pow(trace_generator, 139).
    let pow64 = pow27.clone() * &pow63; // pow(trace_generator, 169).
    let pow65 = pow5.clone() * &pow64; // pow(trace_generator, 171).
    let pow66 = pow4.clone() * &pow63; // pow(trace_generator, 140).
    let pow67 = pow4.clone() * &pow65; // pow(trace_generator, 172).
    let pow68 = pow7.clone() * &pow67; // pow(trace_generator, 176).
    let pow69 = pow7.clone() * &pow68; // pow(trace_generator, 180).
    let pow70 = pow7.clone() * &pow69; // pow(trace_generator, 184).
    let pow71 = pow7.clone() * &pow70; // pow(trace_generator, 188).
    let pow72 = pow7.clone() * &pow71; // pow(trace_generator, 192).
    let pow73 = pow5.clone() * &pow72; // pow(trace_generator, 194).
    let pow74 = pow10.clone() * &pow73; // pow(trace_generator, 201).
    let pow75 = pow4.clone() * &pow74; // pow(trace_generator, 202).
    let pow76 = pow4.clone() * &pow75; // pow(trace_generator, 203).
    let pow77 = pow72.clone() * &pow74; // pow(trace_generator, 393).
    let pow78 = pow4.clone() * &pow76; // pow(trace_generator, 204).
    let pow79 = pow27.clone() * &pow78; // pow(trace_generator, 234).
    let pow80 = pow4.clone() * &pow79; // pow(trace_generator, 235).
    let pow81 = pow4.clone() * &pow80; // pow(trace_generator, 236).
    let pow82 = pow7.clone() * &pow81; // pow(trace_generator, 240).
    let pow83 = pow7.clone() * &pow82; // pow(trace_generator, 244).
    let pow84 = pow7.clone() * &pow83; // pow(trace_generator, 248).
    let pow85 = pow7.clone() * &pow84; // pow(trace_generator, 252).
    let pow86 = pow18.clone() * &pow85; // pow(trace_generator, 266).
    let pow87 = pow4.clone() * &pow86; // pow(trace_generator, 267).
    let pow88 = pow4.clone() * &pow77; // pow(trace_generator, 394).
    let pow89 = pow19.clone() * &pow88; // pow(trace_generator, 409).
    let pow90 = pow20.clone() * &pow89; // pow(trace_generator, 425).
    let pow91 = pow28.clone() * &pow90; // pow(trace_generator, 457).
    let pow92 = pow4.clone() * &pow91; // pow(trace_generator, 458).
    let pow93 = pow4.clone() * &pow92; // pow(trace_generator, 459).
    let pow94 = pow18.clone() * &pow93; // pow(trace_generator, 473).
    let pow95 = pow20.clone() * &pow94; // pow(trace_generator, 489).
    let pow96 = pow28.clone() * &pow95; // pow(trace_generator, 521).
    let pow97 = pow28.clone() * &pow96; // pow(trace_generator, 553).
    let pow98 = pow28.clone() * &pow97; // pow(trace_generator, 585).
    let pow99 = pow24.clone() * &pow98; // pow(trace_generator, 609).
    let pow100 = pow20.clone() * &pow99; // pow(trace_generator, 625).
    let pow101 = pow20.clone() * &pow100; // pow(trace_generator, 641).
    let pow102 = pow20.clone() * &pow101; // pow(trace_generator, 657).
    let pow103 = pow84.clone() * &pow102; // pow(trace_generator, 905).
    let pow104 = pow20.clone() * &pow102; // pow(trace_generator, 673).
    let pow105 = pow20.clone() * &pow103; // pow(trace_generator, 921).
    let pow106 = pow20.clone() * &pow104; // pow(trace_generator, 689).
    let pow107 = pow20.clone() * &pow105; // pow(trace_generator, 937).
    let pow108 = pow28.clone() * &pow107; // pow(trace_generator, 969).
    let pow109 = pow25.clone() * &pow106; // pow(trace_generator, 714).
    let pow110 = pow46.clone() * &pow109; // pow(trace_generator, 778).
    let pow111 = pow4.clone() * &pow108; // pow(trace_generator, 970).
    let pow112 = pow3.clone() * &pow33; // pow(trace_generator, 1579).
    let pow113 = pow4.clone() * &pow109; // pow(trace_generator, 715).
    let pow114 = pow4.clone() * &pow110; // pow(trace_generator, 779).
    let pow115 = pow28.clone() * &pow86; // pow(trace_generator, 298).
    let pow116 = pow4.clone() * &pow111; // pow(trace_generator, 971).
    let pow117 = pow15.clone() * &pow116; // pow(trace_generator, 982).
    let pow118 = pow6.clone() * &pow117; // pow(trace_generator, 985).
    let pow119 = pow17.clone() * &pow118; // pow(trace_generator, 998).
    let pow120 = pow6.clone() * &pow119; // pow(trace_generator, 1001).
    let pow121 = pow17.clone() * &pow120; // pow(trace_generator, 1014).
    let pow122 = pow22.clone() * &pow121; // pow(trace_generator, 1034).
    let pow123 = pow2.clone() * &pow11; // pow(trace_generator, 2019).
    let pow124 = pow2.clone() * &pow27; // pow(trace_generator, 2041).
    let pow125 = pow7.clone() * &pow124; // pow(trace_generator, 2045).
    let pow126 = pow2.clone() * &pow31; // pow(trace_generator, 2047).
    let pow127 = pow4.clone() * &pow122; // pow(trace_generator, 1035).
    let pow128 = pow2.clone() * &pow32; // pow(trace_generator, 2049).
    let pow129 = pow2.clone() * &pow33; // pow(trace_generator, 2051).
    let pow130 = pow2.clone() * &pow35; // pow(trace_generator, 2053).
    let pow131 = pow8.clone() * &pow130; // pow(trace_generator, 2058).
    let pow132 = pow2.clone() * &pow39; // pow(trace_generator, 2059).
    let pow133 = pow1.clone() * &pow21; // pow(trace_generator, 4106).

    // Fetch columns.
    let column0 = column_values[0].clone();
    let column1 = column_values[1].clone();
    let column2 = column_values[2].clone();
    let column3 = column_values[3].clone();
    let column4 = column_values[4].clone();
    let column5 = column_values[5].clone();
    let column6 = column_values[6].clone();
    let column7 = column_values[7].clone();

    // Sum constraints.
    let mut total_sum = F::zero();

    let mut value = (column0.clone() - &oods_values[0])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[0].clone() * &value;

    value = (column0.clone() - &oods_values[1])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[1].clone() * &value;

    value = (column0.clone() - &oods_values[2])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[2].clone() * &value;

    value = (column0.clone() - &oods_values[3])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[3].clone() * &value;

    value = (column0.clone() - &oods_values[4])
        .field_div(&(point.clone().clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[4].clone() * &value;

    value = (column0.clone() - &oods_values[5])
        .field_div(&(point.clone().clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[5].clone() * &value;

    value = (column0.clone() - &oods_values[6])
        .field_div(&(point.clone().clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[6].clone() * &value;

    value = (column0.clone() - &oods_values[7])
        .field_div(&(point.clone().clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[7].clone() * &value;

    value = (column0.clone() - &oods_values[8])
        .field_div(&(point.clone().clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[8].clone() * &value;

    value = (column0.clone() - &oods_values[9])
        .field_div(&(point.clone().clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[9].clone() * &value;

    value = (column0.clone() - &oods_values[10])
        .field_div(&(point.clone().clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[10].clone() * &value;

    value = (column0.clone() - &oods_values[11])
        .field_div(&(point.clone().clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[11].clone() * &value;

    value = (column0.clone() - &oods_values[12])
        .field_div(&(point.clone().clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[12].clone() * &value;

    value = (column0.clone() - &oods_values[13])
        .field_div(&(point.clone().clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[13].clone() * &value;

    value = (column0.clone() - &oods_values[14])
        .field_div(&(point.clone().clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[14].clone() * &value;

    value = (column0.clone() - &oods_values[15])
        .field_div(&(point.clone().clone() - pow19.clone() * oods_point));
    total_sum += constraint_coefficients[15].clone() * &value;

    value = (column1.clone() - &oods_values[16])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[16].clone() * &value;

    value = (column1.clone() - &oods_values[17])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[17].clone() * &value;

    value = (column1.clone() - &oods_values[18])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[18].clone() * &value;

    value = (column1.clone() - &oods_values[19])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[19].clone() * &value;

    value = (column1.clone() - &oods_values[20])
        .field_div(&(point.clone().clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[20].clone() * &value;

    value = (column1.clone() - &oods_values[21])
        .field_div(&(point.clone().clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[21].clone() * &value;

    value = (column1.clone() - &oods_values[22])
        .field_div(&(point.clone().clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[22].clone() * &value;

    value = (column1.clone() - &oods_values[23])
        .field_div(&(point.clone().clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[23].clone() * &value;

    value = (column1.clone() - &oods_values[24])
        .field_div(&(point.clone().clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[24].clone() * &value;

    value = (column1.clone() - &oods_values[25])
        .field_div(&(point.clone().clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[25].clone() * &value;

    value = (column1.clone() - &oods_values[26])
        .field_div(&(point.clone().clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[26].clone() * &value;

    value = (column1.clone() - &oods_values[27])
        .field_div(&(point.clone().clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[27].clone() * &value;

    value = (column1.clone() - &oods_values[28])
        .field_div(&(point.clone().clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[28].clone() * &value;

    value = (column1.clone() - &oods_values[29])
        .field_div(&(point.clone().clone() - pow35.clone() * oods_point));
    total_sum += constraint_coefficients[29].clone() * &value;

    value = (column1.clone() - &oods_values[30])
        .field_div(&(point.clone().clone() - pow36.clone() * oods_point));
    total_sum += constraint_coefficients[30].clone() * &value;

    value = (column1.clone() - &oods_values[31])
        .field_div(&(point.clone().clone() - pow50.clone() * oods_point));
    total_sum += constraint_coefficients[31].clone() * &value;

    value = (column1.clone() - &oods_values[32])
        .field_div(&(point.clone().clone() - pow51.clone() * oods_point));
    total_sum += constraint_coefficients[32].clone() * &value;

    value = (column1.clone() - &oods_values[33])
        .field_div(&(point.clone().clone() - pow57.clone() * oods_point));
    total_sum += constraint_coefficients[33].clone() * &value;

    value = (column1.clone() - &oods_values[34])
        .field_div(&(point.clone().clone() - pow62.clone() * oods_point));
    total_sum += constraint_coefficients[34].clone() * &value;

    value = (column1.clone() - &oods_values[35])
        .field_div(&(point.clone().clone() - pow63.clone() * oods_point));
    total_sum += constraint_coefficients[35].clone() * &value;

    value = (column1.clone() - &oods_values[36])
        .field_div(&(point.clone().clone() - pow65.clone() * oods_point));
    total_sum += constraint_coefficients[36].clone() * &value;

    value = (column1.clone() - &oods_values[37])
        .field_div(&(point.clone().clone() - pow75.clone() * oods_point));
    total_sum += constraint_coefficients[37].clone() * &value;

    value = (column1.clone() - &oods_values[38])
        .field_div(&(point.clone().clone() - pow76.clone() * oods_point));
    total_sum += constraint_coefficients[38].clone() * &value;

    value = (column1.clone() - &oods_values[39])
        .field_div(&(point.clone().clone() - pow79.clone() * oods_point));
    total_sum += constraint_coefficients[39].clone() * &value;

    value = (column1.clone() - &oods_values[40])
        .field_div(&(point.clone().clone() - pow80.clone() * oods_point));
    total_sum += constraint_coefficients[40].clone() * &value;

    value = (column1.clone() - &oods_values[41])
        .field_div(&(point.clone().clone() - pow86.clone() * oods_point));
    total_sum += constraint_coefficients[41].clone() * &value;

    value = (column1.clone() - &oods_values[42])
        .field_div(&(point.clone().clone() - pow87.clone() * oods_point));
    total_sum += constraint_coefficients[42].clone() * &value;

    value = (column1.clone() - &oods_values[43])
        .field_div(&(point.clone().clone() - pow115.clone() * oods_point));
    total_sum += constraint_coefficients[43].clone() * &value;

    value = (column1.clone() - &oods_values[44])
        .field_div(&(point.clone().clone() - pow88.clone() * oods_point));
    total_sum += constraint_coefficients[44].clone() * &value;

    value = (column1.clone() - &oods_values[45])
        .field_div(&(point.clone().clone() - pow92.clone() * oods_point));
    total_sum += constraint_coefficients[45].clone() * &value;

    value = (column1.clone() - &oods_values[46])
        .field_div(&(point.clone().clone() - pow93.clone() * oods_point));
    total_sum += constraint_coefficients[46].clone() * &value;

    value = (column1.clone() - &oods_values[47])
        .field_div(&(point.clone().clone() - pow109.clone() * oods_point));
    total_sum += constraint_coefficients[47].clone() * &value;

    value = (column1.clone() - &oods_values[48])
        .field_div(&(point.clone().clone() - pow113.clone() * oods_point));
    total_sum += constraint_coefficients[48].clone() * &value;

    value = (column1.clone() - &oods_values[49])
        .field_div(&(point.clone().clone() - pow110.clone() * oods_point));
    total_sum += constraint_coefficients[49].clone() * &value;

    value = (column1.clone() - &oods_values[50])
        .field_div(&(point.clone().clone() - pow114.clone() * oods_point));
    total_sum += constraint_coefficients[50].clone() * &value;

    value = (column1.clone() - &oods_values[51])
        .field_div(&(point.clone().clone() - pow111.clone() * oods_point));
    total_sum += constraint_coefficients[51].clone() * &value;

    value = (column1.clone() - &oods_values[52])
        .field_div(&(point.clone().clone() - pow116.clone() * oods_point));
    total_sum += constraint_coefficients[52].clone() * &value;

    value = (column1.clone() - &oods_values[53])
        .field_div(&(point.clone().clone() - pow122.clone() * oods_point));
    total_sum += constraint_coefficients[53].clone() * &value;

    value = (column1.clone() - &oods_values[54])
        .field_div(&(point.clone().clone() - pow127.clone() * oods_point));
    total_sum += constraint_coefficients[54].clone() * &value;

    value = (column1.clone() - &oods_values[55])
        .field_div(&(point.clone().clone() - pow131.clone() * oods_point));
    total_sum += constraint_coefficients[55].clone() * &value;

    value = (column1.clone() - &oods_values[56])
        .field_div(&(point.clone().clone() - pow132.clone() * oods_point));
    total_sum += constraint_coefficients[56].clone() * &value;

    value = (column1.clone() - &oods_values[57])
        .field_div(&(point.clone().clone() - pow133.clone() * oods_point));
    total_sum += constraint_coefficients[57].clone() * &value;

    value = (column2.clone() - &oods_values[58])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[58].clone() * &value;

    value = (column2.clone() - &oods_values[59])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[59].clone() * &value;

    value = (column2.clone() - &oods_values[60])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[60].clone() * &value;

    value = (column2.clone() - &oods_values[61])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[61].clone() * &value;

    value = (column3.clone() - &oods_values[62])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[62].clone() * &value;

    value = (column3.clone() - &oods_values[63])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[63].clone() * &value;

    value = (column3.clone() - &oods_values[64])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[64].clone() * &value;

    value = (column3.clone() - &oods_values[65])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[65].clone() * &value;

    value = (column3.clone() - &oods_values[66])
        .field_div(&(point.clone().clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[66].clone() * &value;

    value = (column3.clone() - &oods_values[67])
        .field_div(&(point.clone().clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[67].clone() * &value;

    value = (column3.clone() - &oods_values[68])
        .field_div(&(point.clone().clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[68].clone() * &value;

    value = (column3.clone() - &oods_values[69])
        .field_div(&(point.clone().clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[69].clone() * &value;

    value = (column3.clone() - &oods_values[70])
        .field_div(&(point.clone().clone() - pow22.clone() * oods_point));
    total_sum += constraint_coefficients[70].clone() * &value;

    value = (column3.clone() - &oods_values[71])
        .field_div(&(point.clone().clone() - pow24.clone() * oods_point));
    total_sum += constraint_coefficients[71].clone() * &value;

    value = (column3.clone() - &oods_values[72])
        .field_div(&(point.clone().clone() - pow26.clone() * oods_point));
    total_sum += constraint_coefficients[72].clone() * &value;

    value = (column3.clone() - &oods_values[73])
        .field_div(&(point.clone().clone() - pow28.clone() * oods_point));
    total_sum += constraint_coefficients[73].clone() * &value;

    value = (column3.clone() - &oods_values[74])
        .field_div(&(point.clone().clone() - pow31.clone() * oods_point));
    total_sum += constraint_coefficients[74].clone() * &value;

    value = (column3.clone() - &oods_values[75])
        .field_div(&(point.clone().clone() - pow33.clone() * oods_point));
    total_sum += constraint_coefficients[75].clone() * &value;

    value = (column3.clone() - &oods_values[76])
        .field_div(&(point.clone().clone() - pow37.clone() * oods_point));
    total_sum += constraint_coefficients[76].clone() * &value;

    value = (column3.clone() - &oods_values[77])
        .field_div(&(point.clone().clone() - pow39.clone() * oods_point));
    total_sum += constraint_coefficients[77].clone() * &value;

    value = (column3.clone() - &oods_values[78])
        .field_div(&(point.clone().clone() - pow41.clone() * oods_point));
    total_sum += constraint_coefficients[78].clone() * &value;

    value = (column3.clone() - &oods_values[79])
        .field_div(&(point.clone().clone() - pow43.clone() * oods_point));
    total_sum += constraint_coefficients[79].clone() * &value;

    value = (column3.clone() - &oods_values[80])
        .field_div(&(point.clone().clone() - pow45.clone() * oods_point));
    total_sum += constraint_coefficients[80].clone() * &value;

    value = (column3.clone() - &oods_values[81])
        .field_div(&(point.clone().clone() - pow46.clone() * oods_point));
    total_sum += constraint_coefficients[81].clone() * &value;

    value = (column3.clone() - &oods_values[82])
        .field_div(&(point.clone().clone() - pow48.clone() * oods_point));
    total_sum += constraint_coefficients[82].clone() * &value;

    value = (column3.clone() - &oods_values[83])
        .field_div(&(point.clone().clone() - pow59.clone() * oods_point));
    total_sum += constraint_coefficients[83].clone() * &value;

    value = (column3.clone() - &oods_values[84])
        .field_div(&(point.clone().clone() - pow60.clone() * oods_point));
    total_sum += constraint_coefficients[84].clone() * &value;

    value = (column3.clone() - &oods_values[85])
        .field_div(&(point.clone().clone() - pow68.clone() * oods_point));
    total_sum += constraint_coefficients[85].clone() * &value;

    value = (column3.clone() - &oods_values[86])
        .field_div(&(point.clone().clone() - pow69.clone() * oods_point));
    total_sum += constraint_coefficients[86].clone() * &value;

    value = (column3.clone() - &oods_values[87])
        .field_div(&(point.clone().clone() - pow70.clone() * oods_point));
    total_sum += constraint_coefficients[87].clone() * &value;

    value = (column3.clone() - &oods_values[88])
        .field_div(&(point.clone().clone() - pow71.clone() * oods_point));
    total_sum += constraint_coefficients[88].clone() * &value;

    value = (column3.clone() - &oods_values[89])
        .field_div(&(point.clone().clone() - pow72.clone() * oods_point));
    total_sum += constraint_coefficients[89].clone() * &value;

    value = (column3.clone() - &oods_values[90])
        .field_div(&(point.clone().clone() - pow73.clone() * oods_point));
    total_sum += constraint_coefficients[90].clone() * &value;

    value = (column3.clone() - &oods_values[91])
        .field_div(&(point.clone().clone() - pow82.clone() * oods_point));
    total_sum += constraint_coefficients[91].clone() * &value;

    value = (column3.clone() - &oods_values[92])
        .field_div(&(point.clone().clone() - pow83.clone() * oods_point));
    total_sum += constraint_coefficients[92].clone() * &value;

    value = (column3.clone() - &oods_values[93])
        .field_div(&(point.clone().clone() - pow84.clone() * oods_point));
    total_sum += constraint_coefficients[93].clone() * &value;

    value = (column3.clone() - &oods_values[94])
        .field_div(&(point.clone().clone() - pow85.clone() * oods_point));
    total_sum += constraint_coefficients[94].clone() * &value;

    value = (column4.clone() - &oods_values[95])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[95].clone() * &value;

    value = (column4.clone() - &oods_values[96])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[96].clone() * &value;

    value = (column4.clone() - &oods_values[97])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[97].clone() * &value;

    value = (column4.clone() - &oods_values[98])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[98].clone() * &value;

    value = (column4.clone() - &oods_values[99])
        .field_div(&(point.clone().clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[99].clone() * &value;

    value = (column4.clone() - &oods_values[100])
        .field_div(&(point.clone().clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[100].clone() * &value;

    value = (column4.clone() - &oods_values[101])
        .field_div(&(point.clone().clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[101].clone() * &value;

    value = (column4.clone() - &oods_values[102])
        .field_div(&(point.clone().clone() - pow10.clone() * oods_point));
    total_sum += constraint_coefficients[102].clone() * &value;

    value = (column4.clone() - &oods_values[103])
        .field_div(&(point.clone().clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[103].clone() * &value;

    value = (column4.clone() - &oods_values[104])
        .field_div(&(point.clone().clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[104].clone() * &value;

    value = (column4.clone() - &oods_values[105])
        .field_div(&(point.clone().clone() - pow15.clone() * oods_point));
    total_sum += constraint_coefficients[105].clone() * &value;

    value = (column4.clone() - &oods_values[106])
        .field_div(&(point.clone().clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[106].clone() * &value;

    value = (column4.clone() - &oods_values[107])
        .field_div(&(point.clone().clone() - pow17.clone() * oods_point));
    total_sum += constraint_coefficients[107].clone() * &value;

    value = (column4.clone() - &oods_values[108])
        .field_div(&(point.clone().clone() - pow37.clone() * oods_point));
    total_sum += constraint_coefficients[108].clone() * &value;

    value = (column4.clone() - &oods_values[109])
        .field_div(&(point.clone().clone() - pow52.clone() * oods_point));
    total_sum += constraint_coefficients[109].clone() * &value;

    value = (column4.clone() - &oods_values[110])
        .field_div(&(point.clone().clone() - pow58.clone() * oods_point));
    total_sum += constraint_coefficients[110].clone() * &value;

    value = (column4.clone() - &oods_values[111])
        .field_div(&(point.clone().clone() - pow66.clone() * oods_point));
    total_sum += constraint_coefficients[111].clone() * &value;

    value = (column4.clone() - &oods_values[112])
        .field_div(&(point.clone().clone() - pow67.clone() * oods_point));
    total_sum += constraint_coefficients[112].clone() * &value;

    value = (column4.clone() - &oods_values[113])
        .field_div(&(point.clone().clone() - pow78.clone() * oods_point));
    total_sum += constraint_coefficients[113].clone() * &value;

    value = (column4.clone() - &oods_values[114])
        .field_div(&(point.clone().clone() - pow81.clone() * oods_point));
    total_sum += constraint_coefficients[114].clone() * &value;

    value = (column4.clone() - &oods_values[115])
        .field_div(&(point.clone().clone() - pow3.clone() * oods_point));
    total_sum += constraint_coefficients[115].clone() * &value;

    value = (column4.clone() - &oods_values[116])
        .field_div(&(point.clone().clone() - pow12.clone() * oods_point));
    total_sum += constraint_coefficients[116].clone() * &value;

    value = (column4.clone() - &oods_values[117])
        .field_div(&(point.clone().clone() - pow30.clone() * oods_point));
    total_sum += constraint_coefficients[117].clone() * &value;

    value = (column4.clone() - &oods_values[118])
        .field_div(&(point.clone().clone() - pow112.clone() * oods_point));
    total_sum += constraint_coefficients[118].clone() * &value;

    value = (column4.clone() - &oods_values[119])
        .field_div(&(point.clone().clone() - pow2.clone() * oods_point));
    total_sum += constraint_coefficients[119].clone() * &value;

    value = (column4.clone() - &oods_values[120])
        .field_div(&(point.clone().clone() - pow123.clone() * oods_point));
    total_sum += constraint_coefficients[120].clone() * &value;

    value = (column4.clone() - &oods_values[121])
        .field_div(&(point.clone().clone() - pow124.clone() * oods_point));
    total_sum += constraint_coefficients[121].clone() * &value;

    value = (column4.clone() - &oods_values[122])
        .field_div(&(point.clone().clone() - pow125.clone() * oods_point));
    total_sum += constraint_coefficients[122].clone() * &value;

    value = (column4.clone() - &oods_values[123])
        .field_div(&(point.clone().clone() - pow126.clone() * oods_point));
    total_sum += constraint_coefficients[123].clone() * &value;

    value = (column4.clone() - &oods_values[124])
        .field_div(&(point.clone().clone() - pow128.clone() * oods_point));
    total_sum += constraint_coefficients[124].clone() * &value;

    value = (column4.clone() - &oods_values[125])
        .field_div(&(point.clone().clone() - pow129.clone() * oods_point));
    total_sum += constraint_coefficients[125].clone() * &value;

    value = (column4.clone() - &oods_values[126])
        .field_div(&(point.clone().clone() - pow130.clone() * oods_point));
    total_sum += constraint_coefficients[126].clone() * &value;

    value = (column4.clone() - &oods_values[127])
        .field_div(&(point.clone().clone() - pow1.clone() * oods_point));
    total_sum += constraint_coefficients[127].clone() * &value;

    value = (column5.clone() - &oods_values[128])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[128].clone() * &value;

    value = (column5.clone() - &oods_values[129])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[129].clone() * &value;

    value = (column5.clone() - &oods_values[130])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[130].clone() * &value;

    value = (column5.clone() - &oods_values[131])
        .field_div(&(point.clone().clone() - pow7.clone() * oods_point));
    total_sum += constraint_coefficients[131].clone() * &value;

    value = (column5.clone() - &oods_values[132])
        .field_div(&(point.clone().clone() - pow9.clone() * oods_point));
    total_sum += constraint_coefficients[132].clone() * &value;

    value = (column5.clone() - &oods_values[133])
        .field_div(&(point.clone().clone() - pow11.clone() * oods_point));
    total_sum += constraint_coefficients[133].clone() * &value;

    value = (column5.clone() - &oods_values[134])
        .field_div(&(point.clone().clone() - pow13.clone() * oods_point));
    total_sum += constraint_coefficients[134].clone() * &value;

    value = (column5.clone() - &oods_values[135])
        .field_div(&(point.clone().clone() - pow14.clone() * oods_point));
    total_sum += constraint_coefficients[135].clone() * &value;

    value = (column5.clone() - &oods_values[136])
        .field_div(&(point.clone().clone() - pow16.clone() * oods_point));
    total_sum += constraint_coefficients[136].clone() * &value;

    value = (column5.clone() - &oods_values[137])
        .field_div(&(point.clone().clone() - pow18.clone() * oods_point));
    total_sum += constraint_coefficients[137].clone() * &value;

    value = (column5.clone() - &oods_values[138])
        .field_div(&(point.clone().clone() - pow20.clone() * oods_point));
    total_sum += constraint_coefficients[138].clone() * &value;

    value = (column5.clone() - &oods_values[139])
        .field_div(&(point.clone().clone() - pow21.clone() * oods_point));
    total_sum += constraint_coefficients[139].clone() * &value;

    value = (column5.clone() - &oods_values[140])
        .field_div(&(point.clone().clone() - pow23.clone() * oods_point));
    total_sum += constraint_coefficients[140].clone() * &value;

    value = (column5.clone() - &oods_values[141])
        .field_div(&(point.clone().clone() - pow24.clone() * oods_point));
    total_sum += constraint_coefficients[141].clone() * &value;

    value = (column5.clone() - &oods_values[142])
        .field_div(&(point.clone().clone() - pow25.clone() * oods_point));
    total_sum += constraint_coefficients[142].clone() * &value;

    value = (column5.clone() - &oods_values[143])
        .field_div(&(point.clone().clone() - pow27.clone() * oods_point));
    total_sum += constraint_coefficients[143].clone() * &value;

    value = (column5.clone() - &oods_values[144])
        .field_div(&(point.clone().clone() - pow29.clone() * oods_point));
    total_sum += constraint_coefficients[144].clone() * &value;

    value = (column5.clone() - &oods_values[145])
        .field_div(&(point.clone().clone() - pow32.clone() * oods_point));
    total_sum += constraint_coefficients[145].clone() * &value;

    value = (column5.clone() - &oods_values[146])
        .field_div(&(point.clone().clone() - pow34.clone() * oods_point));
    total_sum += constraint_coefficients[146].clone() * &value;

    value = (column5.clone() - &oods_values[147])
        .field_div(&(point.clone().clone() - pow38.clone() * oods_point));
    total_sum += constraint_coefficients[147].clone() * &value;

    value = (column5.clone() - &oods_values[148])
        .field_div(&(point.clone().clone() - pow40.clone() * oods_point));
    total_sum += constraint_coefficients[148].clone() * &value;

    value = (column5.clone() - &oods_values[149])
        .field_div(&(point.clone().clone() - pow42.clone() * oods_point));
    total_sum += constraint_coefficients[149].clone() * &value;

    value = (column5.clone() - &oods_values[150])
        .field_div(&(point.clone().clone() - pow44.clone() * oods_point));
    total_sum += constraint_coefficients[150].clone() * &value;

    value = (column5.clone() - &oods_values[151])
        .field_div(&(point.clone().clone() - pow47.clone() * oods_point));
    total_sum += constraint_coefficients[151].clone() * &value;

    value = (column5.clone() - &oods_values[152])
        .field_div(&(point.clone().clone() - pow49.clone() * oods_point));
    total_sum += constraint_coefficients[152].clone() * &value;

    value = (column5.clone() - &oods_values[153])
        .field_div(&(point.clone().clone() - pow53.clone() * oods_point));
    total_sum += constraint_coefficients[153].clone() * &value;

    value = (column5.clone() - &oods_values[154])
        .field_div(&(point.clone().clone() - pow54.clone() * oods_point));
    total_sum += constraint_coefficients[154].clone() * &value;

    value = (column5.clone() - &oods_values[155])
        .field_div(&(point.clone().clone() - pow55.clone() * oods_point));
    total_sum += constraint_coefficients[155].clone() * &value;

    value = (column5.clone() - &oods_values[156])
        .field_div(&(point.clone().clone() - pow56.clone() * oods_point));
    total_sum += constraint_coefficients[156].clone() * &value;

    value = (column5.clone() - &oods_values[157])
        .field_div(&(point.clone().clone() - pow61.clone() * oods_point));
    total_sum += constraint_coefficients[157].clone() * &value;

    value = (column5.clone() - &oods_values[158])
        .field_div(&(point.clone().clone() - pow64.clone() * oods_point));
    total_sum += constraint_coefficients[158].clone() * &value;

    value = (column5.clone() - &oods_values[159])
        .field_div(&(point.clone().clone() - pow74.clone() * oods_point));
    total_sum += constraint_coefficients[159].clone() * &value;

    value = (column5.clone() - &oods_values[160])
        .field_div(&(point.clone().clone() - pow77.clone() * oods_point));
    total_sum += constraint_coefficients[160].clone() * &value;

    value = (column5.clone() - &oods_values[161])
        .field_div(&(point.clone().clone() - pow89.clone() * oods_point));
    total_sum += constraint_coefficients[161].clone() * &value;

    value = (column5.clone() - &oods_values[162])
        .field_div(&(point.clone().clone() - pow90.clone() * oods_point));
    total_sum += constraint_coefficients[162].clone() * &value;

    value = (column5.clone() - &oods_values[163])
        .field_div(&(point.clone().clone() - pow91.clone() * oods_point));
    total_sum += constraint_coefficients[163].clone() * &value;

    value = (column5.clone() - &oods_values[164])
        .field_div(&(point.clone().clone() - pow94.clone() * oods_point));
    total_sum += constraint_coefficients[164].clone() * &value;

    value = (column5.clone() - &oods_values[165])
        .field_div(&(point.clone().clone() - pow95.clone() * oods_point));
    total_sum += constraint_coefficients[165].clone() * &value;

    value = (column5.clone() - &oods_values[166])
        .field_div(&(point.clone().clone() - pow96.clone() * oods_point));
    total_sum += constraint_coefficients[166].clone() * &value;

    value = (column5.clone() - &oods_values[167])
        .field_div(&(point.clone().clone() - pow97.clone() * oods_point));
    total_sum += constraint_coefficients[167].clone() * &value;

    value = (column5.clone() - &oods_values[168])
        .field_div(&(point.clone().clone() - pow98.clone() * oods_point));
    total_sum += constraint_coefficients[168].clone() * &value;

    value = (column5.clone() - &oods_values[169])
        .field_div(&(point.clone().clone() - pow99.clone() * oods_point));
    total_sum += constraint_coefficients[169].clone() * &value;

    value = (column5.clone() - &oods_values[170])
        .field_div(&(point.clone().clone() - pow100.clone() * oods_point));
    total_sum += constraint_coefficients[170].clone() * &value;

    value = (column5.clone() - &oods_values[171])
        .field_div(&(point.clone().clone() - pow101.clone() * oods_point));
    total_sum += constraint_coefficients[171].clone() * &value;

    value = (column5.clone() - &oods_values[172])
        .field_div(&(point.clone().clone() - pow102.clone() * oods_point));
    total_sum += constraint_coefficients[172].clone() * &value;

    value = (column5.clone() - &oods_values[173])
        .field_div(&(point.clone().clone() - pow104.clone() * oods_point));
    total_sum += constraint_coefficients[173].clone() * &value;

    value = (column5.clone() - &oods_values[174])
        .field_div(&(point.clone().clone() - pow106.clone() * oods_point));
    total_sum += constraint_coefficients[174].clone() * &value;

    value = (column5.clone() - &oods_values[175])
        .field_div(&(point.clone().clone() - pow103.clone() * oods_point));
    total_sum += constraint_coefficients[175].clone() * &value;

    value = (column5.clone() - &oods_values[176])
        .field_div(&(point.clone().clone() - pow105.clone() * oods_point));
    total_sum += constraint_coefficients[176].clone() * &value;

    value = (column5.clone() - &oods_values[177])
        .field_div(&(point.clone().clone() - pow107.clone() * oods_point));
    total_sum += constraint_coefficients[177].clone() * &value;

    value = (column5.clone() - &oods_values[178])
        .field_div(&(point.clone().clone() - pow108.clone() * oods_point));
    total_sum += constraint_coefficients[178].clone() * &value;

    value = (column5.clone() - &oods_values[179])
        .field_div(&(point.clone().clone() - pow117.clone() * oods_point));
    total_sum += constraint_coefficients[179].clone() * &value;

    value = (column5.clone() - &oods_values[180])
        .field_div(&(point.clone().clone() - pow118.clone() * oods_point));
    total_sum += constraint_coefficients[180].clone() * &value;

    value = (column5.clone() - &oods_values[181])
        .field_div(&(point.clone().clone() - pow119.clone() * oods_point));
    total_sum += constraint_coefficients[181].clone() * &value;

    value = (column5.clone() - &oods_values[182])
        .field_div(&(point.clone().clone() - pow120.clone() * oods_point));
    total_sum += constraint_coefficients[182].clone() * &value;

    value = (column5.clone() - &oods_values[183])
        .field_div(&(point.clone().clone() - pow121.clone() * oods_point));
    total_sum += constraint_coefficients[183].clone() * &value;

    value = (column6.clone() - &oods_values[184])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[184].clone() * &value;

    value = (column6.clone() - &oods_values[185])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[185].clone() * &value;

    value = (column6.clone() - &oods_values[186])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[186].clone() * &value;

    value = (column6.clone() - &oods_values[187])
        .field_div(&(point.clone().clone() - pow6.clone() * oods_point));
    total_sum += constraint_coefficients[187].clone() * &value;

    value = (column7.clone() - &oods_values[188])
        .field_div(&(point.clone().clone() - pow0.clone() * oods_point));
    total_sum += constraint_coefficients[188].clone() * &value;

    value = (column7.clone() - &oods_values[189])
        .field_div(&(point.clone().clone() - pow4.clone() * oods_point));
    total_sum += constraint_coefficients[189].clone() * &value;

    value = (column7.clone() - &oods_values[190])
        .field_div(&(point.clone().clone() - pow5.clone() * oods_point));
    total_sum += constraint_coefficients[190].clone() * &value;

    value = (column7.clone() - &oods_values[191])
        .field_div(&(point.clone().clone() - pow8.clone() * oods_point));
    total_sum += constraint_coefficients[191].clone() * &value;

    // Sum the OODS boundary constraints on the composition polynomials.
    let oods_point_to_deg = oods_point.powers([Layout::CONSTRAINT_DEGREE as u64]);

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND]
       .clone() - &oods_values[192])
        .field_div(&(point.clone().clone() - &oods_point_to_deg));
    total_sum += constraint_coefficients[192].clone() * &value;

    value = (column_values[Layout::NUM_COLUMNS_FIRST.clone() + &Layout::NUM_COLUMNS_SECOND.clone() + &1]
       .clone() - &oods_values[193])
        .field_div(&(point.clone().clone() - &oods_point_to_deg));
    total_sum += constraint_coefficients[193].clone() * &value;

    total_sum
}
