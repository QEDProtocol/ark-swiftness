use crate::formula::fri_formula;
use alloc::vec;
use starknet_crypto::Felt;
use swiftness_field::{Fp, SimpleField};

#[test]
fn test_fri_formula2() {
    let coset_values = vec![
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "256174450386745647456273661147162555580494518861153534647088465922575117334",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1671405167398496013166151137317583376038528401232344909132875285960291311268",
            )
            .unwrap(),
        ),
    ];

    let eval_point = Fp::from_stark_felt(
        Felt::from_dec_str(
            "990499144245737974799008890724836248213916208950349459587583338754726831595",
        )
        .unwrap(),
    );
    let x_inv = Fp::from_stark_felt(
        Felt::from_dec_str(
            "2562983180373163585382777096151079646715274516289060915516104360308560206742",
        )
        .unwrap(),
    );
    let expected_res = Fp::from_stark_felt(
        Felt::from_dec_str(
            "198440420437625747101596759055022522005259320860955022036987094429833877178",
        )
        .unwrap(),
    );
    let result = fri_formula(
        coset_values,
        eval_point,
        x_inv,
        Fp::from_stark_felt(Felt::from(2)),
    )
    .unwrap();
    assert_eq!(result, expected_res);
}

#[test]
fn test_fri_formula4() {
    let coset_values = vec![
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2918451960196183950799272371389606628523370484646741980148988314056840633012",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1828256075401704910953535512167992927476841764512113836321405179977451944658",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "443990580507814779714721735425307372556191581217364203603052790273043374812",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "478993815713421978957120397192722702770323426746719771295955120433436796180",
            )
            .unwrap(),
        ),
    ];
    let eval_point = Fp::from_stark_felt(
        Felt::from_dec_str(
            "457249448999073095464130886760235558440510604838488179928102756356962280192",
        )
        .unwrap(),
    );
    let x_inv = Fp::from_stark_felt(
        Felt::from_dec_str(
            "3107440215033843359186594841583230014816092994120559276037011692468583562476",
        )
        .unwrap(),
    );
    let coset_size = 4;
    let expected_res = Fp::from_stark_felt(
        Felt::from_dec_str(
            "76986752687751524725198345383694178215277147555245625873131732095927140782",
        )
        .unwrap(),
    );
    let result = fri_formula(
        coset_values,
        eval_point,
        x_inv,
        Fp::from_stark_felt(Felt::from(coset_size)),
    )
    .unwrap();
    assert_eq!(result, expected_res);
}

#[test]
fn test_fri_formula8() {
    let coset_values = vec![
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1661166871144478583893094416262059281826151442139016862759341228313773098756",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1888790466376987171231396642956380917904535958666125046539466878395173202690",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "561547484995955011602324598416005224996941805793915162906443532252891702660",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1438536576067352528859853732647697550807339377747523085134808764166756865377",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2000528913550216347590830479340601949879559709495641913127193800231287027181",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "968156013310731486938436114466792427269789175801786475032517169685274987637",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "3250035871629077170491947405374956034621884547926979323876970138934589005216",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "897157052540850732712732450079850389056926113695526376358380698632562487485",
            )
            .unwrap(),
        ),
    ];
    let eval_point = Fp::from_stark_felt(
        Felt::from_dec_str(
            "117094530326216229550146135028366305396570718736487726300139051888760830677",
        )
        .unwrap(),
    );
    let x_inv = Fp::from_stark_felt(
        Felt::from_dec_str(
            "2178676743740509795000995476125961580296168609656535469725486531798699196988",
        )
        .unwrap(),
    );
    let coset_size = 8;
    let expected_res = Fp::from_stark_felt(
        Felt::from_dec_str(
            "2928957534120406763150873305661822742897260412260280822311358109399058652974",
        )
        .unwrap(),
    );
    let result = fri_formula(
        coset_values,
        eval_point,
        x_inv,
        Fp::from_stark_felt(Felt::from(coset_size)),
    )
    .unwrap();
    assert_eq!(result, expected_res);
}

#[test]
fn test_fri_formula16() {
    let coset_values = vec![
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1830360260767246179429152250672367365974293880197306063642359322652473418653",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "3085926493110094076710734930449361058123224813481795388167668581174293228771",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1607299987054925237445217024334446849543150875865699114944096686437897111753",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "3148344452919029631974324531259422322638996981447765405256284693722148271843",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1414363463551123164953744364899158768001534820947118677192316453629493426683",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1251170352249480221675546930249156874640792574829086684030680899472214442049",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2829586349239053936105008951381321968848749767788105077608267975888347183105",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2479853112422483406409872764151260737242741372650754304755385651924864953187",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "741627624943133398165028231006534361126520291848732128447460710235965240797",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "948446534062965329061639422673810116395745120783172282454806953649972082412",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "740451231596130847381847379108542578609096119014292221334060186112880662077",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2832402624341247112280268990275716678963627285493925393692446990112722001079",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "3136851806033301474120777392426720795558868125196843704074663617779378457446",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1587406744973581680114122359205653339457720336912159943930529946020104828453",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "1405784999711145104568440705151178765262609426103481131577188329447712092445",
            )
            .unwrap(),
        ),
        Fp::from_stark_felt(
            Felt::from_dec_str(
                "2526225071480351877750250312060682153979427353331663476892300511344908692936",
            )
            .unwrap(),
        ),
    ];
    let eval_point = Fp::from_stark_felt(
        Felt::from_dec_str(
            "611757761827218372659316980928600090155368845034029583212395428142956808164",
        )
        .unwrap(),
    );
    let x_inv = Fp::from_stark_felt(
        Felt::from_dec_str(
            "2747636755771078955150747981212578469605285885376168668689388042479636251975",
        )
        .unwrap(),
    );
    let coset_size = 16;
    let expected_res = Fp::from_stark_felt(
        Felt::from_dec_str(
            "624048098022519532611213501847456835806953670583267764150309668941596037474",
        )
        .unwrap(),
    );
    let result = fri_formula(
        coset_values,
        eval_point,
        x_inv,
        Fp::from_stark_felt(Felt::from(coset_size)),
    )
    .unwrap();
    assert_eq!(result, expected_res);
}
