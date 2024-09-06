use frs_iopp::{fri_commit, fri_query_phase, Field, FieldElement, Polynomial, ProofStream};

fn main() {
    // Example pplynomial to encode
    // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 0x^7
    println!("Initial poly: 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 0x^7");

    let prime = 97;

    let field = Field::new(prime);
    let a = FieldElement::new(19, field);
    let b = FieldElement::new(56, field);
    let c = FieldElement::new(34, field);
    let d = FieldElement::new(48, field);
    let e = FieldElement::new(43, field);
    let f = FieldElement::new(37, field);
    let g = FieldElement::new(10, field);
    let h = FieldElement::new(0, field);

    // value 28 obtained based on an example in a course taken
    let domain = vec![
        FieldElement::new(28, field),
        FieldElement::new(28i128.pow(2), field),
        FieldElement::new(28i128.pow(4), field),
        FieldElement::new(28i128.pow(8), field),
    ];

    let poly = Polynomial::new(vec![a, b, c, d, e, f, g, h]);
    let coset_offset = FieldElement::new(1, field);
    let mut transcript = ProofStream::new();
    let num_layer = 3; // this is based on the equation
    let number_of_queries = 10;

    println!("Initial eveluation Domain size: {}", domain.len());
    println!("Prime field: {}", prime);
    println!();

    // commit phase
    let (last_value, fri_layers) =
        fri_commit(num_layer, poly, &mut transcript, coset_offset, &domain);

    // displaying the results of the folding and mixing
    for (i, val) in fri_layers.iter().enumerate() {
        let res = val.polynomial.clone();

        print!("Polyomial - {}: ", i);
        for x in res.coeffs {
            print!("{}, ", x.num);
        }
        println!();
    }

    println!();
    println!("Last value: {:?}", last_value);
    println!();

    // query phase
    // this is one of the roots of unity in the domain
    let nth_root_of_unit = FieldElement::new(28i128.pow(2), field);

    let query_list = fri_query_phase(
        nth_root_of_unit,
        domain.len(),
        &fri_layers,
        &mut transcript,
        &number_of_queries,
    );

    // display results
    println!("COMMIT PHASE: ");
    println!("g (from verfier): {}", nth_root_of_unit.num);
    for (i, val) in transcript.objects.iter().enumerate() {
        println!("Merkle root - {}: {:?}", i, val);
    }
    println!();

    println!("QUERY PHASE: ");
    for (i, query) in query_list.iter().enumerate() {
        let layers: Vec<i128> = query.layers_evaluations.iter().map(|l| l.num).collect();
        let layer_sym: Vec<i128> = query.layers_evaluations_sym.iter().map(|l| l.num).collect();
        println!(
            "Layer {} evaluation at {} and {}: {:?}",
            i, g.num, -g.num, layers
        );
        println!(
            "Layer {} evaluation symetric at {} and {}: {:?}",
            i, g.num, -g.num, layer_sym
        );
        println!();
    }
}
