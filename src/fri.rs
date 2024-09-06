use crate::{fold_polynomial, FieldElement, Polynomial, ProofStream};
use merkle::{MerkleTree, Proof};
use ring::{digest::Algorithm, digest::SHA256};

static DIGEST: &Algorithm = &SHA256;

#[derive(Clone, Debug)]
pub struct FriLayer {
    pub polynomial: Polynomial, // The polynomial associated with this FRI layer.
    pub merkle_tree: MerkleTree<FieldElement>, // Merkle tree for commitments based on the polynomial evaluation.
    pub domain: Vec<FieldElement>,             // Domain over with the polynomial is evaluated.
}

impl FriLayer {
    // Constructs a new `FriLayer` with a given polynomial, coset offset, and domain.
    // The polynomial is evaluated over the domain, and a Merkle tree is created based on the evaluations.
    pub fn new(poly: &Polynomial, domain: Vec<FieldElement>) -> Self {
        let evaluation = poly.evaluate_domain(&domain);

        let merkle_tree = MerkleTree::from_vec(DIGEST, evaluation.clone());

        Self {
            polynomial: poly.clone(),
            merkle_tree,
            domain,
        }
    }
}

// The commit phase of the FRI protocol.
// This phase is responsible for generating commitments to multiple layers of polynomials and storing them in a proof transcript.
pub fn fri_commit(
    number_layers: usize,         // The number of layers in the FRI commitment.
    p_0: Polynomial,              // Initial polynomial.
    transcript: &mut ProofStream, // Proof stream to store commitments.
    domain: &Vec<FieldElement>,   // Domain of the FRI layers.
) -> (FieldElement, Vec<FriLayer>) {
    let field = p_0.coeffs[0].field;

    // setup phase
    let mut fri_layers = Vec::with_capacity(number_layers);
    let mut current_layer = FriLayer::new(&p_0, domain.clone());
    fri_layers.push(current_layer.clone());
    let mut current_poly = p_0;

    // send first commitment
    transcript.push(current_layer.merkle_tree.root_hash());

    // begin the interactive phase
    for i in 1..number_layers {
        // recieve challange
        let alpha = transcript.prover_fiat_shamir(&field);

        // Compute layer polynomial and domain
        let new_domain = domain[i];
        println!("folding with: {:?}", &alpha);
        current_poly = fold_polynomial(&current_poly, &alpha);
        current_layer = FriLayer::new(&current_poly, vec![new_domain]);
        let new_data = current_layer.merkle_tree.root_hash();
        fri_layers.push(current_layer.clone());

        // sending commitment
        transcript.push(new_data);
    }

    // last round
    // receive challange
    let alpha = transcript.prover_fiat_shamir(&field);

    let last_poly = fold_polynomial(&current_poly, &alpha);

    let zero = FieldElement::new(0, field);
    let last_value = last_poly.coeffs.first().unwrap_or(&zero);

    // send last value as raw byte
    transcript.push(&last_value.num.to_be_bytes().to_vec());

    (*last_value, fri_layers)
}

/// The `FriDecommitment` struct holds evaluation pairs and authentication paths
/// for verifying FRI decommitments.
#[derive(Debug, Clone)]
pub struct FriDecommitment {
    pub layers_auth_paths_sym: Vec<Option<Proof<FieldElement>>>,
    pub layers_evaluations_sym: Vec<FieldElement>,
    pub layers_auth_paths: Vec<Option<Proof<FieldElement>>>,
    pub layers_evaluations: Vec<FieldElement>,
}

// The query phase of the FRI protocol.
// Verifies whether the values at randomly selected points in the domain match the polynomial evaluations.
pub fn fri_query_phase(
    g: FieldElement,              // nth root of unity for domain evaluation.
    domain_size: usize,           // size of the domain.
    fri_layers: &Vec<FriLayer>,   // FRI layers generated during the commit phase.
    transcript: &mut ProofStream, // Proof stream for handling challanges.
    number_of_queries: &usize,    // Number of queries to be made in the protocol.
) -> Vec<FriDecommitment> {
    if !fri_layers.is_empty() {
        let number_of_queries = *number_of_queries;
        let iotas = (0..number_of_queries)
            .map(|_| (transcript.objects.len() % domain_size))
            .collect::<Vec<usize>>();
        let query_list: Vec<FriDecommitment> = iotas
            .iter()
            .map(|_| {
                // receive challange
                let mut layers_auth_paths_sym = vec![];
                let mut layers_evaluations_sym = vec![];
                let mut layers_evaluations = vec![];
                let mut layers_auth_paths = vec![];

                for (i, layer) in fri_layers.iter().enumerate() {
                    // evaluate the value at g and -g, then send the merkle roots to the verfier
                    let eval = layer.polynomial.evaluate(g.pow(i as u32 + 1));
                    let eval_sym = layer.polynomial.evaluate(-g.pow(i as u32 + 1));

                    // get merkle branches
                    let auth_path = layer.merkle_tree.gen_proof(eval);
                    let auth_path_sym = layer.merkle_tree.gen_proof(eval_sym);

                    // storing the results
                    layers_auth_paths_sym.push(auth_path_sym);
                    layers_evaluations_sym.push(eval_sym);

                    layers_evaluations.push(eval);
                    layers_auth_paths.push(auth_path);
                }

                FriDecommitment {
                    layers_auth_paths_sym,
                    layers_evaluations_sym,
                    layers_evaluations,
                    layers_auth_paths,
                }
            })
            .collect();

        query_list
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Field, FieldElement};

    #[test]
    fn can_create_fri_layer() {
        let prime = 97;
        let field = Field::new(prime);
        let a = FieldElement::new(1, field);
        let b = FieldElement::new(2, field);
        let c = FieldElement::new(3, field);
        let poly = Polynomial::new(vec![a, b, c]);

        let domain = vec![
            FieldElement::new(0, field),
            FieldElement::new(1, field),
            FieldElement::new(2, field),
        ];

        let layer = FriLayer::new(&poly, domain);

        assert!(!layer.polynomial.coeffs.is_empty());
    }
}
