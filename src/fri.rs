use std::ops::Neg;

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
    number_of_queries: usize,     // Number of queries to be made in the protocol.
) -> Vec<FriDecommitment> {
    if !fri_layers.is_empty() {
        let mut decommitments = Vec::with_capacity(number_of_queries);

        // Generate a list of random indices
        let query_indices = (0..number_of_queries as i32)
            .map(|_| transcript.verifier_random_index(domain_size))
            .collect::<Vec<usize>>();

        // Process each query index
        for &query_index in query_indices.iter() {
            let mut layers_auth_paths_sym = vec![];
            let mut layers_evaluations_sym = vec![];
            let mut layers_evaluations = vec![];
            let mut layers_auth_paths = vec![];

            // Iterate over each layer in the FRI layers
            for (i, layer) in fri_layers.iter().enumerate() {
                // Get the power of g for the current layer
                let g_i = g.pow(i as u32 + 1);
                let neg_g_i = g_i.neg(); // Compute -g^i

                // Evaluate the polynomial at g^i and -g^i
                let eval = layer.polynomial.evaluate(g_i);
                let eval_sym = layer.polynomial.evaluate(neg_g_i);

                // Generate Merkle proofs for the evaluations at g^i and -g^i
                let auth_path = layer.merkle_tree.gen_nth_proof(query_index);
                let auth_path_sym = layer
                    .merkle_tree
                    .gen_nth_proof((query_index + domain_size / 2) % domain_size); // Symmetric point proof

                // Push results into the vectors
                layers_evaluations.push(eval);
                layers_evaluations_sym.push(eval_sym);
                layers_auth_paths.push(auth_path);
                layers_auth_paths_sym.push(auth_path_sym);
            }

            // Store the decommitment for this query
            decommitments.push(FriDecommitment {
                layers_auth_paths_sym,
                layers_evaluations_sym,
                layers_evaluations,
                layers_auth_paths,
            });
        }

        decommitments
    } else {
        vec![]
    }
}

// Verifies the results of the FRI query phase.
// This function checks the validity of the decommitment by verifying the Merkle proofs
// and confirming the polynomial folding consistency across the FRI layers.
pub fn verify_fri(
    fri_layers: &Vec<FriLayer>, // FRI layers generated during the commit phase.
    decommitments: &Vec<FriDecommitment>, // Decommitments provided during the query phase.
    transcript: &mut ProofStream, // Proof stream for handling challenges.
) -> bool {
    // Iterate over each decommitment and verify it
    for (query_index, decommitment) in decommitments.iter().enumerate() {
        // for each layer, we need to verify the Merkle proof and consistency with the evaluations
        for (i, layer) in fri_layers.iter().enumerate() {
            // Extract the evaluation and the Merkle authentication path for both g and -g.
            let eval = decommitment.layers_evaluations[i];
            let eval_sym = decommitment.layers_evaluations_sym[i];
            let auth_path = &decommitment.layers_auth_paths[i];
            let auth_path_sym = &decommitment.layers_auth_paths_sym[i];

            // Verify the Merkle proof for evaluation at g^i
            let eval_proof_valid = match auth_path {
                Some(proof) => proof.validate(layer.merkle_tree.root_hash()),
                None => false,
            };

            // Verify the Merkle proof for evaluation at g^-1
            let eval_sym_proof_valid = match auth_path_sym {
                Some(proof) => proof.validate(layer.merkle_tree.root_hash()),
                None => false,
            };

            // Both Merkle proofs must be valid.
            if !eval_proof_valid || !eval_sym_proof_valid {
                println!(
                    "Merkle proof verification failed at layer {}, at query index {}",
                    i, query_index
                );
                return false;
            } else {
                println!(
                    "Merkle proof verification passed at layer {}, at query index {}",
                    i, query_index
                );
            }

            // Check consistency with the next layer by verifying that folding was done correctly.
            // This can be done by recomputing the folded polynomial from eval and eval_sym and comparing.
            // TODO: this does not produce the right result
            if i < fri_layers.len() - 1 {
                let alpha = transcript.verifier_fiat_shamir(&eval.field);
                let folded_value = fold_polynomial_evaluation(eval, eval_sym, &alpha);

                // The folded value must match the next layer's evaluation at g^(i+1).
                let next_eval = decommitment.layers_evaluations[i + 1];
                if folded_value != next_eval {
                    println!("Folding consistency check failed at layer {}", i);
                    return false;
                } else {
                    println!("Folding consistency check passed at layer {}", i);
                }
            }
        }
    }

    // If all checks pass, return true
    true
}

// Helper function to compute the folded polynomial evaluation.
fn fold_polynomial_evaluation(
    eval: FieldElement,
    eval_sym: FieldElement,
    alpha: &FieldElement,
) -> FieldElement {
    // Fold using the formula: f'(x) = (f(x) + f(-x)) / 2 + alpha * (f(x) - f(-x)) / 2
    let two = FieldElement::new(2, eval.field);
    ((eval + eval_sym) * two.inverse()) + (*alpha * (eval - eval_sym) * two.inverse())
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
