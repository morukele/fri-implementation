use rs_merkle::{algorithms, Hasher, MerkleTree};

use crate::{FiniteField, Polynomial};

/// This struct holds a layer for the FRI protocol.
/// It contains the evaluations of the polynomial at the layer, and the corresponding merkel tree.
#[derive(Clone)]
pub struct FriLayer {
    // holds the evaluation of the polynomial
    pub evaluations: Vec<FiniteField>,
    // holds the merket tree of the evaluation
    pub merkle_tree: MerkleTree<algorithms::Sha256>,
    // the size of the domain to evaluate over
    pub domain_size: usize,
}

impl FriLayer {
    pub fn new(polynomial: Polynomial, domain_size: usize) -> Self {
        // evaluate the polynomial over the given domain
        let mut evaluations = vec![FiniteField::new(0, polynomial.prime); domain_size];

        for i in 0..domain_size {
            let x = FiniteField::new(i as u64, polynomial.prime);
            let eval = polynomial.evaluate(x);
            evaluations[i] = eval;
        }

        // generate merkel tree
        let leaves: Vec<[u8; 32]> = evaluations
            .iter()
            // important to convert the number to bytes for the sake of this crate
            .map(|x| algorithms::Sha256::hash(x.num.to_string().as_bytes()))
            .collect();
        let mut merkle_tree: MerkleTree<algorithms::Sha256> = MerkleTree::from_leaves(&leaves);
        merkle_tree.commit();

        Self {
            evaluations,
            merkle_tree,
            domain_size,
        }
    }
}

/// Performs polynomial folding on a given set of coefficients.
///
/// # Arguments
///
/// * `coeffs` - A vector of coefficients representing the input polynomial.
/// * `beta` - A random number used for folding. Both `beta` and coefficients are finite fields.
///
/// # Returns
///
/// A vector representing the folded polynomial.
pub fn fold_polynomial(poly: Polynomial, beta: FiniteField) -> Polynomial {
    let coeffs = poly.coeffs;
    // split polynomial into even and odd indexes, multiply the odd indexes by beta and return the vector of folded polynomial coefficients
    let even: Vec<FiniteField> = coeffs.iter().step_by(2).cloned().collect();
    let odd: Vec<FiniteField> = coeffs
        .iter()
        .skip(1)
        .step_by(2)
        .cloned()
        .map(|o| o * beta)
        .collect();

    // result
    let coeffs = even
        .iter()
        .zip(odd.iter())
        .map(|(even, odd)| *even + *odd)
        .collect();

    Polynomial::new(coeffs, poly.prime)
}

/// The function handles the commitment phase of the FRI protocol
pub fn commit() {}

pub fn query() {}

#[cfg(test)]
mod tests {
    use super::*;
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

    #[test]
    fn able_to_fold_polynomial_by_factor_of_two() {
        let coeffs = vec![
            FiniteField::new(19, 97),
            FiniteField::new(56, 97),
            FiniteField::new(34, 97),
            FiniteField::new(48, 97),
            FiniteField::new(43, 97),
            FiniteField::new(37, 97),
            FiniteField::new(10, 97),
            FiniteField::new(0, 97),
        ];
        let beta = FiniteField::new(12, 97);
        let poly = Polynomial::new(coeffs, 97);
        let res = fold_polynomial(poly, beta);

        assert_eq!(
            res.coeffs,
            [
                FiniteField::new(12, 97),
                FiniteField::new(28, 97),
                FiniteField::new(2, 97),
                FiniteField::new(10, 97)
            ]
        )
    }

    #[test]
    fn able_to_fold_to_a_singe_coeff_by_factor_of_two() {
        let coeffs = vec![
            FiniteField::new(19, 97),
            FiniteField::new(56, 97),
            FiniteField::new(34, 97),
            FiniteField::new(48, 97),
            FiniteField::new(43, 97),
            FiniteField::new(37, 97),
            FiniteField::new(10, 97),
            FiniteField::new(0, 97),
        ];

        // round one
        println!("{:?}", &coeffs);
        let mut poly = Polynomial::new(coeffs, 97);
        let mut beta = FiniteField::new(12, 97);
        poly = fold_polynomial(poly, beta);
        assert_eq!(
            poly.coeffs,
            [
                FiniteField::new(12, 97),
                FiniteField::new(28, 97),
                FiniteField::new(2, 97),
                FiniteField::new(10, 97)
            ]
        );

        // round two
        println!("{:?}", &poly);
        beta = FiniteField::new(32, 97);
        poly = fold_polynomial(poly, beta);
        assert_eq!(
            poly.coeffs,
            [FiniteField::new(35, 97), FiniteField::new(31, 97),]
        );

        // round three
        println!("{:?}", &poly);
        beta = FiniteField::new(64, 97);
        poly = fold_polynomial(poly, beta);
        assert_eq!(poly.coeffs, [FiniteField::new(79, 97)]);
    }

    #[test]
    fn create_new_fri_layer() {
        let prime = 97;
        let a = FiniteField::new(1, prime);
        let b = FiniteField::new(2, prime);
        let c = FiniteField::new(3, prime);
        let coeffs = vec![a, b, c];

        let poly = Polynomial::new(coeffs, prime);
        let layer = FriLayer::new(poly, 10);

        dbg!(&layer.merkle_tree.root());
        dbg!(&layer.merkle_tree.root_hex());

        // the evaluation at 5 should equal 86
        assert_eq!(layer.evaluations[5], FiniteField::new(86, prime))
    }
}
