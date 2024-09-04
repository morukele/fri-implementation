use modulo::Mod;
use rs_merkle::{algorithms, Hasher, MerkleTree};
use sha2::{Digest, Sha256};

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

pub struct Transcript {
    pub root: [u8; 32],
    pub g: FiniteField,
    pub h: FiniteField,
}

impl Transcript {
    pub fn new(g: FiniteField, h: FiniteField) -> Self {
        Self {
            root: [0; 32],
            g,
            h,
        }
    }

    pub fn append(&mut self, root: [u8; 32]) {
        self.root = root;
    }

    fn generator(&self) -> [u8; 32] {
        // An rudementry version of the Fiat-Shamir Transformation
        // Essentailly a hash of two agree upon variables (g, h) with a thrid data point.
        let mut hasher = Sha256::new();
        hasher.update(self.g.num.to_le_bytes());
        hasher.update(self.h.num.to_be_bytes());
        hasher.update(self.root);

        hasher.finalize().into()
    }

    // returns a random challange
    pub fn get_challange(&self, prime: u64) -> FiniteField {
        // converting the bytes from the hash merkle root into an 8 element array
        let bytes = self.generator();
        let mut first_8_bytes = [0u8; 8];
        first_8_bytes.copy_from_slice(&bytes[0..8]);

        // modulo prime is used here to contrain the answer within the finite field
        FiniteField::new(u64::from_le_bytes(first_8_bytes).modulo(prime), prime)
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

pub fn commit(
    num_of_layers: usize,
    initial_poly: Polynomial,
    mut transcript: Transcript,
    domain_size: usize,
) -> (FiniteField, Vec<FriLayer>) {
    let prime = initial_poly.prime;
    let mut domain_size = domain_size;
    let mut layer_list = Vec::with_capacity(num_of_layers);

    // create the first layer and assign it to the current layer
    let mut current_layer = FriLayer::new(initial_poly.clone(), domain_size);
    layer_list.push(current_layer.clone());
    let mut current_poly = initial_poly;

    // send initial commitment
    let root = current_layer.merkle_tree.root().unwrap();
    transcript.append(root);

    for _ in 1..num_of_layers {
        // recieving challenge from the verfier
        let zeta = transcript.get_challange(prime);
        domain_size /= 2; // domain size always reduces for next computation

        // Fold the current polynomial
        current_poly = fold_polynomial(current_poly.clone(), zeta);
        current_layer = FriLayer::new(current_poly.clone(), domain_size);
        let new_root = current_layer.merkle_tree.root().unwrap();
        layer_list.push(current_layer.clone());

        // Send subsequent commitments
        transcript.append(new_root);
    }

    // receive challange
    let zeta = transcript.get_challange(prime);

    let last_poly = fold_polynomial(current_poly.clone(), zeta);
    let last_value = *last_poly
        .coeffs
        .first()
        .unwrap_or(&FiniteField::new(0, prime));

    // send last value to transcript
    // The Sha256 gives an array of 32 elements, however, when we get to a constant polynomial
    // in the finite field, the result is an array of 8 elements.
    let mut array = [0; 32];
    let smaller_array = last_value.num.to_be_bytes();
    array[..8].copy_from_slice(&smaller_array);
    transcript.append(array);

    (last_value, layer_list)
}

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

    #[test]
    fn able_to_recieve_challange() {
        let prime = 97;
        let mut transcript =
            Transcript::new(FiniteField::new(10, prime), FiniteField::new(20, prime));

        let leaf_values = ["a", "b", "c", "d", "e", "f"];
        let leaves: Vec<[u8; 32]> = leaf_values
            .iter()
            .map(|x| Sha256::hash(x.as_bytes()))
            .collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        transcript.append(merkle_tree.root().unwrap());
        let challange = transcript.get_challange(prime);

        assert!(challange.num < prime);
    }

    #[test]
    fn fri_can_commit() {
        let prime = 97;
        let transcript = Transcript::new(FiniteField::new(10, prime), FiniteField::new(20, prime));

        let coeffs = vec![
            FiniteField::new(19, prime),
            FiniteField::new(56, prime),
            FiniteField::new(34, prime),
            FiniteField::new(48, prime),
            FiniteField::new(43, prime),
            FiniteField::new(37, prime),
            FiniteField::new(10, prime),
            FiniteField::new(0, prime),
        ];
        let len = coeffs.len();

        let poly = Polynomial::new(coeffs, prime);
        let res = commit((len / 2) - 1, poly, transcript, 10);

        assert!(res.0.num > 0);
        assert_eq!(res.1.len(), (len / 2) - 1);
    }
}
