use serde::{Deserialize, Serialize};

use crate::FieldElement;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Polynomial {
    pub coeffs: Vec<FieldElement>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<FieldElement>) -> Self {
        Self { coeffs }
    }

    pub fn degree(&self) -> i64 {
        if self.coeffs.is_empty() {
            return -1;
        }
        let zero = self.coeffs[0].field.zero();
        let mut maxindex = 0;
        for i in 0..self.coeffs.len() {
            if self.coeffs[i] != zero {
                maxindex = i
            }
        }
        maxindex as i64
    }

    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        let mut xi = x.field.one();
        let mut value = x.field.zero();
        for c in self.coeffs.clone() {
            value = value + c * xi;
            xi = xi * x;
        }

        value
    }

    pub fn evaluate_domain(&self, domain: &Vec<FieldElement>) -> Vec<FieldElement> {
        let mut output = Vec::with_capacity(domain.len());
        for x in domain {
            let res = self.evaluate(*x);
            output.push(res);
        }

        output
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
pub fn fold_polynomial(poly: &Polynomial, beta: &FieldElement) -> Polynomial {
    let coeffs = poly.coeffs.clone();
    // split polynomial into even and odd indexes, multiply the odd indexes by beta and return the vector of folded polynomial coefficients
    let even: Vec<FieldElement> = coeffs.iter().step_by(2).cloned().collect();
    let odd: Vec<FieldElement> = coeffs
        .iter()
        .skip(1)
        .step_by(2)
        .cloned()
        .map(|o| o * *beta)
        .collect();

    // result
    let coeffs = even
        .iter()
        .zip(odd.iter())
        .map(|(even, odd)| *even + *odd)
        .collect();

    Polynomial::new(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Field, FieldElement};

    #[test]
    fn polynomial_evaluation() {
        let prime = 97;
        let field = Field::new(prime);
        let a = FieldElement::new(1, field);
        let b = FieldElement::new(2, field);
        let c = FieldElement::new(3, field);
        let poly = Polynomial::new(vec![a, b, c]);
        let res = poly.evaluate(FieldElement::new(5, field));

        assert_eq!(res.num, 86);
    }

    #[test]
    fn polynomial_evaluation_domain() {
        let field = Field::new(97);
        let domain = vec![
            FieldElement::new(0, field),
            FieldElement::new(1, field),
            FieldElement::new(2, field),
        ];
        let a = FieldElement::new(1, field);
        let b = FieldElement::new(2, field);
        let c = FieldElement::new(3, field);
        let poly = Polynomial::new(vec![a, b, c]);

        let res = poly.evaluate_domain(&domain);

        assert_eq!(res.len(), 5);
        assert_eq!(res[0], FieldElement::new(1, field));
        assert_eq!(res[1], FieldElement::new(6, field));
    }
}
