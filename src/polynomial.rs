use crate::FieldElement;
use serde::{Deserialize, Serialize};

// The `Polynomial` struct represents a polynomial where the coefficients
// are elements in a finite field (FieldElement).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Polynomial {
    pub coeffs: Vec<FieldElement>,
}

impl Polynomial {
    // Constructs a new polynomial from a vector of coefficients.
    pub fn new(coeffs: Vec<FieldElement>) -> Self {
        Self { coeffs }
    }

    // Evaluates the polynomial at a given point `x` (which is a `FieldElement`).
    // This function implements Horner's method, evaluating the polynomial by
    // iterating through the coefficients and computing the result.
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        let mut xi = x.field.one();
        let mut value = x.field.zero();
        for c in self.coeffs.clone() {
            value = value + c * xi;
            xi = xi * x;
        }

        value
    }

    // Evaluates the polynomial over an entire domain of points (a vector of `FieldElement`s).
    // Returns a vector of the results for each point in the domain.
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
/// * `poly` - The input polynomial to be folded.
/// * `beta` - A random field element used for folding.
///
/// # Returns
///
/// A new `Polynomial` instance where the even-indexed and odd-indexed coefficients are combined using the folding technique.
pub fn fold_polynomial(poly: &Polynomial, beta: &FieldElement) -> Polynomial {
    let coeffs = poly.coeffs.clone();

    // split polynomial into even and odd indexes,
    // multiply the odd indexes by beta and return the vector of folded polynomial coefficients
    let even: Vec<FieldElement> = coeffs.iter().step_by(2).cloned().collect();
    let odd: Vec<FieldElement> = coeffs
        .iter()
        .skip(1)
        .step_by(2)
        .cloned()
        .map(|o| o * *beta) //Multiply odd-indexed coefficients by `beta`.
        .collect();

    // Combine the even and odd coefficients by adding corresponding elements.
    let coeffs = even
        .iter()
        .zip(odd.iter())
        .map(|(even, odd)| *even + *odd)
        .collect();

    // Return the new folded polynomial.
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

        assert_eq!(res.len(), 3);
        assert_eq!(res[0], FieldElement::new(1, field));
        assert_eq!(res[1], FieldElement::new(6, field));
    }
}
