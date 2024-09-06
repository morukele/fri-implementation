use merkle::Hashable;
use modulo::Mod;
use ring::digest::Context;
use serde::{Deserialize, Serialize};
use std::ops::{Add, BitXor, Div, Mul, Neg, Sub};
/// This is not necessary, there are external libraries for this.
/// I am doing an implementation because I want to better understand the concept.

// The `FieldElement` struct represents an element in a finite field, storing
// both the numeric value (`num`) and a reference to the field it belongs to (`field`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct FieldElement {
    pub num: i128,    // The numeric value of the field element.
    pub field: Field, // The field that this element belongs to.
}

impl FieldElement {
    // Creates a new `FieldElement` given a value and a field.
    pub fn new(num: i128, field: Field) -> Self {
        let num = num.modulo(field.prime);
        Self { num, field }
    }

    // Constructs a `FieldElement` from a byte slice, converting the first 8 bytes into an integer.
    // This method allows for generating field elements from a hash or byte array.
    pub fn from_bytes(bytes: &[u8], field: Field) -> Self {
        // convert the first 8 bytes of the hash to i64
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[0..8]);
        let num = i64::from_be_bytes(array) as i128;
        let num = num.modulo(field.prime);

        FieldElement { num, field }
    }

    // Computes the power of the `FieldElement` using a given exponent.
    // The result is taken modulo the prime of the field.
    pub fn pow(&self, exponent: u32) -> Self {
        let num = self.num.pow(exponent).modulo(self.field.prime);
        Self {
            num,
            field: self.field,
        }
    }

    // Returns the multiplicative inverse of the `FieldElement`.
    // This is computed using the field's inverse operation.
    pub fn inverse(&self) -> Self {
        self.field.inverse(*self)
    }
}

// Implements the `Hashable` trait to make `FieldElement` usable in a Merkle tree.
// This is necessary for generating and verifying Merkle proofs.
impl Hashable for FieldElement {
    fn update_context(&self, context: &mut Context) {
        // Converts the field element to little-endian bytes and updates the context.
        let bytes: Vec<u8> = self.num.to_le_bytes().to_vec();
        context.update(&bytes);
    }
}

// Implements the `PartialEq` trait to compare two `FieldElement` instances.
// Two field elements are considered equal if their numeric values are the same.
impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.num == other.num
    }
}

// Implements the `Add` trait to enable addition of two `FieldElement` instances.
impl Add for FieldElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // ensure that the elements are in the same finite fields
        if self.field.prime != rhs.field.prime {
            panic!("cannot add two numbers in different Fields");
        }

        // The addition in a finite field is defined with the modulo operator
        let num = (self.num + rhs.num).modulo(self.field.prime);
        Self {
            num,
            field: self.field,
        }
    }
}

// Implements the `Mul` trait for multiplication of `FieldElement` instances.
impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.field.multiply(self, rhs)
    }
}

// Implements the `Sub` trait for subtraction of `FieldElement` instances.
impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.field.subtract(self, rhs)
    }
}

// Implements the `Div` trait for division of `FieldElement` instances.
impl Div for FieldElement {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.field.divide(self, rhs)
    }
}

// Implements the `Neg` trait for negation of `FieldElement` instances.
impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.field.negate(self)
    }
}

// The `Field` struct represents a finite field defined by a prime modulus.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Field {
    pub prime: i128,
}

impl Field {
    // Creates a new finite field with the given prime modulus.
    pub fn new(prime: i128) -> Self {
        Self { prime }
    }

    // Returns the additive identity (0) for the field.
    pub fn zero(&self) -> FieldElement {
        FieldElement {
            num: 0,
            field: *self,
        }
    }

    // Returns the multiplicative identity (1) for the field.
    pub fn one(&self) -> FieldElement {
        FieldElement {
            num: 1,
            field: *self,
        }
    }

    // Multiplies two `FieldElement` instances and returns the result, reduced modulo the prime.
    pub fn multiply(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (left.num * right.num).modulo(self.prime),
            field: *self,
        }
    }

    // Adds two `FieldElement` instances and returns the result, reduced modulo the prime.
    pub fn add(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (left.num + right.num).modulo(self.prime),
            field: *self,
        }
    }

    // Subtracts the second `FieldElement` from the first, reduced modulo the prime.
    pub fn subtract(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (self.prime + left.num - right.num).modulo(self.prime),
            field: *self,
        }
    }

    // Divides the first `FieldElement` by the second by using the extended Euclidean algorithm.
    pub fn divide(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        assert!(right.num != 0, "divide by 0");

        let (a, _b, _g) = extended_euclidean_algorithm(right.num, self.prime);
        FieldElement {
            num: (left.num * a).modulo(self.prime),
            field: *self,
        }
    }

    // Returns the multiplicative inverse of a `FieldElement` using the extended Euclidean algorithm.
    pub fn inverse(&self, operand: FieldElement) -> FieldElement {
        let (a, _b, _c) = extended_euclidean_algorithm(operand.num, self.prime);
        FieldElement {
            num: a,
            field: *self,
        }
    }

    // Returns the negation of a `FieldElement`.
    pub fn negate(&self, operand: FieldElement) -> FieldElement {
        FieldElement {
            num: (self.prime - operand.num).modulo(self.prime),
            field: *self,
        }
    }

    // Returns a generator for the field. In this case, the number 28 is used as the generator.
    pub fn generator(&self) -> FieldElement {
        // using 2 as the generator of the field because 2 has high order
        FieldElement::new(28, *self)
    }

    // Returns the nth primitive root of unity in the field by exponentiating the generator.
    //NB: didn't use this in the code because it was a very expensive operation
    pub fn primitive_nth_root(&self, n: i128) -> FieldElement {
        let mut root = self.generator(); // Start with the generator of the field
        let mut order = 2;

        // Divide the order of the generator down to n
        while order != n {
            root = root.pow(2);
            order /= 2;
        }

        root
    }

    // Samples a field element from a byte array by treating the array as an integer
    // and reducing it modulo the field's prime.
    pub fn sample(self, byte_array: Vec<u8>) -> FieldElement {
        let mut acc: i128 = 0;
        for b in byte_array {
            acc = (acc << 8).bitxor(b as i128);
        }

        FieldElement::new(acc.modulo(self.prime), self)
    }
}

// Extended Euclidean algorithm used to compute the greatest common divisor (gcd) of two integers.
// This is used to find the multiplicative inverse in the field.
pub fn extended_euclidean_algorithm(a: i128, b: i128) -> (i128, i128, i128) {
    let (mut old_r, mut r) = (a, b);
    let (mut old_s, mut s) = (1, 0);
    let (mut old_t, mut t) = (0, 1);

    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
        (old_t, t) = (t, old_t - quotient * t);
    }

    (old_r, old_s, old_t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_euclidean_algorithm_works() {
        assert_eq!(extended_euclidean_algorithm(101, 13), (1, 4, -31));
        assert_eq!(extended_euclidean_algorithm(123, 19), (1, -2, 13));
        assert_eq!(extended_euclidean_algorithm(25, 36), (1, 13, -9));
        assert_eq!(extended_euclidean_algorithm(69, 54), (3, -7, 9));
        assert_eq!(extended_euclidean_algorithm(55, 79), (1, 23, -16));
        assert_eq!(extended_euclidean_algorithm(33, 44), (11, -1, 1));
        assert_eq!(extended_euclidean_algorithm(50, 70), (10, 3, -2));
    }

    #[test]
    fn finite_field_compare() {
        let field = Field::new(97);
        let a = FieldElement::new(7, field);
        let b = FieldElement::new(6, field);

        assert_ne!(a, b);
        assert_eq!(a, a);
    }

    #[test]
    fn finite_field_add() {
        let field = Field::new(97);

        let a = FieldElement::new(7, field);
        let b = FieldElement::new(12, field);
        let c = FieldElement::new(19, field);

        assert_eq!(a + b, c);
    }

    #[test]
    fn finite_field_subtract() {
        let field = Field::new(97);
        let a = FieldElement::new(12, field);
        let b = FieldElement::new(2, field);
        let c = FieldElement::new(10, field);

        assert_eq!(a - b, c);
    }

    #[test]
    fn finite_field_multiply() {
        let field = Field::new(97);

        let a = FieldElement::new(3, field);
        let b = FieldElement::new(12, field);
        let c = FieldElement::new(36, field);

        assert_eq!(a * b, c);
    }

    #[test]
    fn finite_field_power() {
        let field = Field::new(97);

        let a = FieldElement::new(3, field);
        let c = FieldElement::new(27, field);

        assert_eq!(a.pow(3), c);
    }

    #[test]
    fn finite_field_divide() {
        let field = Field::new(97);

        let mut a = FieldElement::new(2, field);
        let mut b = FieldElement::new(7, field);
        let mut c = FieldElement::new(2, field);

        assert_eq!(a / b, c);

        a = FieldElement::new(7, field);
        b = FieldElement::new(5, field);
        c = FieldElement::new(7, field);

        assert_eq!(a / b, c);
    }
}
