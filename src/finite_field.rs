use merkle::Hashable;
use modulo::Mod;
use ring::digest::Context;
use serde::{Deserialize, Serialize};
use std::ops::{Add, BitXor, Div, Mul, Neg, Sub};
/// This is not necessary, there are external libraries for this.
/// I am doing an implementation because I want to better understand the concept.

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct FieldElement {
    pub num: i128,
    pub field: Field,
}

impl FieldElement {
    pub fn new(num: i128, field: Field) -> Self {
        Self { num, field }
    }

    pub fn from_bytes(bytes: &[u8], field: Field) -> Self {
        // convert the first 8 bytes of the hash to i64
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[0..8]);
        let num = i64::from_be_bytes(array) as i128;

        FieldElement { num, field }
    }

    pub fn pow(&self, exponent: u32) -> Self {
        let num = self.num.pow(exponent).modulo(self.field.prime);
        Self {
            num,
            field: self.field,
        }
    }

    pub fn inverse(&self) -> Self {
        return self.field.inverse(*self);
    }
}

// need to implement this to be hashable in the merkle tree
impl Hashable for FieldElement {
    fn update_context(&self, context: &mut Context) {
        let bytes: Vec<u8> = self.num.to_le_bytes().to_vec();
        context.update(&bytes);
    }
}

// this is necessary to check if two fields are equal or not.
impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.num == other.num
    }
}

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

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.field.multiply(self, rhs)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.field.subtract(self, rhs)
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.field.divide(self, rhs)
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.field.negate(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct Field {
    pub prime: i128,
}

impl Field {
    pub fn new(prime: i128) -> Self {
        Self { prime }
    }

    pub fn zero(&self) -> FieldElement {
        FieldElement {
            num: 0,
            field: *self,
        }
    }

    pub fn one(&self) -> FieldElement {
        FieldElement {
            num: 1,
            field: *self,
        }
    }

    pub fn multiply(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (left.num * right.num).modulo(self.prime),
            field: *self,
        }
    }

    pub fn add(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (left.num + right.num).modulo(self.prime),
            field: *self,
        }
    }

    pub fn subtract(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        FieldElement {
            num: (self.prime + left.num - right.num).modulo(self.prime),
            field: *self,
        }
    }

    pub fn divide(&self, left: FieldElement, right: FieldElement) -> FieldElement {
        assert!(right.num != 0, "divide by 0");

        let (a, _b, _g) = extended_euclidean_algorithm(right.num, self.prime);
        FieldElement {
            num: (left.num * a).modulo(self.prime),
            field: *self,
        }
    }

    pub fn inverse(&self, operand: FieldElement) -> FieldElement {
        let (a, _b, _c) = extended_euclidean_algorithm(operand.num, self.prime);
        FieldElement {
            num: a,
            field: *self,
        }
    }

    pub fn negate(&self, operand: FieldElement) -> FieldElement {
        FieldElement {
            num: (self.prime - operand.num).modulo(self.prime),
            field: *self,
        }
    }

    pub fn generator(&self) -> FieldElement {
        // using 2 as the generator of the field because 2 has high order
        FieldElement::new(28, *self)
    }

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

    pub fn sample(self, byte_array: Vec<u8>) -> FieldElement {
        let mut acc: i128 = 0;
        for b in byte_array {
            acc = (acc << 8).bitxor(b as i128);
        }

        FieldElement::new(acc.modulo(self.prime), self)
    }
}

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
