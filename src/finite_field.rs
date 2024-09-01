use std::ops::{Add, Div, Mul, Sub};

use modulo::Mod;

/// This is not necessary, there are external libraries for this.
/// I am doing an implementation because I want to better understand the concept.

#[derive(Debug, Clone)]
pub struct FiniteField {
    pub num: u64,
    pub prime: u64,
}

impl FiniteField {
    pub fn new(num: u64, prime: u64) -> Self {
        // check that num is between 0 and prime-1 inclusive.
        if num >= prime {
            panic!("Num {} not in field range 0 to {}", num, prime - 1);
        }

        Self { num, prime }
    }

    pub fn pow(&self, exponent: u32) -> Self {
        let num = self.num.pow(exponent).modulo(self.prime);
        Self {
            num,
            prime: self.prime,
        }
    }
}

// this is necessary to check if two fields are equal or not.
impl PartialEq for FiniteField {
    fn eq(&self, other: &Self) -> bool {
        self.num == other.num && self.prime == other.prime
    }
}

impl Eq for FiniteField {}

// Implement the OPERATIONS for the finite field using the Rust Traits
impl Add for FiniteField {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // ensure that the elements are in the same finite fields
        if self.prime != rhs.prime {
            panic!("cannot add two numbers in different Fields");
        }

        // The addition in a finite field is defined with the modulo operator
        let num = (self.num + rhs.num).modulo(self.prime);
        Self {
            num,
            prime: self.prime,
        }
    }
}

impl Sub for FiniteField {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.prime != rhs.prime {
            panic!("cannot subtract two numbers in different Fields");
        }

        let num = (self.num - rhs.num).modulo(self.prime);

        Self {
            num,
            prime: self.prime,
        }
    }
}

impl Mul for FiniteField {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if self.prime != rhs.prime {
            panic!("cannot multiply two numbers in different Fields");
        }

        let num = (self.num * rhs.num).modulo(self.prime);
        Self {
            num,
            prime: self.prime,
        }
    }
}

impl Div for FiniteField {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        if self.prime != rhs.prime {
            panic!("cannot divide two numbers in different Fields");
        }

        // Use Fermat's little theorem
        // self.num.pow(p - 1) % p == 1
        let exp = (rhs.prime - 2) as u32;
        let num_pow = rhs.pow(exp);
        let result = self.num * num_pow.num;
        Self {
            num: result % self.prime,
            prime: self.prime,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_field_compare() {
        let a = FiniteField::new(7, 13);
        let b = FiniteField::new(6, 13);

        assert_ne!(a, b);
        assert_eq!(a, a);
    }

    #[test]
    fn finite_field_add() {
        let a = FiniteField::new(7, 13);
        let b = FiniteField::new(12, 13);
        let c = FiniteField::new(6, 13);

        assert_eq!(a + b, c);
    }

    #[test]
    fn finite_field_subtract() {
        let a = FiniteField::new(12, 13);
        let b = FiniteField::new(2, 13);
        let c = FiniteField::new(10, 13);

        assert_eq!(a - b, c);
    }

    #[test]
    fn finite_field_multiply() {
        let a = FiniteField::new(3, 13);
        let b = FiniteField::new(12, 13);
        let c = FiniteField::new(10, 13);

        assert_eq!(a * b, c);
    }

    #[test]
    fn finite_field_power() {
        let a = FiniteField::new(3, 13);
        let c = FiniteField::new(1, 13);

        assert_eq!(a.pow(3), c);
    }

    #[test]
    fn finite_field_divide() {
        let prime = 19;
        let mut a = FiniteField::new(2, prime);
        let mut b = FiniteField::new(7, prime);
        let mut c = FiniteField::new(3, prime);

        assert_eq!(a / b, c);

        a = FiniteField::new(7, prime);
        b = FiniteField::new(5, prime);
        c = FiniteField::new(9, prime);

        assert_eq!(a / b, c);
    }
}
