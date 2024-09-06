# Fast Reed-Solomon IOPP (Interactive Oracle Proof of Proximity) Implementation

This project is a simplified implementation of the Fast Reed-Solomon Interactive Oracle Proof of Proximity (FRS-IOPP). It encodes a polynomial and performs a commit phase and a query phase, demonstrating a basic proof of proximity.

## Project Overview

This project encodes a sample polynomial using FRS-IOPP and demonstrates the commit and query phases of the protocol. The program prints out the evaluation results from these phases, helping the user understand how the protocol folds and reduces the original polynomial, and how it handles queries.

### Polynomial: 

> 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 0x^7

The polynomial is evaluated over a domain generated from powers of a given element 28, and the program demonstrates the commit and query phases with a fixed number of queries.

## Running Instruction

1. Clone the repository.

```bash
git clone https://github.com/morukele/fri-implementation.git
```

2. Navigate into the project directory

3. Compile the project with. 

```bash
    cargo build
```

4. Run the project with.

```bash
   cargo Run
```

After running the program, it will output the following:

- The initial polynomial.
- The size of the evaluation domain and the prime field.
- The result of the commit phase, including the folded polynomials.
- The final result of the commit phase.
- The results of the query phase, displaying evaluations of the layers at specific points.

## Unit Test

The project includes unit tests that validate key components of the FRS-IOPP implementation, including polynomial operations, field element handling, and the commit/query phases.

To run the unit tests, use the following command:

```bash
    cargo test
```

This will run all defined unit tests and output the test results. The tests check the correctness of the polynomial folding, domain evaluation, and finite field behavior.
