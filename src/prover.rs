use crate::{Field, FieldElement};
use rand::Rng;
use sha2::{Digest, Sha256};

/// The `ProofStream` struct is used to simulate a transcript between the prover and verifier
/// in an interactive proof system. It stores a sequence of objects (typically commitments or queries),
/// and supports pushing new objects or pulling previously pushed ones in sequence.
#[derive(Default)]
pub struct ProofStream {
    pub objects: Vec<Vec<u8>>,
    pub read_index: i64,
}

impl ProofStream {
    // Creates a new, empty `ProofStream` with no objects and the read index set to zero.
    pub fn new() -> Self {
        Self {
            objects: vec![],
            read_index: 0,
        }
    }

    // Adds a new object (byte array) to the proof stream.
    // This simulates the prover pushing data into the proof stream.
    pub fn push(&mut self, object: &Vec<u8>) {
        self.objects.push(object.clone());
    }

    // Retrieves the next object from the proof stream, advancing the read index.
    // This simulates the verifier pulling data from the proof stream.
    pub fn pull(&mut self) -> Vec<u8> {
        assert!(
            self.read_index < self.objects.len() as i64,
            "Cannot put object, queue empty."
        );
        let obj = self.objects[self.read_index as usize].clone();
        self.read_index += 1;

        obj
    }

    // Serializes the current state of the proof stream to a JSON string.
    // This can be used to store or transfer the proof stream.
    pub fn serialize(&self) -> String {
        serde_json::to_string(&self.objects.clone()).unwrap()
    }

    // Deserializes a JSON string into a new `ProofStream` instance.
    // This can be used to reconstruct a proof stream from serialized data.
    pub fn deserialize(&self, string_obj: String) -> Self {
        let mut ps = ProofStream::new();
        ps.objects = serde_json::from_str(&string_obj).unwrap();

        ps
    }

    // Prover's Fiat-Shamir heuristic.
    // The prover hashes the current state of the proof stream to generate a challenge
    // in the form of a `FieldElement`. This method simulates the prover's Fiat-Shamir process.
    pub fn prover_fiat_shamir(&self, field: &Field) -> FieldElement {
        let mut hasher = Sha256::new();
        hasher.update(self.serialize().as_bytes());

        let result = hasher.finalize();

        // return a field element from bytes
        FieldElement::from_bytes(&result, *field)
    }

    pub fn verifier_fiat_shamir(&self, field: &Field) -> FieldElement {
        let slice = &self.objects[self.read_index as usize];
        let binding = serde_json::to_string(slice).expect("Serialization failed");
        let data = binding.as_bytes();

        let mut hasher = Sha256::new();
        hasher.update(data);

        let result = hasher.finalize();

        // return a field element from bytes
        FieldElement::from_bytes(&result, *field)
    }

    // Generates a pseudorandom index
    pub fn verifier_random_index(&mut self, domain_size: usize) -> usize {
        let mut rng = rand::thread_rng();
        let num: usize = rng.gen();

        // Return the result mod domain_size to fit within the valid index range
        num % domain_size
    }
}
