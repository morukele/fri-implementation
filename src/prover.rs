use sha2::{Digest, Sha256};

use crate::{Field, FieldElement};

#[derive(Default)]
pub struct ProofStream {
    pub objects: Vec<Vec<u8>>,
    pub read_index: i64,
}

impl ProofStream {
    pub fn new() -> Self {
        Self {
            objects: vec![],
            read_index: 0,
        }
    }

    pub fn push(&mut self, object: &Vec<u8>) {
        self.objects.push(object.clone());
    }

    pub fn pull(&mut self) -> Vec<u8> {
        assert!(
            self.read_index < self.objects.len() as i64,
            "Cannot put object, queue empty."
        );
        let obj = self.objects[self.read_index as usize].clone();
        self.read_index += 1;

        obj
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(&self.objects.clone()).unwrap()
    }

    pub fn deserialize(&self, string_obj: String) -> Self {
        let mut ps = ProofStream::new();
        ps.objects = serde_json::from_str(&string_obj).unwrap();

        ps
    }

    pub fn prover_fiat_shamir(&self, field: &Field) -> FieldElement {
        let mut hasher = Sha256::new();
        hasher.update(self.serialize().as_bytes());

        let result = hasher.finalize();

        // return a field element from bytes
        FieldElement::from_bytes(&result, field.clone())
    }

    pub fn verifier_fiat_shamir(self, field: &Field) -> FieldElement {
        let sliced_objects = &self.objects[..self.read_index as usize];
        let serialized_data = serde_json::to_string(&sliced_objects).unwrap();

        // perform the hashing
        let mut hasher = Sha256::new();
        hasher.update(&serialized_data);
        let result = hasher.finalize();

        // return a field element from the hashing
        FieldElement::from_bytes(&result, field.clone())
    }
}
