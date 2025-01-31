use rand::rngs::OsRng;
use redjubjub::{Binding, Signature, SigningKey, VerificationKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct KeyPair {
    private: SigningKey<Binding>,
    public: VerificationKey<Binding>,
}

#[wasm_bindgen]
impl KeyPair {
    pub fn generate() -> Self {
        let private = SigningKey::<Binding>::new(OsRng);
        let public = VerificationKey::from(&private);
        KeyPair { private, public }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.private.sign(&mut OsRng, message);
        let sig_bytes: [u8; 64] = sig.into();
        sig_bytes.to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig_bytes: [u8; 64] = signature.try_into().expect("Invalid signature length");
        let sig: Signature<Binding> = sig_bytes.into();
        self.public.verify(message, &sig).is_ok()
    }

    pub fn public_key(&self) -> Vec<u8> {
        let pk: [u8; 32] = self.public.into();
        pk.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public_key().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        assert!(keypair.verify(message, &signature));

        let wrong_message = b"Wrong message";
        assert!(!keypair.verify(wrong_message, &signature));

        let wrong_signature = vec![0u8; 64];
        assert!(!keypair.verify(message, &wrong_signature));
    }

    #[test]
    #[should_panic(expected = "Invalid signature length")]
    fn test_invalid_signature_length() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";
        let invalid_signature = vec![0u8; 32]; // Wrong length
        keypair.verify(message, &invalid_signature);
    }
}
