use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;
use rand::rngs::StdRng;
use rand::SeedableRng;
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

    pub fn from_seed(seed: &[u8]) -> Self {
        // Create a deterministic RNG from the seed
        let mut rng = StdRng::from_seed(seed.try_into().expect("Seed must be 32 bytes"));
        let private = SigningKey::<Binding>::new(&mut rng);
        let public = VerificationKey::from(&private);
        KeyPair { private, public }
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| format!("Invalid mnemonic phrase: {}", e))?;

        let seed = mnemonic.to_seed("");

        let seed_bytes: [u8; 32] = seed[..32]
            .try_into()
            .map_err(|_| "Failed to convert seed to 32 bytes")?;

        Ok(Self::from_seed(&seed_bytes))
    }

    pub fn generate_mnemonic() -> String {
        let entropy = rand::random::<[u8; 32]>();
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");
        mnemonic.to_string()
    }

    pub fn format_mnemonic(mnemonic: &str) -> String {
        mnemonic
            .split_whitespace()
            .enumerate()
            .map(|(i, word)| format!("{:2}. {}", i + 1, word))
            .collect::<Vec<String>>()
            .join("\n")
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
    fn test_keypair_from_seed() {
        // Test that same seed produces same keypair
        let seed = [1u8; 32];
        let keypair1 = KeyPair::from_seed(&seed);
        let keypair2 = KeyPair::from_seed(&seed);

        assert_eq!(keypair1.public_key(), keypair2.public_key());

        // Test that different seeds produce different keypairs
        let seed2 = [2u8; 32];
        let keypair3 = KeyPair::from_seed(&seed2);
        assert_ne!(keypair1.public_key(), keypair3.public_key());
    }

    #[test]
    fn test_mnemonic_generation_and_recovery() {
        // Generate a new mnemonic
        let mnemonic = KeyPair::generate_mnemonic();
        println!("\nMnemonic words:\n{}", KeyPair::format_mnemonic(&mnemonic));
        assert!(!mnemonic.is_empty());

        // Create keypair from mnemonic
        let keypair1 =
            KeyPair::from_mnemonic(&mnemonic).expect("Failed to create keypair from mnemonic");

        // Recover the same keypair from the same mnemonic
        let keypair2 =
            KeyPair::from_mnemonic(&mnemonic).expect("Failed to recover keypair from mnemonic");

        // Verify both keypairs are identical
        assert_eq!(keypair1.public_key(), keypair2.public_key());

        // Test with invalid mnemonic
        let invalid_mnemonic = "invalid mnemonic phrase";
        assert!(KeyPair::from_mnemonic(invalid_mnemonic).is_err());
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
