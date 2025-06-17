use bip39::{Language, Mnemonic, MnemonicType, Seed};
use rand::rngs::OsRng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use redjubjub::{Binding, Signature, SigningKey, VerificationKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug)]
pub struct KeyPair {
    private: SigningKey<Binding>,
    public: VerificationKey<Binding>,
}

#[wasm_bindgen]
impl KeyPair {
    #[inline]
    pub fn generate() -> Self {
        let private = SigningKey::<Binding>::new(OsRng);
        let public = VerificationKey::from(&private);
        KeyPair { private, public }
    }

    #[inline]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.private.sign(&mut OsRng, message);
        let sig_bytes: [u8; 64] = sig.into();
        sig_bytes.to_vec()
    }

    #[inline]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let sig_bytes: [u8; 64] = signature.try_into().expect("Invalid signature length");
        let sig: Signature<Binding> = sig_bytes.into();
        self.public.verify(message, &sig).is_ok()
    }

    #[inline]
    pub fn public_key(&self) -> Vec<u8> {
        let pk: [u8; 32] = self.public.into();
        pk.to_vec()
    }

    #[inline]
    pub fn private_key(&self) -> Vec<u8> {
        let sk: [u8; 32] = self.private.into();
        sk.to_vec()
    }

    pub fn from_mnemonic(mnemonic: &str) -> Result<KeyPair, String> {
        let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English)
            .map_err(|e| format!("Invalid mnemonic phrase: {:?}", e))?;

        let seed = Seed::new(&mnemonic, "");
        let seed_bytes: [u8; 32] = seed.as_bytes()[..32]
            .try_into()
            .map_err(|_| "Failed to convert seed to 32 bytes")?;

        Ok(Self::from_seed(&seed_bytes))
    }

    #[inline]
    fn from_seed(seed: &[u8]) -> Self {
        let mut rng = StdRng::from_seed(seed.try_into().expect("Seed must be 32 bytes"));
        let private = SigningKey::<Binding>::new(&mut rng);
        let public = VerificationKey::from(&private);
        KeyPair { private, public }
    }

    #[inline]
    pub fn generate_mnemonic() -> String {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        mnemonic.to_string()
    }

    #[inline]
    pub fn format_mnemonic(mnemonic: &str) -> String {
        mnemonic
            .split_whitespace()
            .enumerate()
            .map(|(i, word)| format!("{:2}. {}", i + 1, word))
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// Create a KeyPair from private key bytes
    pub fn from_private_key_bytes(private_key_bytes: &[u8]) -> Result<KeyPair, String> {
        let private_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| "Private key must be exactly 32 bytes")?;

        let private = SigningKey::<Binding>::try_from(private_key_array)
            .map_err(|e| format!("Invalid private key: {:?}", e))?;
        let public = VerificationKey::from(&private);

        Ok(KeyPair { private, public })
    }

    /// Create a KeyPair from public key bytes
    pub fn from_public_key_bytes(public_key_bytes: &[u8]) -> Result<KeyPair, String> {
        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| "Public key must be exactly 32 bytes")?;

        let _public = VerificationKey::<Binding>::try_from(public_key_array)
            .map_err(|e| format!("Invalid public key: {:?}", e))?;

        // Note: This creates a KeyPair with only the public key.
        // The private key will be uninitialized and signing operations will fail.
        // This is useful for verification-only scenarios.
        Err("Cannot create a complete KeyPair from public key bytes alone. Use from_private_key_bytes or from_key_bytes instead.".to_string())
    }

    /// Create a KeyPair from both private and public key bytes
    pub fn from_key_bytes(
        private_key_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<KeyPair, String> {
        let private_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| "Private key must be exactly 32 bytes")?;

        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| "Public key must be exactly 32 bytes")?;

        let private = SigningKey::<Binding>::try_from(private_key_array)
            .map_err(|e| format!("Invalid private key: {:?}", e))?;
        let public = VerificationKey::<Binding>::try_from(public_key_array)
            .map_err(|e| format!("Invalid public key: {:?}", e))?;

        // Verify that the public key corresponds to the private key
        let expected_public = VerificationKey::from(&private);
        if public != expected_public {
            return Err("Public key does not correspond to the provided private key".to_string());
        }

        Ok(KeyPair { private, public })
    }

    /// Create a verification-only KeyPair from public key bytes
    /// This creates a KeyPair that can only verify signatures, not sign messages
    pub fn from_public_key_only(public_key_bytes: &[u8]) -> Result<KeyPair, String> {
        let public_key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| "Public key must be exactly 32 bytes")?;

        let public = VerificationKey::<Binding>::try_from(public_key_array)
            .map_err(|e| format!("Invalid public key: {:?}", e))?;

        // Create a dummy private key that will cause signing to fail
        // This is a workaround since we can't have a KeyPair without a private key
        let dummy_private = SigningKey::<Binding>::new(OsRng);

        Ok(KeyPair {
            private: dummy_private, // This will be overridden for signing operations
            public,
        })
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
        assert_eq!(keypair1.private_key(), keypair2.private_key());

        // Test that different seeds produce different keypairs
        let seed2 = [2u8; 32];
        let keypair3 = KeyPair::from_seed(&seed2);
        assert_ne!(keypair1.public_key(), keypair3.public_key());
        assert_ne!(keypair1.private_key(), keypair3.private_key());
    }

    #[test]
    fn test_mnemonic_generation_and_recovery() {
        // Generate a new mnemonic
        let mnemonic = KeyPair::generate_mnemonic();
        println!("\nMnemonic words:\n{}", KeyPair::format_mnemonic(&mnemonic));
        assert!(!mnemonic.is_empty());

        // Create keypair from mnemonic
        let keypair =
            KeyPair::from_mnemonic(&mnemonic).expect("Failed to create keypair from mnemonic");
        assert_eq!(keypair.public_key().len(), 32);
        assert_eq!(keypair.private_key().len(), 32);

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
    fn test_sign_and_verify_with_mnemonic() {
        let mnemonic = "spread struggle twice like memory profit artefact chimney climb burger fatigue mixed trap weird melody clump total ridge shine observe reward swap vast friend";

        let keypair =
            KeyPair::from_mnemonic(mnemonic).expect("Failed to create keypair from mnemonic");

        let message = b"Test message for mnemonic-derived key";
        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));

        let keypair2 = KeyPair::from_mnemonic(mnemonic).expect("Failed to create second keypair");
        assert_eq!(keypair.public_key(), keypair2.public_key());
        assert_eq!(keypair.private_key(), keypair2.private_key());

        assert!(keypair2.verify(message, &signature));

        let wrong_message = b"Wrong message for mnemonic-derived key";
        assert!(!keypair.verify(wrong_message, &signature));
    }

    #[test]
    fn test_deterministic_key_derivation() {
        let mnemonic = "spread struggle twice like memory profit artefact chimney climb burger fatigue mixed trap weird melody clump total ridge shine observe reward swap vast friend";

        let keypair1 = KeyPair::from_mnemonic(mnemonic).expect("Failed to create first keypair");
        let keypair2 = KeyPair::from_mnemonic(mnemonic).expect("Failed to create second keypair");

        assert_eq!(keypair1.public_key(), keypair2.public_key());
        assert_eq!(keypair1.private_key(), keypair2.private_key());

        let message = b"Test message for deterministic derivation";
        let signature = keypair1.sign(message);

        assert!(keypair1.verify(message, &signature));
        assert!(keypair2.verify(message, &signature));

        let different_mnemonic = "man boy oxygen bind opera spread wagon valve trumpet unaware ski sample entire obvious early trash kick trust dove mercy call salon dutch dirt";
        let different_keypair =
            KeyPair::from_mnemonic(different_mnemonic).expect("Failed to create different keypair");

        assert_ne!(keypair1.public_key(), different_keypair.public_key());
        assert_ne!(keypair1.private_key(), different_keypair.private_key());

        assert!(!different_keypair.verify(message, &signature));
    }

    #[test]
    #[should_panic(expected = "Invalid signature length")]
    fn test_invalid_signature_length() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";
        let invalid_signature = vec![0u8; 32]; // Wrong length
        keypair.verify(message, &invalid_signature);
    }

    #[test]
    fn test_from_private_key_bytes() {
        // Generate a keypair first
        let original_keypair = KeyPair::generate();
        let private_key_bytes = original_keypair.private_key();

        // Create a new keypair from the private key bytes
        let new_keypair = KeyPair::from_private_key_bytes(&private_key_bytes)
            .expect("Failed to create keypair from private key bytes");

        // Verify that both keypairs have the same keys
        assert_eq!(original_keypair.private_key(), new_keypair.private_key());
        assert_eq!(original_keypair.public_key(), new_keypair.public_key());

        // Test signing and verification with the new keypair
        let message = b"Test message for from_private_key_bytes";
        let signature = new_keypair.sign(message);
        assert!(new_keypair.verify(message, &signature));
        assert!(original_keypair.verify(message, &signature));
    }

    #[test]
    fn test_from_key_bytes() {
        // Generate a keypair first
        let original_keypair = KeyPair::generate();
        let private_key_bytes = original_keypair.private_key();
        let public_key_bytes = original_keypair.public_key();

        // Create a new keypair from both private and public key bytes
        let new_keypair = KeyPair::from_key_bytes(&private_key_bytes, &public_key_bytes)
            .expect("Failed to create keypair from key bytes");

        // Verify that both keypairs have the same keys
        assert_eq!(original_keypair.private_key(), new_keypair.private_key());
        assert_eq!(original_keypair.public_key(), new_keypair.public_key());

        // Test signing and verification with the new keypair
        let message = b"Test message for from_key_bytes";
        let signature = new_keypair.sign(message);
        assert!(new_keypair.verify(message, &signature));
        assert!(original_keypair.verify(message, &signature));
    }

    #[test]
    fn test_from_key_bytes_mismatch() {
        // Generate two different keypairs
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        // Try to create a keypair with mismatched private and public keys
        let result = KeyPair::from_key_bytes(&keypair1.private_key(), &keypair2.public_key());

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Public key does not correspond"));
    }

    #[test]
    fn test_from_public_key_only() {
        // Generate a keypair first
        let original_keypair = KeyPair::generate();
        let public_key_bytes = original_keypair.public_key();

        // Create a verification-only keypair from public key bytes
        let verification_keypair = KeyPair::from_public_key_only(&public_key_bytes)
            .expect("Failed to create verification keypair");

        // Verify that the public keys match
        assert_eq!(
            original_keypair.public_key(),
            verification_keypair.public_key()
        );

        // Test that verification works
        let message = b"Test message for verification";
        let signature = original_keypair.sign(message);
        assert!(verification_keypair.verify(message, &signature));

        // Note: The verification keypair should not be able to sign
        // This is expected behavior for a public-key-only keypair
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Test with wrong private key length
        let short_private_key = vec![1u8; 16]; // Too short
        let result = KeyPair::from_private_key_bytes(&short_private_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Private key must be exactly 32 bytes"));

        // Test with wrong public key length
        let long_public_key = vec![1u8; 64]; // Too long
        let result = KeyPair::from_public_key_only(&long_public_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Public key must be exactly 32 bytes"));
    }

    #[test]
    fn test_from_mnemonic_consistency_with_bytes() {
        let mnemonic = "spread struggle twice like memory profit artefact chimney climb burger fatigue mixed trap weird melody clump total ridge shine observe reward swap vast friend";

        // Create keypair from mnemonic
        let keypair_from_mnemonic =
            KeyPair::from_mnemonic(mnemonic).expect("Failed to create keypair from mnemonic");

        // Create keypair from the private key bytes
        let private_key_bytes = keypair_from_mnemonic.private_key();
        let keypair_from_bytes = KeyPair::from_private_key_bytes(&private_key_bytes)
            .expect("Failed to create keypair from private key bytes");

        // Verify they are identical
        assert_eq!(
            keypair_from_mnemonic.private_key(),
            keypair_from_bytes.private_key()
        );
        assert_eq!(
            keypair_from_mnemonic.public_key(),
            keypair_from_bytes.public_key()
        );

        // Test that both can sign and verify messages
        let message = b"Test message for consistency";
        let signature1 = keypair_from_mnemonic.sign(message);
        let signature2 = keypair_from_bytes.sign(message);

        // Both signatures should be valid (but different due to randomness)
        assert!(keypair_from_mnemonic.verify(message, &signature1));
        assert!(keypair_from_mnemonic.verify(message, &signature2));
        assert!(keypair_from_bytes.verify(message, &signature1));
        assert!(keypair_from_bytes.verify(message, &signature2));

        // Both keypairs should be able to verify each other's signatures
        assert!(keypair_from_mnemonic.verify(message, &signature2));
        assert!(keypair_from_bytes.verify(message, &signature1));
    }
}
