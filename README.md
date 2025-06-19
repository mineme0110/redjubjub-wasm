# RedJubjub WebAssembly Demo

A web application demonstrating RedJubjub curve signatures using Rust WebAssembly and Next.js, with support for mnemonic phrase-based key generation and key creation from bytes.

## Project Structure 
```
project/
├── rust-jubjub-wasm/          # Rust WASM library
│   ├── src/
│   │   └── lib.rs            # Rust implementation for jubjub keys
│   ├── Cargo.toml
│   └── Cargo.lock
└── jubjub-signature-app/     # Next.js frontend
    ├── src/
    │   ├── app/
    │   │   └── page.tsx
    │   ├── components/
    │   │   └── SignatureComponent.tsx
    │   └── wasm/            # Compiled WASM files
    └── next.config.js
```

## Features

- Generate RedJubjub keypairs
- Sign messages using RedJubjub signatures
- Verify signatures
- Generate and use BIP39 mnemonic phrases
- **Create keypairs from private key bytes**
- **Create keypairs from both private and public key bytes**
- **Create verification-only keypairs from public key bytes**
- Display public and private keys in hex format
- TypeScript support for type safety

## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (v16 or later)
- [npm](https://www.npmjs.com/) (comes with Node.js)

## Setup Instructions

1. **Build the Rust WASM Library**
```bash
# In the rust project root directory
wasm-pack build --target web
```

2. **Set up the Next.js Application**
```bash
# Navigate to the Next.js app directory
cd jubjub-signature-app

# Install dependencies
npm install

# Create wasm directory if it doesn't exist
mkdir -p src/wasm

# Copy WASM files from rust project
cp -r ../pkg/* src/wasm/
```

3. **Run the Development Server**
```bash
# In the jubjub-signature-app directory
npm run dev
```

The application will be available at [http://localhost:3000](http://localhost:3000)

## TypeScript API Usage

### Basic Setup

```typescript
import { KeyPair } from '../wasm/redjubjub_wasm';

// Initialize the WASM module
await KeyPair.init();
```

### Key Generation and Management

```typescript
// Generate a new random key pair
const keypair = KeyPair.generate();

// Get the public key as a hex string
const publicKey = Buffer.from(keypair.public_key()).toString('hex');

// Get the private key as a hex string
const privateKey = Buffer.from(keypair.private_key()).toString('hex');

// Generate a new mnemonic phrase
const mnemonic = KeyPair.generate_mnemonic();

// Format mnemonic with word numbers
const formattedMnemonic = KeyPair.format_mnemonic(mnemonic);
console.log(formattedMnemonic);
// Output:
//  1. word1
//  2. word2
//  ...

// Create a key pair from a mnemonic phrase
const keypairFromMnemonic = KeyPair.from_mnemonic(mnemonic);
```

### Creating Keys from Bytes

```typescript
// Create a keypair from private key bytes (32 bytes)
const privateKeyBytes = Buffer.from('your_private_key_hex_string', 'hex');
const keypairFromPrivate = KeyPair.from_private_key_bytes(privateKeyBytes);

// Create a keypair from both private and public key bytes
const privateKeyBytes = Buffer.from('your_private_key_hex_string', 'hex');
const publicKeyBytes = Buffer.from('your_public_key_hex_string', 'hex');
const keypairFromBoth = KeyPair.from_key_bytes(privateKeyBytes, publicKeyBytes);

// Create a verification-only keypair from public key bytes
const publicKeyBytes = Buffer.from('your_public_key_hex_string', 'hex');
const verificationKeypair = KeyPair.from_public_key_only(publicKeyBytes);
```

### Signing and Verification

```typescript
// Sign a message
const message = new TextEncoder().encode("Hello, World!");
const signature = keypair.sign(message);
const signatureHex = Buffer.from(signature).toString('hex');

// Verify a signature
const isValid = keypair.verify(message, signature);
```

### Complete Example Component

```typescript
import { useState, useEffect } from 'react';
import { KeyPair } from '../wasm/redjubjub_wasm';

export function SignatureComponent() {
  const [keypair, setKeypair] = useState<KeyPair | null>(null);
  const [publicKey, setPublicKey] = useState<string>('');
  const [privateKey, setPrivateKey] = useState<string>('');
  const [message, setMessage] = useState<string>('');
  const [signature, setSignature] = useState<string>('');

  useEffect(() => {
    // Initialize WASM
    KeyPair.init().then(() => {
      // Generate initial keypair
      const newKeypair = KeyPair.generate();
      setKeypair(newKeypair);
      setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
      setPrivateKey(Buffer.from(newKeypair.private_key()).toString('hex'));
    });
  }, []);

  const generateNewKeypair = () => {
    const newKeypair = KeyPair.generate();
    setKeypair(newKeypair);
    setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
    setPrivateKey(Buffer.from(newKeypair.private_key()).toString('hex'));
    setSignature('');
  };

  const createFromPrivateKey = (privateKeyHex: string) => {
    try {
      const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
      const newKeypair = KeyPair.from_private_key_bytes(privateKeyBytes);
      setKeypair(newKeypair);
      setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
      setPrivateKey(Buffer.from(newKeypair.private_key()).toString('hex'));
    } catch (error) {
      console.error('Error creating keypair from private key:', error);
    }
  };

  const createFromKeyBytes = (privateKeyHex: string, publicKeyHex: string) => {
    try {
      const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
      const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
      const newKeypair = KeyPair.from_key_bytes(privateKeyBytes, publicKeyBytes);
      setKeypair(newKeypair);
      setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
      setPrivateKey(Buffer.from(newKeypair.private_key()).toString('hex'));
    } catch (error) {
      console.error('Error creating keypair from key bytes:', error);
    }
  };

  const signMessage = () => {
    if (!keypair || !message) return;
    const messageBytes = new TextEncoder().encode(message);
    const sig = keypair.sign(messageBytes);
    setSignature(Buffer.from(sig).toString('hex'));
  };

  const verifySignature = () => {
    if (!keypair || !message || !signature) return;
    const messageBytes = new TextEncoder().encode(message);
    const sigBytes = Buffer.from(signature, 'hex');
    const isValid = keypair.verify(messageBytes, sigBytes);
    alert(isValid ? 'Signature is valid!' : 'Signature is invalid!');
  };

  return (
    <div>
      <button onClick={generateNewKeypair}>Generate New Keypair</button>
      
      <div>
        <h3>Create from Private Key:</h3>
        <input
          type="text"
          placeholder="Enter private key hex"
          onChange={(e) => createFromPrivateKey(e.target.value)}
        />
      </div>

      <div>
        <h3>Create from Key Bytes:</h3>
        <input
          type="text"
          placeholder="Private key hex"
          onChange={(e) => {
            const publicKeyInput = document.getElementById('publicKeyInput') as HTMLInputElement;
            if (publicKeyInput) {
              createFromKeyBytes(e.target.value, publicKeyInput.value);
            }
          }}
        />
        <input
          id="publicKeyInput"
          type="text"
          placeholder="Public key hex"
          onChange={(e) => {
            const privateKeyInput = document.getElementById('privateKeyInput') as HTMLInputElement;
            if (privateKeyInput) {
              createFromKeyBytes(privateKeyInput.value, e.target.value);
            }
          }}
        />
      </div>

      <div>
        <h3>Public Key:</h3>
        <pre>{publicKey}</pre>
      </div>

      <div>
        <h3>Private Key:</h3>
        <pre>{privateKey}</pre>
      </div>

      <div>
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter message to sign"
        />
        <button onClick={signMessage}>Sign Message</button>
      </div>

      {signature && (
        <div>
          <h3>Signature:</h3>
          <pre>{signature}</pre>
          <button onClick={verifySignature}>Verify Signature</button>
        </div>
      )}
    </div>
  );
}
```

## Key Creation Methods

### 1. `from_private_key_bytes(private_key_bytes: &[u8]) -> Result<KeyPair, String>`

Creates a complete KeyPair from a 32-byte private key. The public key is automatically derived from the private key.

**Parameters:**
- `private_key_bytes`: A byte array of exactly 32 bytes representing the private key

**Returns:**
- `Ok(KeyPair)` if successful
- `Err(String)` if the private key is invalid or wrong length

**Example:**
```typescript
const privateKeyHex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
const keypair = KeyPair.from_private_key_bytes(privateKeyBytes);
```

### 2. `from_key_bytes(private_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<KeyPair, String>`

Creates a KeyPair from both private and public key bytes. This method validates that the public key corresponds to the private key.

**Parameters:**
- `private_key_bytes`: A byte array of exactly 32 bytes representing the private key
- `public_key_bytes`: A byte array of exactly 32 bytes representing the public key

**Returns:**
- `Ok(KeyPair)` if successful and keys match
- `Err(String)` if keys are invalid, wrong length, or don't match

**Example:**
```typescript
const privateKeyHex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const publicKeyHex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
const keypair = KeyPair.from_key_bytes(privateKeyBytes, publicKeyBytes);
```

### 3. `from_public_key_only(public_key_bytes: &[u8]) -> Result<KeyPair, String>`

Creates a verification-only KeyPair from public key bytes. This KeyPair can only verify signatures, not create them.

**Parameters:**
- `public_key_bytes`: A byte array of exactly 32 bytes representing the public key

**Returns:**
- `Ok(KeyPair)` if successful
- `Err(String)` if the public key is invalid or wrong length

**Example:**
```typescript
const publicKeyHex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
const verificationKeypair = KeyPair.from_public_key_only(publicKeyBytes);
```

## Common Issues and Solutions

1. **WASM Loading Issues**
   - Ensure `next.config.js` has the correct WASM configuration:
   ```javascript
   const nextConfig = {
     webpack: (config) => {
       config.experiments = { asyncWebAssembly: true };
       return config;
     },
   };
   ```

2. **TypeScript Type Definitions**
   - The WASM module includes TypeScript definitions
   - Import types from the generated `.d.ts` file

3. **Memory Management**
   - The WASM module handles memory cleanup automatically
   - No manual memory management required

4. **Key Length Validation**
   - Private keys must be exactly 32 bytes (64 hex characters)
   - Public keys must be exactly 32 bytes (64 hex characters)
   - Invalid lengths will return an error

5. **Key Mismatch Errors**
   - When using `from_key_bytes()`, ensure the public key corresponds to the private key
   - The method will validate this automatically

## Development

To make changes to the Rust code:

1. Modify the Rust code in `src/lib.rs`
2. Rebuild the WASM package:
```bash
wasm-pack build --target web
```
3. Copy the new WASM files to the Next.js app:
```bash
cp -r pkg/* jubjub-signature-app/src/wasm/
```
4. Restart the Next.js development server

## Security Considerations

- Private keys should be handled securely and never exposed in logs or error messages
- When creating keys from bytes, validate the input format and length
- The `from_key_bytes()` method provides additional security by validating key correspondence
- Use `from_public_key_only()` when you only need verification capabilities

## License

This project is licensed under the MIT License - see the LICENSE file for details. 