# RedJubjub WebAssembly Demo

A web application demonstrating RedJubjub curve signatures using Rust WebAssembly and Next.js, with support for mnemonic phrase-based key generation.

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
- Display public keys and signatures in hex format
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
  const [message, setMessage] = useState<string>('');
  const [signature, setSignature] = useState<string>('');
  const [mnemonic, setMnemonic] = useState<string>('');

  useEffect(() => {
    // Initialize WASM
    KeyPair.init().then(() => {
      // Generate initial keypair
      const newKeypair = KeyPair.generate();
      setKeypair(newKeypair);
      setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
    });
  }, []);

  const generateNewKeypair = () => {
    const newKeypair = KeyPair.generate();
    setKeypair(newKeypair);
    setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
    setSignature('');
  };

  const generateMnemonic = () => {
    const newMnemonic = KeyPair.generate_mnemonic();
    setMnemonic(newMnemonic);
    const newKeypair = KeyPair.from_mnemonic(newMnemonic);
    setKeypair(newKeypair);
    setPublicKey(Buffer.from(newKeypair.public_key()).toString('hex'));
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
      <button onClick={generateMnemonic}>Generate Mnemonic</button>
      
      {mnemonic && (
        <div>
          <h3>Mnemonic Phrase:</h3>
          <pre>{KeyPair.format_mnemonic(mnemonic)}</pre>
        </div>
      )}

      <div>
        <h3>Public Key:</h3>
        <pre>{publicKey}</pre>
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

## License

This project is licensed under the MIT License - see the LICENSE file for details. 