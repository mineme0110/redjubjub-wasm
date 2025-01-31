# JubJub Signature Demo

A web application demonstrating JubJub curve signatures using Rust WebAssembly and Next.js.

## Project Structure 

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

## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (v16 or later)
- [npm](https://www.npmjs.com/) (comes with Node.js)

## Setup Instructions After Cloning

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

## Common Setup Issues

1. **Missing WASM Files**
   - Ensure you've run `wasm-pack build --target web` in the root directory
   - Check that all files from `pkg/` are copied to `jubjub-signature-app/src/wasm/`

2. **Node Modules Issues**
   - If you encounter module-related errors, try:
     ```bash
     cd jubjub-signature-app
     rm -rf node_modules
     rm package-lock.json
     npm install
     ```

3. **WASM Loading Issues**
   - Verify `next.config.js` has the correct WASM configuration
   - Check browser console for WASM-related errors

## Usage

1. Click "Generate Keypair" to create a new JubJub keypair
2. Enter a message in the input field
3. Click "Sign Message" to create a signature
4. Click "Verify Signature" to verify the signature

## Features

- Generate JubJub keypairs
- Sign messages using JubJub signatures
- Verify signatures
- Display public keys and signatures in hex format

## Technical Details

### Rust WASM Library
- Uses the JubJub elliptic curve for signatures
- Compiled to WebAssembly using wasm-pack
- Exports KeyPair generation, signing, and verification functions

### Next.js Frontend
- Built with Next.js 13+ App Router
- Uses TypeScript for type safety
- Tailwind CSS for styling
- WebAssembly integration for cryptographic operations

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