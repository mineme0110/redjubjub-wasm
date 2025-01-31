# JubJub Signature Demo

A web application demonstrating JubJub curve signatures using Rust WebAssembly and Next.js.


## Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (v16 or later)
- [npm](https://www.npmjs.com/) (comes with Node.js)

## Setup Instructions

1. **Build the Rust WASM Library**
In the rust project directory
```bash
wasm-pack build --target web
```

2. **Copy WASM Files**
 This will create pkg folder with the wasm files

Create wasm directory in Next.js app

mkdir -p jubjub-signature-app/src/wasm

Copy WASM files
cp -r pkg/ jubjub-signature-app/src/wasm/

4. **Run the Development Server**
```bash
npm run dev
```


The application will be available at [http://localhost:3000](http://localhost:3000)

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