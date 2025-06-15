'use client';

import { useEffect, useState } from 'react';
import init, { KeyPair } from '../wasm/redjubjub_wasm';

export default function SignatureComponent() {
    const [isWasmLoaded, setIsWasmLoaded] = useState(false);
    const [keyPair, setKeyPair] = useState<KeyPair | null>(null);
    const [publicKey, setPublicKey] = useState('');
    const [privateKey, setPrivateKey] = useState('');
    const [message, setMessage] = useState('');
    const [signature, setSignature] = useState('');
    const [isValid, setIsValid] = useState<boolean | null>(null);
    const [mnemonic, setMnemonic] = useState('');
    const [formattedMnemonic, setFormattedMnemonic] = useState('');

    useEffect(() => {
        console.log('Initializing WASM...');
        init()
            .then(() => {
                console.log('WASM initialized successfully');
                setIsWasmLoaded(true);
            })
            .catch(err => {
                console.error('Failed to initialize WASM:', err);
            });
    }, []);

    const handleGenerateKeys = () => {
        console.log('Generating new keypair...');
        try {
            const newKeyPair = KeyPair.generate();
            setKeyPair(newKeyPair);
            const pubKey = newKeyPair.public_key();
            const pubKeyHex = Buffer.from(pubKey).toString('hex');
            console.log('Generated public key:', pubKeyHex);
            setPublicKey(pubKeyHex);
            setPrivateKey('private key generated'); // Just an indicator since we don't expose private key
            console.log('Keypair generated successfully');
        } catch (error) {
            console.error('Error generating keys:', error);
        }
    };

    const handleGenerateMnemonic = () => {
        console.log('Generating new mnemonic...');
        try {
            const newMnemonic = KeyPair.generate_mnemonic();
            setMnemonic(newMnemonic);
            const formatted = KeyPair.format_mnemonic(newMnemonic);
            setFormattedMnemonic(formatted);
            console.log('Generated mnemonic:', formatted);
        } catch (error) {
            console.error('Error generating mnemonic:', error);
        }
    };

    const handleCreateFromMnemonic = () => {
        console.log('Creating keypair from mnemonic...');
        try {
            if (!mnemonic) {
                console.log('No mnemonic provided');
                return;
            }
            const newKeyPair = KeyPair.from_mnemonic(mnemonic);
            if (newKeyPair) {
                setKeyPair(newKeyPair);
                const pubKey = newKeyPair.public_key();
                const pubKeyHex = Buffer.from(pubKey).toString('hex');
                setPublicKey(pubKeyHex);
                setPrivateKey('private key generated from mnemonic');
                console.log('Keypair created from mnemonic successfully');
            }
        } catch (error) {
            console.error('Error creating keypair from mnemonic:', error);
        }
    };

    const handleSign = () => {
        console.log('Attempting to sign message...');
        console.log('KeyPair present:', !!keyPair);
        console.log('Message present:', !!message);
        console.log('Message content:', message);

        try {
            if (!keyPair || !message) {
                console.log('Cannot sign: missing keypair or message');
                return;
            }
            const messageBytes = new TextEncoder().encode(message);
            console.log('Message bytes:', messageBytes);
            const sig = keyPair.sign(messageBytes);
            const sigHex = Buffer.from(sig).toString('hex');
            console.log('Generated signature:', sigHex);
            setSignature(sigHex);
        } catch (error) {
            console.error('Error signing message:', error);
        }
    };

    const handleVerify = () => {
        console.log('Attempting to verify signature...');
        console.log('KeyPair present:', !!keyPair);
        console.log('Message present:', !!message);
        console.log('Signature present:', !!signature);

        try {
            if (!keyPair || !message || !signature) {
                console.log('Cannot verify: missing keypair, message, or signature');
                return;
            }
            const messageBytes = new TextEncoder().encode(message);
            const signatureBytes = Uint8Array.from(Buffer.from(signature, 'hex'));
            const valid = keyPair.verify(messageBytes, signatureBytes);
            console.log('Signature verification result:', valid);
            setIsValid(valid);
        } catch (error) {
            console.error('Error verifying signature:', error);
        }
    };

    console.log('Current state:', {
        isWasmLoaded,
        hasKeyPair: !!keyPair,
        publicKey,
        hasPrivateKey: !!privateKey,
        message,
        signature,
        isValid
    });

    if (!isWasmLoaded) {
        return <div>Loading WASM...</div>;
    }

    return (
        <div className="max-w-2xl mx-auto p-4 space-y-6">
            <h1 className="text-2xl font-bold mb-4">JubJub Signature Demo</h1>

            <div className="space-y-4">
                <div className="space-y-2">
                    <div className="space-y-4 border p-4 rounded">
                        <h2 className="text-lg font-semibold">Mnemonic Phrase</h2>
                        <button
                            onClick={handleGenerateMnemonic}
                            className="bg-green-500 text-white px-4 py-2 rounded"
                        >
                            Generate New Mnemonic
                        </button>

                        <div>
                            <label className="block text-sm font-medium">Mnemonic Phrase:</label>
                            <textarea
                                value={mnemonic}
                                onChange={(e) => setMnemonic(e.target.value)}
                                placeholder="Enter or paste your mnemonic phrase here (space-separated words)"
                                className="text-black w-full p-2 border rounded h-24"
                            />
                        </div>

                        {formattedMnemonic && (
                            <div className="bg-gray-100 p-4 rounded">
                                <h3 className="font-medium mb-2">Formatted Mnemonic:</h3>
                                <pre className="whitespace-pre-wrap text-black">{formattedMnemonic}</pre>
                            </div>
                        )}

                        <button
                            onClick={handleCreateFromMnemonic}
                            disabled={!mnemonic}
                            className="bg-purple-500 text-white px-4 py-2 rounded disabled:opacity-50"
                        >
                            Create Keypair from Mnemonic
                        </button>
                    </div>
                </div>

                <div className="space-y-2">
                    <div>
                        <label className="block text-sm font-medium">Public Key:</label>
                        <input
                            type="text"
                            value={publicKey}
                            readOnly
                            className="text-black w-full p-2 border rounded"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium">Private Key:</label>
                        <input
                            type="text"
                            value={privateKey}
                            readOnly
                            className="text-black w-full p-2 border rounded"
                        />
                    </div>
                </div>

                <div>
                    <label className="block text-sm font-medium">Message:</label>
                    <input
                        type="text"
                        value={message}
                        onChange={(e) => setMessage(e.target.value)}
                        className="text-black w-full p-2 border rounded"
                    />
                </div>

                <button
                    onClick={handleSign}
                    disabled={!keyPair || !message}
                    className="bg-green-500 text-white px-4 py-2 rounded disabled:opacity-50"
                >
                    Sign Message
                </button>

                <div>
                    <label className="block text-sm font-medium">Signature:</label>
                    <input
                        type="text"
                        value={signature}
                        readOnly
                        className="text-black w-full p-2 border rounded"
                    />
                </div>

                <button
                    onClick={handleVerify}
                    disabled={!signature}
                    className="bg-purple-500 text-white px-4 py-2 rounded disabled:opacity-50"
                >
                    Verify Signature
                </button>

                {isValid !== null && (
                    <div className={`p-2 rounded ${isValid ? 'text-black bg-green-100' : 'text-black bg-red-100'}`}>
                        Signature is {isValid ? 'valid' : 'invalid'}
                    </div>
                )}
            </div>
        </div>
    );
}