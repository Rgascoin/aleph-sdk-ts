import { secp256k1Decryption, secp256k1Encryption } from "./secp256k1";
import { secp256r1Decryption, secp256r1Encryption } from "./secp256r1";
import { ed25519Decryption, ed25519Encryption } from "./ed25519";

export const curvesEncryption: { [key: string]: (pkey: string, content: Buffer) => Promise<Buffer> } = {
    secp256k1: secp256k1Encryption,
    secp256r1: secp256r1Encryption,
    ed25519: ed25519Encryption,
};

export const curvesDecryption: {
    [key: string]: (pkey: string, content: Buffer) => Promise<Uint8Array | null> | Promise<Buffer>;
} = {
    secp256k1: secp256k1Decryption,
    secp256r1: secp256r1Decryption,
    ed25519: ed25519Decryption,
};
