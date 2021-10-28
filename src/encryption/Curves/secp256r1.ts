import { decrypt as secp256r1_decrypt, encrypt as secp256r1_encrypt, EncryptPayload } from "../secp256r1";
import { utils } from "eciesjs";

export async function secp256r1Encryption(targetPublicKey: string, encryptedContent: Buffer): Promise<Buffer> {
    const result = await secp256r1_encrypt(utils.decodeHex(targetPublicKey), encryptedContent);

    return encapsulate(result);
}

export async function secp256r1Decryption(privateKey: string, content: Buffer): Promise<Buffer> {
    const opts = decapsulate(content);

    return await secp256r1_decrypt(utils.decodeHex(privateKey), opts);
}

function encapsulate(opts: EncryptPayload): Buffer {
    return Buffer.concat([opts.ephemPublicKey, opts.iv, opts.mac, new Uint8Array(opts.ciphertext)]);
}

function decapsulate(content: Buffer): EncryptPayload {
    return {
        ephemPublicKey: content.slice(0, 65),
        iv: content.slice(65, 65 + 16),
        mac: content.slice(65 + 16, 65 + 48),
        ciphertext: content.slice(65 + 48),
    };
}
