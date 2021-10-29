import { decrypt as secp256k1_decrypt, encrypt as secp256k1_encrypt, utils } from "eciesjs";

export function secp256k1Encryption(targetPublicKey: string, encryptedContent: Buffer): Promise<Buffer> {
    return new Promise((resolve) => resolve(secp256k1_encrypt(targetPublicKey, encryptedContent)));
}

export function secp256k1Decryption(privateKey: string, content: Buffer): Promise<Buffer> {
    return new Promise((resolve) => resolve(secp256k1_decrypt(utils.decodeHex(privateKey), content)));
}
