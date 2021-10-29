import nacl from "tweetnacl";
import base58 from "bs58";

export function ed25519Encryption(targetPublicKey: string, encryptedContent: Buffer): Promise<Buffer> {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const content = nacl.secretbox(encryptedContent, nonce, base58.decode(targetPublicKey));

    return new Promise((resolve) =>
        resolve(
            encapsulateBox({
                nonce,
                ciphertext: content,
            }),
        ),
    );
}

export function ed25519Decryption(privateKey: string, content: Buffer): Promise<Uint8Array | null> {
    const opts = decapsulateBox(content);

    return new Promise((resolve) =>
        resolve(nacl.secretbox.open(opts.ciphertext, opts.nonce, base58.decode(privateKey))),
    );
}

function encapsulateBox(opts: { nonce: Uint8Array; ciphertext: Uint8Array }): Buffer {
    if (!opts.nonce) {
        throw new Error("No nonce found");
    }
    return Buffer.concat([opts.nonce, opts.ciphertext]);
}

function decapsulateBox(content: Buffer): { nonce: Buffer; ciphertext: Buffer } {
    return {
        nonce: content.slice(0, nacl.secretbox.nonceLength),
        ciphertext: content.slice(nacl.secretbox.nonceLength),
    };
}
