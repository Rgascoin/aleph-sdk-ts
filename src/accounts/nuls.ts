import secp256k1 from "secp256k1";
import shajs from "sha.js";
import RIPEMD160 from "ripemd160";
import bs58 from "bs58";

type ChainNAddress = {
    chain_id?: number;
    address_type?: number;
};

export function getXOR(body: Uint8Array): number {
    let xor = 0;

    for (let i = 0; i < body.length; i += 1) {
        xor ^= body[i];
    }
    return xor;
}

export function privateKeyToPublicKey(privateKey: Uint8Array): Uint8Array {
    return secp256k1.publicKeyCreate(privateKey);
}

export function publicKeyToHash(
    publicKey: Uint8Array,
    { chain_id = 8964, address_type = 1 }: ChainNAddress = { chain_id: 8964, address_type: 1 },
): Buffer {
    const sha = new shajs.sha256().update(publicKey).digest();
    const publicKeyHash = new RIPEMD160().update(sha).digest();
    const output = Buffer.allocUnsafe(3);

    output.writeInt16LE(chain_id, 0);
    output.writeInt8(address_type, 2);
    return Buffer.concat([output, publicKeyHash]);
}

export function addressFromHash(hash: Uint8Array, prefix?: string): string {
    const address = bs58.encode(Buffer.concat([hash, Buffer.from([getXOR(hash)])]));

    if (prefix) return prefix + String.fromCharCode(prefix.length + 96) + address;
    return address;
}
