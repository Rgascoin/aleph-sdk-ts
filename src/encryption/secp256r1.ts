import { ec, SignatureInput } from "elliptic";
import * as nodeCrypto from "crypto";

const elliptic = new ec("p256");
// TODO: Look for global.msCrypto
const browserCrypto = global.crypto || {};
// TODO: Look for browserCrypto.webkitSubtle
const { subtle } = browserCrypto;
const EC_GROUP_ORDER = Buffer.from("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "hex");
const ZERO32 = Buffer.alloc(32, 0);

type IV = Uint8Array;
type Key =
    | Int8Array
    | Int16Array
    | Int32Array
    | Uint8Array
    | Uint16Array
    | Uint32Array
    | Uint8ClampedArray
    | Float32Array
    | Float64Array
    | DataView;
type Data = Key;
type PublicKey = Uint8Array | Buffer | string | number[];
type Message = string | Buffer | Uint8Array | ReadonlyArray<number>;

function assert(condition: boolean, message?: string) {
    if (!condition) {
        throw new Error(message || "Assertion failed");
    }
}

function isScalar<T>(x: T): boolean {
    return Buffer.isBuffer(x) && x.length === 32;
}

function isValidPrivateKey(privateKey: Buffer): boolean {
    if (!isScalar(privateKey)) {
        return false;
    }
    return privateKey.compare(ZERO32) > 0 && privateKey.compare(EC_GROUP_ORDER) < 0;
}

function equalConstTime(b1: Buffer, b2: Buffer): boolean {
    if (b1.length !== b2.length) {
        return false;
    }

    let res = 0;
    for (let i = 0; i < b1.length; i += 1) {
        /* eslint-disable  no-bitwise */
        res |= b1[i] ^ b2[i];
    }
    return res === 0;
}

function randomBytes(size: number): Buffer {
    const arr = new Uint8Array(size);

    if (typeof browserCrypto.getRandomValues === "undefined") {
        return Buffer.from(nodeCrypto.randomBytes(size));
    }
    browserCrypto.getRandomValues(arr);

    return Buffer.from(arr);
}

function sha512(msg: string | NodeJS.ArrayBufferView): Uint8Array {
    const hash = nodeCrypto.createHash("sha512");
    const result = hash.update(msg).digest();

    return new Uint8Array(result);
}

function getAes(op: "decrypt" | "encrypt"): (iv: IV, key: Key, data: Data) => Promise<ArrayBuffer> {
    return (iv: IV, key: Key, data: Data): Promise<ArrayBuffer> => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return new Promise((resolve) => {
            if (subtle) {
                const importAlgorithm:
                    | AlgorithmIdentifier
                    | RsaHashedImportParams
                    | EcKeyImportParams
                    | HmacImportParams
                    // | DhImportKeyParams
                    | AesKeyAlgorithm = {
                    name: "AES-CBC",
                };
                const keyp = subtle.importKey("raw", key, importAlgorithm, false, [op]);

                return keyp.then((cryptoKey) => {
                    const encryptionAlgorithm:
                        | AlgorithmIdentifier
                        | RsaOaepParams
                        | AesCtrParams
                        | AesCbcParams
                        // | AesCmacParams
                        // | AesCfbParams
                        | AesGcmParams = {
                        name: "AES-CBC",
                        iv,
                    };

                    if (op === "encrypt") {
                        return subtle.encrypt(encryptionAlgorithm, cryptoKey, data);
                    }
                    return subtle.decrypt(encryptionAlgorithm, cryptoKey, data);
                });
            }
            if (op === "encrypt") {
                const cipher = nodeCrypto.createCipheriv("aes-256-cbc", key, iv);

                cipher.update(data);
                resolve(cipher.final());
            } else if (op === "decrypt") {
                const decipher = nodeCrypto.createDecipheriv("aes-256-cbc", key, iv);

                decipher.update(data);
                resolve(decipher.final());
            }
        });
    };
}

const aesCbcEncrypt = getAes("encrypt");
const aesCbcDecrypt = getAes("decrypt");

function hmacSha256Sign(
    key: WithImplicitCoercion<ArrayBuffer | SharedArrayBuffer>,
    msg: string | NodeJS.ArrayBufferView,
): Buffer {
    const hmac = nodeCrypto.createHmac("sha256", Buffer.from(key));

    hmac.update(msg);
    return hmac.digest();
}

function hmacSha256Verify(
    key: WithImplicitCoercion<ArrayBuffer | SharedArrayBuffer>,
    msg: string | NodeJS.ArrayBufferView,
    sig: Buffer,
): boolean {
    const hmac = nodeCrypto.createHmac("sha256", Buffer.from(key));
    hmac.update(msg);
    const expectedSig = hmac.digest();

    return equalConstTime(expectedSig, sig);
}

export function generatePrivate(): Buffer {
    let privateKey = randomBytes(32);

    while (!isValidPrivateKey(privateKey)) {
        privateKey = randomBytes(32);
    }
    return privateKey;
}

export function getPublic(privateKey: Buffer): Buffer {
    // This function has sync API so we throw an error immediately.
    assert(privateKey.length === 32, "Bad private key");
    assert(isValidPrivateKey(privateKey), "Bad private key");
    // XXX(Kagami): `elliptic.utils.encode` returns array for every
    // encoding except `hex`.
    return Buffer.from(elliptic.keyFromPrivate(privateKey).getPublic("array"));
}

export function getPublicCompressed(privateKey: Buffer): Buffer {
    assert(privateKey.length === 32, "Bad private key");
    assert(isValidPrivateKey(privateKey), "Bad private key");
    // See https://github.com/wanderer/secp256k1-node/issues/46
    const compressed = true;
    return Buffer.from(elliptic.keyFromPrivate(privateKey).getPublic(compressed, "array"));
}

export function sign(privateKey: Buffer, msg: Message): Buffer {
    assert(privateKey.length === 32, "Bad private key");
    assert(isValidPrivateKey(privateKey), "Bad private key");
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");

    return Buffer.from(elliptic.sign(msg, privateKey, { canonical: true }).toDER());
}

export function verify(publicKey: Buffer, msg: Message, sig: SignatureInput): null {
    assert(publicKey.length === 65 || publicKey.length === 33, "Bad public key");
    if (publicKey.length === 65) {
        assert(publicKey[0] === 4, "Bad public key");
    }
    if (publicKey.length === 33) {
        assert(publicKey[0] === 2 || publicKey[0] === 3, "Bad public key");
    }
    assert(msg.length > 0, "Message should not be empty");
    assert(msg.length <= 32, "Message is too long");
    if (elliptic.verify(msg, sig, publicKey)) {
        return null;
    }
    throw new Error("Bad signature");
}

export function derive(privateKeyA: Buffer, publicKeyB: PublicKey): Promise<Buffer> {
    return new Promise<Buffer>((resolve) => {
        assert(Buffer.isBuffer(privateKeyA), "Bad private key");
        assert(Buffer.isBuffer(publicKeyB), "Bad public key");
        assert(privateKeyA.length === 32, "Bad private key");
        assert(isValidPrivateKey(privateKeyA), "Bad private key");
        assert(publicKeyB.length === 65 || publicKeyB.length === 33, "Bad public key");
        if (publicKeyB.length === 65) {
            assert(publicKeyB[0] === 4, "Bad public key");
        }
        if (publicKeyB.length === 33) {
            assert(publicKeyB[0] === 2 || publicKeyB[0] === 3, "Bad public key");
        }
        const keyA = elliptic.keyFromPrivate(privateKeyA);
        const keyB = elliptic.keyFromPublic(publicKeyB);
        const Px = keyA.derive(keyB.getPublic()); // BN instance
        resolve(Buffer.from(Px.toArray()));
    });
}

type EncryptOptions = {
    ephemPrivateKey?: Buffer;
    iv?: IV;
};

export type EncryptPayload = {
    iv: IV;
    ephemPublicKey: Buffer;
    ciphertext: ArrayBuffer;
    mac: Buffer;
    nonce?: Uint8Array;
};

export async function encrypt(_publicKeyTo: PublicKey, msg: Data, opts?: EncryptOptions): Promise<EncryptPayload> {
    let ephemPrivateKey: Buffer = opts?.ephemPrivateKey || randomBytes(32);

    while (!isValidPrivateKey(ephemPrivateKey)) {
        ephemPrivateKey = opts?.ephemPrivateKey || randomBytes(32);
    }
    const ephemPublicKey: Buffer = getPublic(ephemPrivateKey);

    const Px = await derive(ephemPrivateKey, ephemPublicKey);
    const hash = sha512(Px);

    const iv: Uint8Array | Buffer = opts?.iv || randomBytes(16);
    const encryptionKey = hash.slice(0, 32);
    const macKey: Uint8Array = hash.slice(32);

    const cipherText: ArrayBuffer = await aesCbcEncrypt(iv, encryptionKey, msg);
    const dataToMac = Buffer.concat([iv, ephemPublicKey, new Uint8Array(cipherText)]);
    const mac = hmacSha256Sign(macKey, dataToMac);

    return {
        iv,
        ephemPublicKey,
        ciphertext: cipherText,
        mac,
    };
}

export async function decrypt(privateKey: Buffer, opts: EncryptPayload): Promise<Buffer> {
    const Px = await derive(privateKey, opts.ephemPublicKey);
    const hash = sha512(Px);

    const encryptionKey = hash.slice(0, 32);
    const macKey = hash.slice(32);
    const dataToMac = Buffer.concat([opts.iv, opts.ephemPublicKey, new Uint8Array(opts.ciphertext)]);

    const macGood = hmacSha256Verify(macKey, dataToMac, opts.mac);
    assert(macGood, "Bad MAC");

    const msg = await aesCbcDecrypt(opts.iv, encryptionKey, new Uint8Array(opts.ciphertext));
    return Buffer.from(new Uint8Array(msg));
}
