import { EncryptPayload } from "./secp256r1";
import { Account } from "../accounts/account";
import { curvesDecryption, curvesEncryption } from "./Curves";

type EncryptionOpts = {
    as_hex?: boolean;
    as_string?: boolean;
    curve?: string;
};
type ContentType = string | Buffer;

/**
 * Extract the curve method used by an account
 *
 * @param userAccount The user's account
 */
export function getCurveFromAccount(userAccount: Account): string {
    const defaultCurve = "secp256k1";

    if (userAccount.GetChain() === "SOL") return "ed25519";
    return defaultCurve;
}

/**
 * Encrypt a content using a user's public key
 *
 * @param targetPublicKey The user's public key
 * @param encryptedContent The content to encrypt
 * @param as_hex Encrypt the content in hexadecimal
 * @param as_string Encrypt the content as a string
 * @param curve Specify the curve used while encrypting content
 */
export async function encrypt(
    targetPublicKey: string,
    encryptedContent: ContentType,
    { as_hex = true, as_string = true, curve = "secp256k1" }: EncryptionOpts = {},
): Promise<string | Buffer> {
    let result: Buffer | string | EncryptPayload | null = null;

    if (as_string) encryptedContent = Buffer.from(encryptedContent);
    if (!(encryptedContent instanceof Buffer))
        throw new Error("could not encrypt, content is not a buffer at this point");

    result = await curvesEncryption[curve](targetPublicKey, encryptedContent);

    if (result === null) throw new Error("could not encrypt message");
    if (as_hex) result = result.toString("hex");
    return result;
}

/**
 * Decrypt the content using a user's account
 *
 * @param userAccount The user's account
 * @param content The encrypted content to decrypt
 * @param as_hex Was the content encrypted as hexadecimal ?
 * @param as_string Was the content encrypted as a string ?
 */
export async function decrypt(
    userAccount: Account,
    content: WithImplicitCoercion<string> | { [Symbol.toPrimitive](hint: "string"): string },
    { as_hex = true, as_string = true }: EncryptionOpts = {},
): Promise<Buffer | Uint8Array | string> {
    const curve = getCurveFromAccount(userAccount);
    let localContent: Buffer;
    let result: Buffer | Uint8Array | string | null = null;

    if (userAccount.getSecret() === undefined) {
        throw new Error("no private key was loaded in this account");
    }
    if (as_hex) localContent = Buffer.from(content, "hex");
    else localContent = Buffer.from(content);

    result = await curvesDecryption[curve](userAccount.getSecret(), localContent);

    if (result === null) throw new Error("could not decrypt");
    if (as_string) result = result.toString();
    return result;
}

export async function encryptForSelf(
    userAccount: Account,
    content: ContentType,
    { as_hex = true, as_string = true }: EncryptionOpts = {},
): Promise<string | Buffer> {
    const curve = getCurveFromAccount(userAccount);

    if (userAccount.publicKey === undefined) {
        throw new Error("no public key was loaded in this account");
    }
    return encrypt(userAccount.publicKey, content, { as_hex, as_string, curve });
}
