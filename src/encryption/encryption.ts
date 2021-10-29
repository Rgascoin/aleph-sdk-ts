import { EncryptPayload } from "./secp256r1";
import { Account } from "../accounts/account";
import { curvesEncryption } from "./curves";

export type EncryptionOpts = {
    as_hex?: boolean;
    as_string?: boolean;
    curve?: CurveType;
};
export type DecryptContent = WithImplicitCoercion<string> | { [Symbol.toPrimitive](hint: "string"): string };
type ContentType = string | Buffer;
export type CurveType = "secp256k1" | "secp256r1" | "ed25519";

/**
 * Extract the curve method used by an account
 *
 * @param userAccount The user's account
 */
export function getCurveFromAccount(userAccount: Account): CurveType {
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
