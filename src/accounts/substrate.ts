import { Account, ChainType } from "./account";
import { BaseMessage, GetVerificationBuffer } from "../messages/message";
import { Keyring } from "@polkadot/keyring";
import { KeyringPair } from "@polkadot/keyring/types";
import { cryptoWaitReady, mnemonicToMiniSecret } from "@polkadot/util-crypto";
import { generateMnemonic } from "@polkadot/util-crypto/mnemonic/bip39";
import { curves, encryption } from "../encryption";

/**
 * DOTAccount implements the Account class for the substrate protocol.
 *  It is used to represent a substrate account when publishing a message on the Aleph network.
 */
class DOTAccount extends Account {
    private pair: KeyringPair;
    private privateKey: string;
    constructor(pair: KeyringPair, privateKey: string) {
        const publicKey: string = Buffer.from(pair.publicKey).toString("hex");
        super(pair.address, publicKey);
        this.pair = pair;
        this.privateKey = privateKey;
    }

    GetChain(): ChainType {
        return ChainType.Substrate;
    }

    /**
     * The Sign method provides a way to sign a given Aleph message using a substrate account.
     * The full message is not used as the payload, only fields of the BaseMessage type are.
     *
     * The sign method of the package 'polkadot' is used as the signature method.
     *
     * @param message The Aleph message to sign, using some of its fields.
     */
    Sign(message: BaseMessage): Promise<string> {
        const buffer = GetVerificationBuffer(message);
        return new Promise((resolve) => {
            const signed = `0x${Buffer.from(this.pair.sign(buffer)).toString("hex")}`;

            resolve(
                JSON.stringify({
                    curve: "sr25519",
                    data: signed,
                }),
            );
        });
    }

    /**
     * Decrypt a given content using an DOTAccount
     *
     * @param userAccount The user's account
     * @param content The encrypted content to decrypt
     * @param as_hex Was the content encrypted as hexadecimal ?
     * @param as_string Was the content encrypted as a string ?
     */
    override async Decrypt(
        content: encryption.DecryptContent,
        { as_hex = true, as_string = true }: encryption.EncryptionOpts = {},
    ): Promise<Buffer | Uint8Array | string> {
        const curve = encryption.getCurveFromAccount(this);
        let result: Buffer | Uint8Array | string | null;
        let localContent: Buffer;

        if (as_hex) localContent = Buffer.from(content, "hex");
        else localContent = Buffer.from(content);

        const secret = this.privateKey;
        result = await curves.curvesDecryption[curve](secret, localContent);

        if (result === null) throw new Error("could not decrypt");
        if (as_string) result = result.toString();
        return result;
    }
}

/**
 * Creates a new substrate account using a randomly generated substrate keyring.
 */
export async function NewAccount(): Promise<DOTAccount> {
    const mnemonic = generateMnemonic();

    return await ImportAccountFromMnemonic(mnemonic);
}

/**
 * Imports a substrate account given a mnemonic and the 'polkadot' package.
 *
 * It creates an substrate wallet containing information about the account, extracted in the DOTAccount constructor.
 *
 * @param mnemonic The mnemonic of the account to import.
 */
export async function ImportAccountFromMnemonic(mnemonic: string): Promise<DOTAccount> {
    const privateKey = `0x${Buffer.from(mnemonicToMiniSecret(mnemonic)).toString("hex")}`;

    return ImportAccountFromPrivateKey(privateKey);
}

/**
 * Imports a substrate account given a private key and the 'polkadot/keyring' package's class.
 *
 * It creates a substrate wallet containing information about the account, extracted in the DOTAccount constructor.
 *
 * @param privateKey The private key of the account to import.
 */
export async function ImportAccountFromPrivateKey(privateKey: string): Promise<DOTAccount> {
    const keyRing = new Keyring({ type: "sr25519" });

    await cryptoWaitReady();
    return new DOTAccount(keyRing.createFromUri(privateKey, { name: "sr25519" }), privateKey);
}
