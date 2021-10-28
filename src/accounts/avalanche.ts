import { Account, ChainType } from "./account";
import { BaseMessage } from "../messages/message";
import { KeyChain, KeyPair } from "avalanche/dist/apis/avm/keychain";
import { Avalanche, BinTools, Buffer } from "avalanche";
import { createHash } from "crypto";

/**
 * Imports an avalanche account given a private key and the 'avalanche' package.
 *
 * It creates an avalanche wallet containing information about the account, extracted in the AVAAccount constructor.
 *
 * @param keyPair The keyPair of the account to import.
 */
class AVAAccount extends Account {
    private readonly keyPair: KeyPair;
    constructor(keyPair: KeyPair) {
        super(keyPair.getAddressString(), keyPair.getPublicKeyString());
        this.keyPair = keyPair;
    }

    GetChain(): ChainType {
        return ChainType.Avalanche;
    }

    /**
     * The Sign method provides a way to sign a given Aleph message using an avalanche account.
     * The full message is not used as the payload, only fields of the BaseMessage type are.
     *
     * The signMessage method of the package 'avalanche' is used as the signature method.
     *
     * @param message The Aleph message to sign, using some of its fields.
     */
    Sign(message: BaseMessage): Promise<string> {
        const buffer = this.getVerificationBuffer(message);

        return new Promise<string>((resolve) => {
            const binTools = BinTools.getInstance();
            const digest = this.digestMessage(buffer);
            const digestHex = digest.toString("hex");
            const digestBuffer = Buffer.from(digestHex, "hex");
            resolve(binTools.cb58Encode(this.keyPair.sign(digestBuffer)));
        });
    }

    /**
     * Creates a digest of a message
     *
     * @param msg The original message
     */
    private digestMessage(msg: Buffer) {
        const msgSize = Buffer.alloc(4);
        const msgStr = msg.toString("utf-8");

        msgSize.writeUInt32BE(msg.length, 0);
        const messageBuffer = Buffer.from(`\x1AAvalanche Signed Message:\n${msgSize}${msgStr}`, "utf8");
        return createHash("sha256").update(messageBuffer).digest();
    }

    /**
     * Creates a buffer used in the message signature using the message data
     * Notice this method is used over 'getVerificationBuffer' from "../messages/message" to use avalanche's Buffer
     *
     * @param msg The message
     */
    private getVerificationBuffer(msg: BaseMessage): Buffer {
        return Buffer.from(`${msg.chain}\n${msg.sender}\n${msg.type}\n${msg.item_hash}`);
    }
}

/**
 * Creates a new avalanche account using a generated mnemonic following BIP 39 standard.
 */
export function NewAccount(): AVAAccount {
    const keyChain = getKeychain();
    const keyPair = keyChain.makeKey();

    return new AVAAccount(keyPair);
}

/**
 * Imports an avalanche account given a private key and the 'avalanche' package.
 *
 * It creates an avalanche wallet containing information about the account, extracted in the AVAAccount constructor.
 *
 * @param privateKey The private key of the account to import.
 */
export function ImportAccountFromPrivateKey(privateKey: string | Buffer): AVAAccount {
    const keychain = getKeychain();
    let hexPrivateKey: Buffer;

    if (typeof privateKey === "string") hexPrivateKey = Buffer.from(privateKey, "hex");
    else hexPrivateKey = privateKey;
    const keyPair = keychain.importKey(hexPrivateKey);
    return new AVAAccount(keyPair);
}

/**
 * Retrieves the AVAX Keychain, used to sign transactions
 *
 * @param host The hostname to resolve to reach the Avalanche Client RPC APIs
 * @param port The port to resolve to reach the Avalanche Client RPC APIs
 * @param protocol The protocol string to use before a “://” in a request, ex: “http”, “https”, “git”, “ws”, etc …
 * @param networkID Sets the NetworkID of the AVAX object
 * @param XChainID Sets the blockchainID for the AVM. Will try to auto-detect, otherwise default “4R5p2RXDGLqaifZE4hHWH9owe34pfoBULn1DrQTWivjg8o4aH”
 * @param CChainID Sets the blockchainID for the EVM. Will try to auto-detect, otherwise default “2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5”
 * @param hrp The human-readable part of the bech32 addresses
 * @param skipInit Skips creating the APIs
 */
export function getKeychain(
    host = "https://api.avax.network/",
    port = 9650,
    protocol = "https",
    networkID = 1,
    XChainID?: string,
    CChainID?: string,
    hrp?: string,
    skipInit = false,
): KeyChain {
    const ava = new Avalanche(host, port, protocol, networkID, XChainID, CChainID, hrp, skipInit);
    const xChain = ava.XChain();

    return xChain.keyChain();
}
