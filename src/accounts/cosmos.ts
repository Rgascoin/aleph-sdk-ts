import * as bip39 from "bip39";
import secp256k1 from "secp256k1";
import { Account, ChainType } from "./account";
import { BaseMessage, GetVerificationBuffer } from "../messages/message";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const cosmosjs = require("@cosmostation/cosmosjs");

type COSMOSImportConfig = {
    path?: string;
    prefix?: string;
};
type messages = {
    type: string;
    value: { message: Buffer; signer: string };
};
type signableMessage = {
    chain_id: string;
    account_number: string;
    fee: { amount: never[]; gas: string };
    memo: string;
    sequence: string;
    msgs: messages[];
};
const CHAIN_ID = "signed-message-v1";

/**
 * COSMOSAccount implements the Account class for the cosmos protocol.
 *  It is used to represent a cosmos account when publishing a message on the Aleph network.
 */
class COSMOSAccount extends Account {
    private readonly privateKey: string;
    constructor(address: string, publicKey: string, privateKey: string) {
        super(address, publicKey);
        this.privateKey = privateKey;
    }

    GetChain(): ChainType {
        return ChainType.Cosmos;
    }

    /**
     * The Sign method provides a way to sign a given Aleph message using a cosmos account.
     * The full message is not used as the payload, only fields of the BaseMessage type are.
     *
     * The sign method of the package 'cosmosjs' is used as the signature method.
     *
     * @param message The Aleph message to sign, using some of its fields.
     */
    Sign(message: BaseMessage): Promise<string> {
        const signable = this.GetSignableMessage(message);

        return new Promise((resolve) => {
            const cosmos = cosmosjs.network("...", CHAIN_ID);
            const signed = cosmos.sign(cosmos.newStdMsg(signable), Buffer.from(this.privateKey, "hex"));
            resolve(JSON.stringify(signed["tx"]["signatures"][0]));
        });
    }

    /**
     * Generate a signableMessage from BaseMessage used for the signature.
     *
     * @param message The Aleph message to sign, using some of its fields.
     */
    private GetSignableMessage(message: BaseMessage): signableMessage {
        const buffer = GetVerificationBuffer(message);
        const content_message = {
            type: "signutil/MsgSignText",
            value: {
                message: buffer,
                signer: message.sender,
            },
        };
        return {
            chain_id: CHAIN_ID,
            account_number: "0",
            fee: {
                amount: [],
                gas: "0",
            },
            memo: "",
            sequence: "0",
            msgs: [content_message],
        };
    }
}

/**
 * Creates a new cosmos account using a randomly generated mnemonic with bip39.
 *  @param path The derivation path.
 *  @param prefix An account prefix
 */
export function NewAccount(
    { path = "m/44'/118'/0'/0/0", prefix = "cosmos" }: COSMOSImportConfig = {
        path: "m/44'/118'/0'/0/0",
        prefix: "cosmos",
    },
): COSMOSAccount {
    const mnemonic = bip39.generateMnemonic();
    return ImportAccountFromMnemonic(mnemonic, { path: path, prefix: prefix });
}

/**
 * Imports a cosmos account given a mnemonic and the 'cosmosjs' package.
 *
 * It creates an cosmos wallet containing information about the account, extracted in the COSMOSAccount constructor.
 *
 * @param mnemonic The mnemonic of the account to import.
 * @param path The derivation path.
 * @param prefix An account prefix
 */
export function ImportAccountFromMnemonic(
    mnemonic: string,
    { path = "m/44'/118'/0'/0/0", prefix = "cosmos" }: COSMOSImportConfig = {
        path: "m/44'/118'/0'/0/0",
        prefix: "cosmos",
    },
): COSMOSAccount {
    const cosmos = cosmosjs.network("...", CHAIN_ID);
    cosmos.setBech32MainPrefix(prefix);
    cosmos.setPath(path);

    const address = cosmos.getAddress(mnemonic);
    const privateKey = cosmos.getECPairPriv(mnemonic);
    const publicKeyBuffer = Buffer.from(secp256k1.publicKeyCreate(privateKey));
    return new COSMOSAccount(address, publicKeyBuffer.toString("hex"), privateKey.toString("hex"));
}
