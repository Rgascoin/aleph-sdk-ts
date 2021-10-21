import * as bip39 from "bip39";
import * as bip32 from "bip32";
import { generateMnemonic } from "bip39";
import { Account, ChainType } from "./account";
import { BaseMessage } from "../messages/message";
import { addressFromHash, privateKeyToPublicKey, publicKeyToHash } from "./nuls";

export type NULS2ImportConfig = {
    chain_id?: number;
    prefix?: string;
};

class NULS2Account extends Account {
    private readonly privateKey: string;
    constructor(address: string, publicKey: string, privateKey: string) {
        super(address, publicKey);
        this.privateKey = privateKey;
    }

    GetChain(): ChainType {
        return ChainType.NULS2;
    }

    Sign(message: BaseMessage): Promise<string> {
        return Promise.resolve(message.channel);
    }

    GetPrivateKey(): string {
        return this.privateKey;
    }
}

export async function NewAccount(
    { chain_id = 1, prefix = "NULS" }: NULS2ImportConfig = { chain_id: 1, prefix: "NULS" },
): Promise<NULS2Account> {
    const mnemonic = generateMnemonic();

    return await ImportAccountFromMnemonic(mnemonic, { chain_id: chain_id, prefix: prefix });
}

export async function ImportAccountFromMnemonic(
    mnemonic: string,
    { chain_id = 1, prefix = "NULS" }: NULS2ImportConfig = { chain_id: 1, prefix: "NULS" },
): Promise<NULS2Account> {
    const v = await bip39.mnemonicToSeed(mnemonic);
    const b = bip32.fromSeed(v);

    if (!b || !b.privateKey) throw new Error("could not import from mnemonic");
    const privateKey = b.privateKey.toString("hex");
    return ImportAccountFromPrivateKey(privateKey, { chain_id: chain_id, prefix: prefix });
}

export async function ImportAccountFromPrivateKey(
    privateKey: string,
    { chain_id = 1, prefix = "NULS" }: NULS2ImportConfig = { chain_id: 1, prefix: "NULS" },
): Promise<NULS2Account> {
    const pub = privateKeyToPublicKey(Buffer.from(privateKey, "hex"));
    const publicKey = Buffer.from(pub).toString("hex");

    const hash = publicKeyToHash(pub, { chain_id: chain_id });
    const address = addressFromHash(hash, prefix);
    return new NULS2Account(address, publicKey, privateKey);
}
