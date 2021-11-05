import { avalanche } from "../index";
import { Buffer } from "avalanche";
import * as aggregate from "../../src/messages/aggregate/index";
import { StorageEngine } from "../../src/messages/message";
import { DEFAULT_API_V2 } from "../../src/global";

describe("Avalanche accounts", () => {
    it("should create a new avalanche accounts", async () => {
        const { account, mnemonic } = await avalanche.NewAccount();

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
        expect(mnemonic).not.toBe("");
    });

    it("should create a new account from a mnemonic", async () => {
        const importedAccount = await avalanche.ImportAccountFromMnemonic(
            "opera play wrestle piano mention shock asset shrug lion hint clerk reduce",
        );

        expect(importedAccount.publicKey).toBe("6FF9QbM3GV9VjZZcdzK8ZZr8BNgSA9jTveuhpot5QN6DUaWPYP");
    });

    it("should create a new account from a private key", () => {
        const importedAccount = avalanche.ImportAccountFromPrivateKey(
            "9677e5b1627e5b3a73b5e0df95d7f3598a3356892dc24ce3b22e4694c4be95b6",
        );

        expect(importedAccount.publicKey).toBe("6FF9QbM3GV9VjZZcdzK8ZZr8BNgSA9jTveuhpot5QN6DUaWPYP");
    });

    it("should create a new account from private key format CB58 string", () => {
        const importedAccount = avalanche.ImportAccountFromPrivateKey(
            "3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs",
        );

        expect(importedAccount.publicKey).toBe("6nEZsuNhDnknxVTf1YH454nxiB5MpVSN7gQktMRioqRiCP6hTv");
    });

    it("should create a new account from private key CB58 Buffer", () => {
        const privateKey = Buffer.from("3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs", "hex");
        const importedAccount = avalanche.ImportAccountFromPrivateKey(privateKey);

        expect(importedAccount.publicKey).toBe("6nEZsuNhDnknxVTf1YH454nxiB5MpVSN7gQktMRioqRiCP6hTv");
    });

    it("should publish an Aggregate message successfully", async () => {
        const { account } = await avalanche.NewAccount();
        const key = "AVAX";
        const content: { body: string } = {
            body: "I changed this one",
        };

        await aggregate.Publish({
            account: account,
            key: key,
            content: content,
            channel: "TEST",
            storageEngine: StorageEngine.IPFS,
            inlineRequested: true,
            APIServer: DEFAULT_API_V2,
        });

        type exceptedType = {
            AVAX: {
                body: string;
            };
        };
        const amends = await aggregate.Get<exceptedType>({
            APIServer: DEFAULT_API_V2,
            address: account.address,
            keys: [key],
        });
        expect(amends.AVAX.body).toStrictEqual(content.body);
    });
});
