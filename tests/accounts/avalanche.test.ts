import { avalanche } from "../index";
import { BinTools } from "avalanche";

describe("Avalanche accounts", () => {
    it("should create a new avalanche accounts", () => {
        const account = avalanche.NewAccount();

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
    });

    it("should create a new account from private key format CB58 string", () => {
        const importedAccount = avalanche.ImportAccountFromPrivateKey(
            "PrivateKey-3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs",
        );

        expect(importedAccount.publicKey).toBe("6n5MHPWfEfjxQ66QfgE8EygZHz5UBXCPZ5m7orEzqMJZij3u18");
    });

    it("should create a new account from private key format Buffer", () => {
        const bintools = BinTools.getInstance();
        const privateKey = bintools.cb58Decode("3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs"); // returns a Buffer;
        const importedAccount = avalanche.ImportAccountFromPrivateKey(privateKey);

        expect(importedAccount.publicKey).toBe("6n5MHPWfEfjxQ66QfgE8EygZHz5UBXCPZ5m7orEzqMJZij3u18");
    });

    it("should throws an error because a bad private key is provided", async () => {
        const privateKey = "invalid mnemonic";
        let hasThrown = false;

        try {
            avalanche.ImportAccountFromPrivateKey(privateKey);
        } catch (e) {
            hasThrown = true;
        }
        expect(hasThrown).toBe(true);
    });
});
