import { avalanche } from "../index";
import { Buffer } from "avalanche";

describe("Avalanche accounts", () => {
    it("should create a new avalanche accounts", () => {
        const account = avalanche.NewAccount();

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
    });

    it("should create a new account from private key format CB58 string", () => {
        const importedAccount = avalanche.ImportAccountFromPrivateKey(
            "3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs",
        );

        expect(importedAccount.publicKey).toBe("6nEZsuNhDnknxVTf1YH454nxiB5MpVSN7gQktMRioqRiCP6hTv");
    });

    it("should create a new account from private key format Buffer", () => {
        const privateKey = Buffer.from("3XLFCJUwucDffVNaLRu3RYnctffzJGPZi74xkVEZAZM6aNiVs", "hex");
        const importedAccount = avalanche.ImportAccountFromPrivateKey(privateKey);

        expect(importedAccount.publicKey).toBe("6nEZsuNhDnknxVTf1YH454nxiB5MpVSN7gQktMRioqRiCP6hTv");
    });
});
