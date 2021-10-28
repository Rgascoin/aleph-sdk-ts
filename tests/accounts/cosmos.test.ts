import { cosmos } from "../index";
import * as bip39 from "bip39";

describe("Cosmos accounts", () => {
    it("should create a new cosmos accounts", () => {
        const account = cosmos.NewAccount();

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
    });

    it("should import an cosmos accounts using a mnemonic", () => {
        const mnemonic = bip39.generateMnemonic();
        const account = cosmos.ImportAccountFromMnemonic(mnemonic);

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
    });

    it("should import cosmos accounts with different prefix's", () => {
        const mnemonic = bip39.generateMnemonic();
        const accountA = cosmos.ImportAccountFromMnemonic(mnemonic, { prefix: "winnie" });
        const accountB = cosmos.ImportAccountFromMnemonic(mnemonic, { prefix: "zorro" });

        expect(accountA.address).not.toBe(accountB.address);
        expect(accountA.publicKey).toBe(accountB.publicKey);
    });
});
