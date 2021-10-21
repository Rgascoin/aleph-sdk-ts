import * as bip39 from "bip39";
import { nuls2 } from "../index";
import { ChainType } from "../../src/accounts/account";

describe("NULS2 accounts", () => {
    it("should create a NULS2 accounts", async () => {
        const account = await nuls2.NewAccount();

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
        expect(account.GetChain()).toStrictEqual(ChainType.NULS2);
    });

    it("should import an NULS2 accounts using a mnemonic", async () => {
        const mnemonic = bip39.generateMnemonic();
        const account = await nuls2.ImportAccountFromMnemonic(mnemonic);

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
        expect(account.GetChain()).toStrictEqual(ChainType.NULS2);
    });

    it("should import an NULS2 accounts using a private key", async () => {
        const accountOne = await nuls2.NewAccount();
        const accountTwo = await nuls2.ImportAccountFromPrivateKey(accountOne.GetPrivateKey());

        expect(accountTwo.address).not.toBe("");
        expect(accountOne.publicKey).toBe(accountTwo.publicKey);
        expect(accountOne.address).toBe(accountTwo.address);
    });

    it("should change NULS2 account address' prefix", async () => {
        const accountOne = await nuls2.NewAccount({ prefix: "TEST" });
        const accountTwo = await nuls2.ImportAccountFromPrivateKey(accountOne.GetPrivateKey());

        const accountOnePrefix = accountOne.address.substring(0, 3);
        const accountOneAddress = accountOne.address.substring(4, accountOne.address.length);
        const accountTwoPrefix = accountTwo.address.substring(0, 3);
        const accountTwoAddress = accountTwo.address.substring(4, accountTwo.address.length);

        expect(accountOne.publicKey).toBe(accountTwo.publicKey);
        expect(accountOnePrefix).not.toBe(accountTwoPrefix);
        expect(accountOneAddress).toBe(accountTwoAddress);
    });
});
