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

    it("should import a NULS2 accounts using a mnemonic", async () => {
        const mnemonic = bip39.generateMnemonic();
        const account = await nuls2.ImportAccountFromMnemonic(mnemonic);

        expect(account.address).not.toBe("");
        expect(account.publicKey).not.toBe("");
        expect(account.GetChain()).toStrictEqual(ChainType.NULS2);
    });

    it("should import a NULS2 accounts using a private key", async () => {
        const account = await nuls2.ImportAccountFromPrivateKey(
            "cc0681517ecbf8d2800f6fe237fb0af9bef8c95eaa04bfaf3a733cf144a9640c",
        );

        expect(account.address).not.toBe("");
        expect(account.publicKey).toBe("02a7e23f579821364bf186b2ee0fb2aa9e5faa57cd4f281599ca242d8d9faa8533");
        expect(account.address).toBe("NULSd6HgcLR5Yjc7yyMiteQZxTpuB6NYRiqWf");
    });

    it("should change NULS2 account address' prefix", async () => {
        const mnemonic = "cool install source weather mass material hope inflict nerve evil swing swamp";
        const accountOne = await nuls2.ImportAccountFromMnemonic(mnemonic, { prefix: "TEST" });
        const accountTwo = await nuls2.ImportAccountFromPrivateKey(
            "cc0681517ecbf8d2800f6fe237fb0af9bef8c95eaa04bfaf3a733cf144a9640c",
        );

        const accountOnePrefix = accountOne.address.substring(0, 3);
        const accountOneAddress = accountOne.address.substring(4, accountOne.address.length);
        const accountTwoPrefix = accountTwo.address.substring(0, 3);
        const accountTwoAddress = accountTwo.address.substring(4, accountTwo.address.length);

        expect(accountOne.publicKey).toBe(accountTwo.publicKey);
        expect(accountOnePrefix).not.toBe(accountTwoPrefix);
        expect(accountOneAddress).toBe(accountTwoAddress);
    });
});
