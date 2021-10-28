import { encryption, ethereum } from "../index";

describe("Encryption accounts", () => {
    it("encrypt using an Ethereum account", async () => {
        const ethAccount = await ethereum.NewAccount();
        const cipher = await encryption.encrypt(ethAccount.publicKey, "Test");

        expect(cipher).not.toBeNull();
    });

    it("decrypt using an Ethereum account", async () => {
        const ethAccount = await ethereum.NewAccount();

        const content = "This is just a test.";
        const cipher = await encryption.encryptForSelf(ethAccount, content);
        const decipher = await encryption.decrypt(ethAccount, cipher.toString());

        expect(decipher).toBe(content);
    });
});
