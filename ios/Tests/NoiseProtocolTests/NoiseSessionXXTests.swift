import Testing
import Foundation
@testable import NoiseProtocol

@Suite("NoiseSession XX Tests")
struct NoiseSessionXXTests {

    @Test("XX handshake completes end-to-end with static keys")
    func xxHandshakeCompletes() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let respStatic = Curve25519DH().generateKeyPair()

        let initiator = try NoiseSession(
            protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic)
        let responder = try NoiseSession(
            protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic)

        // XX: → e | ← e, ee, s, es | → s, se
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        try responder.readMessage(initiator.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let plaintext = Data("Hello XX".utf8)
        let ciphertext = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let decrypted = try respT.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("XX handshake matches test vector")
    func xxTestVector() throws {
        let initStatic = KeyPair(
            privateKey: hexToData("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
            publicKey: hexToData("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a"))
        let respStatic = KeyPair(
            privateKey: hexToData("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
            publicKey: hexToData("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"))
        let initEph = KeyPair(
            privateKey: hexToData("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey: hexToData("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
        let respEph = KeyPair(
            privateKey: hexToData("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey: hexToData("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
        let prologue = hexToData("4a6f686e2047616c74")

        let initiator = try NoiseSession(
            protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic, prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(
            protocolName: "Noise_XX_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic, prologue: prologue, localEphemeral: respEph)

        // Message 1: → e
        let msg1 = try initiator.writeMessage(hexToData("4c756477696720766f6e204d69736573"))
        #expect(dataToHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        // Message 2: ← e, ee, s, es
        let msg2 = try responder.writeMessage(hexToData("4d757272617920526f746862617264"))
        #expect(dataToHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad")
        try initiator.readMessage(msg2)

        // Message 3: → s, se
        let msg3 = try initiator.writeMessage(hexToData("462e20412e20486179656b"))
        #expect(dataToHex(msg3) == "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030")
        try responder.readMessage(msg3)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        // Transport: XX last handshake from initiator, so first transport is from responder
        let initT = try initiator.split()
        let respT = try responder.split()

        let tMsg1 = try respT.sender.encryptWithAd(Data(), plaintext: hexToData("4361726c204d656e676572"))
        #expect(dataToHex(tMsg1) == "96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df")

        let tMsg2 = try initT.sender.encryptWithAd(Data(), plaintext: hexToData("4a65616e2d426170746973746520536179"))
        #expect(dataToHex(tMsg2) == "3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5")
    }

    private func hexToData(_ hex: String) -> Data {
        var data = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2)
            let byte = UInt8(hex[i..<next], radix: 16)!
            data.append(byte)
            i = next
        }
        return data
    }

    private func dataToHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
