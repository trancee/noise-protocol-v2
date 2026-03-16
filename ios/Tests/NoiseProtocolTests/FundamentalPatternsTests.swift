import Testing
import Foundation
@testable import NoiseProtocol

@Suite("Fundamental Patterns Tests")
struct FundamentalPatternsTests {

    // Shared test vector keys
    private let initStatic = KeyPair(
        privateKey: hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
        publicKey: hex("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a"))
    private let respStatic = KeyPair(
        privateKey: hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
        publicKey: hex("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"))
    private let initEph = KeyPair(
        privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
    private let respEph = KeyPair(
        privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
    private let prologue = hex("4a6f686e2047616c74")

    // --- NK: pre-message ← s ---

    @Test("NK handshake matches test vector")
    func nkTestVector() throws {
        let initiator = try NoiseSession(
            protocolName: "Noise_NK_25519_ChaChaPoly_SHA256", role: .initiator,
            remoteStaticKey: respStatic.publicKey, prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(
            protocolName: "Noise_NK_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic, prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexToData("4c756477696720766f6e204d69736573"))
        #expect(dataToHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448134d00711fdb390a0d178fa008f6d47d2891e5ea18ae136c3b4c23ac384efb0")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hexToData("4d757272617920526f746862617264"))
        #expect(dataToHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438ea16e3701bc0d77744f117bee22451c9afa7f4cdbbcff00c04a8ee0913c88")
        try initiator.readMessage(msg2)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let tMsg1 = try initT.sender.encryptWithAd(Data(), plaintext: hexToData("462e20412e20486179656b"))
        #expect(dataToHex(tMsg1) == "a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0")

        let tMsg2 = try respT.sender.encryptWithAd(Data(), plaintext: hexToData("4361726c204d656e676572"))
        #expect(dataToHex(tMsg2) == "174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff")
    }

    // --- KK: pre-messages → s, ← s ---

    @Test("KK handshake matches test vector")
    func kkTestVector() throws {
        let initiator = try NoiseSession(
            protocolName: "Noise_KK_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic, remoteStaticKey: respStatic.publicKey,
            prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(
            protocolName: "Noise_KK_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic, remoteStaticKey: initStatic.publicKey,
            prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexToData("4c756477696720766f6e204d69736573"))
        #expect(dataToHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440177015efc1fe7a37c629af7120a96274e6ab7afcc9261901d0e09ae32a5bb96")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hexToData("4d757272617920526f746862617264"))
        #expect(dataToHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843b274d3429adc47ca093ba63ef90f8da89fda108db471dccfa4894aa7b00003")
        try initiator.readMessage(msg2)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let tMsg1 = try initT.sender.encryptWithAd(Data(), plaintext: hexToData("462e20412e20486179656b"))
        #expect(dataToHex(tMsg1) == "966b05bc69ec01b8454d3160a214e6f24a3d884eb31ec2408af63f")

        let tMsg2 = try respT.sender.encryptWithAd(Data(), plaintext: hexToData("4361726c204d656e676572"))
        #expect(dataToHex(tMsg2) == "0ad887fba4f611bbb4afe44ba3556b8164332ca7d5934634d63d80")
    }

    // --- NX ---

    @Test("NX handshake completes end-to-end")
    func nxHandshake() throws {
        let respStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(protocolName: "Noise_NX_25519_ChaChaPoly_SHA256", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NX_25519_ChaChaPoly_SHA256", role: .responder,
                                         staticKeyPair: respStatic)

        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        try verifyTransport(initiator, responder)
    }

    // --- KN ---

    @Test("KN handshake completes end-to-end")
    func knHandshake() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(protocolName: "Noise_KN_25519_ChaChaPoly_SHA256", role: .initiator,
                                         staticKeyPair: initStatic)
        let responder = try NoiseSession(protocolName: "Noise_KN_25519_ChaChaPoly_SHA256", role: .responder,
                                         remoteStaticKey: initStatic.publicKey)

        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        try verifyTransport(initiator, responder)
    }

    // --- KX ---

    @Test("KX handshake completes end-to-end")
    func kxHandshake() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let respStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(protocolName: "Noise_KX_25519_ChaChaPoly_SHA256", role: .initiator,
                                         staticKeyPair: initStatic)
        let responder = try NoiseSession(protocolName: "Noise_KX_25519_ChaChaPoly_SHA256", role: .responder,
                                         staticKeyPair: respStatic, remoteStaticKey: initStatic.publicKey)

        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        try verifyTransport(initiator, responder)
    }

    // --- XN ---

    @Test("XN handshake completes end-to-end")
    func xnHandshake() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(protocolName: "Noise_XN_25519_ChaChaPoly_SHA256", role: .initiator,
                                         staticKeyPair: initStatic)
        let responder = try NoiseSession(protocolName: "Noise_XN_25519_ChaChaPoly_SHA256", role: .responder)

        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        try responder.readMessage(initiator.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        try verifyTransport(initiator, responder)
    }

    // --- XK ---

    @Test("XK handshake completes end-to-end")
    func xkHandshake() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let respStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(protocolName: "Noise_XK_25519_ChaChaPoly_SHA256", role: .initiator,
                                         staticKeyPair: initStatic, remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(protocolName: "Noise_XK_25519_ChaChaPoly_SHA256", role: .responder,
                                         staticKeyPair: respStatic)

        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        try responder.readMessage(initiator.writeMessage())

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
        try verifyTransport(initiator, responder)
    }

    // --- Error handling ---

    @Test("KK without initiator static throws invalidKey")
    func kkMissingStaticThrows() throws {
        #expect(throws: NoiseError.self) {
            try NoiseSession(protocolName: "Noise_KK_25519_ChaChaPoly_SHA256", role: .initiator,
                             remoteStaticKey: respStatic.publicKey)
        }
    }

    @Test("NK without remote static throws invalidKey")
    func nkMissingRemoteStaticThrows() throws {
        #expect(throws: NoiseError.self) {
            try NoiseSession(protocolName: "Noise_NK_25519_ChaChaPoly_SHA256", role: .initiator)
        }
    }

    // --- Helpers ---

    private func verifyTransport(_ initiator: NoiseSession, _ responder: NoiseSession) throws {
        let initT = try initiator.split()
        let respT = try responder.split()
        let plaintext = Data("Hello from initiator".utf8)
        let ciphertext = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let decrypted = try respT.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == plaintext)

        let reply = Data("Hello from responder".utf8)
        let replyCipher = try respT.sender.encryptWithAd(Data(), plaintext: reply)
        let replyDecrypted = try initT.receiver.decryptWithAd(Data(), ciphertext: replyCipher)
        #expect(replyDecrypted == reply)
    }

    private func hexToData(_ hex: String) -> Data { Self.hex(hex) }

    private static func hex(_ hex: String) -> Data {
        var data = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2)
            data.append(UInt8(hex[i..<next], radix: 16)!)
            i = next
        }
        return data
    }

    private func dataToHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
