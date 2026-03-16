import Testing
import Foundation
@testable import NoiseProtocol

@Suite("NoiseSession NN Tests")
struct NoiseSessionNNTests {

    @Test("NN handshake completes between initiator and responder")
    func handshakeCompletes() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)

        // NN pattern: → e, ← e, ee
        let msg1 = try initiator.writeMessage()
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage()
        try initiator.readMessage(msg2)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }

    @Test("transport encrypt by initiator can be decrypted by responder and vice versa")
    func transportEncryptDecrypt() throws {
        let (initTransport, respTransport) = try completeNNHandshake()

        let message = Data("Hello from initiator".utf8)
        let ciphertext = try initTransport.sender.encryptWithAd(Data(), plaintext: message)
        let decrypted = try respTransport.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == message)

        let reply = Data("Hello from responder".utf8)
        let replyCiphertext = try respTransport.sender.encryptWithAd(Data(), plaintext: reply)
        let replyDecrypted = try initTransport.receiver.decryptWithAd(Data(), ciphertext: replyCiphertext)
        #expect(replyDecrypted == reply)
    }

    private func completeNNHandshake() throws -> (TransportSession, TransportSession) {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        return (try initiator.split(), try responder.split())
    }

    @Test("NN handshake matches cacophony test vector")
    func testVectorConformance() throws {
        let initEphemeral = KeyPair(
            privateKey: hexToData("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey: hexToData("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        let respEphemeral = KeyPair(
            privateKey: hexToData("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey: hexToData("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )
        let prologue = hexToData("4a6f686e2047616c74")

        let initiator = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator,
            prologue: prologue, localEphemeral: initEphemeral
        )
        let responder = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder,
            prologue: prologue, localEphemeral: respEphemeral
        )

        // Message 1
        let payload1 = hexToData("4c756477696720766f6e204d69736573")
        let msg1 = try initiator.writeMessage(payload1)
        #expect(dataToHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        // Message 2
        let payload2 = hexToData("4d757272617920526f746862617264")
        let msg2 = try responder.writeMessage(payload2)
        #expect(dataToHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a0ff96bdf86b579ef7dbf94e812a7470b903c20a85a87e3a1fe863264ae547")
        try initiator.readMessage(msg2)

        // Transport
        let initTransport = try initiator.split()
        let respTransport = try responder.split()

        let tPayload1 = hexToData("462e20412e20486179656b")
        let tMsg1 = try initTransport.sender.encryptWithAd(Data(), plaintext: tPayload1)
        #expect(dataToHex(tMsg1) == "eb1a3e3d80c1792b1bb9cb0e1382f8d8322bfb1ca7c4c8517bb686")

        let tPayload2 = hexToData("4361726c204d656e676572")
        let tMsg2 = try respTransport.sender.encryptWithAd(Data(), plaintext: tPayload2)
        #expect(dataToHex(tMsg2) == "c781b198d2a974eb1da2c7d518c000cf6396de87ca540963c03713")
    }

    private func hexToData(_ hex: String) -> Data {
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            let byteString = hex[index..<nextIndex]
            data.append(UInt8(byteString, radix: 16)!)
            index = nextIndex
        }
        return data
    }

    private func dataToHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    @Test("split throws when handshake is not complete")
    func splitBeforeComplete() throws {
        let session = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        #expect(!session.isHandshakeComplete)
        #expect(throws: NoiseError.handshakeNotComplete) {
            try session.split()
        }
    }

    @Test("writeMessage after split throws")
    func writeAfterSplit() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA256", role: .responder)
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        _ = try initiator.split()
        #expect(throws: NoiseError.handshakeAlreadyComplete) {
            try initiator.writeMessage()
        }
    }
}
