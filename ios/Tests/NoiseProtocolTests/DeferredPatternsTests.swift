import Testing
@testable import NoiseProtocol
import Foundation

struct DeferredPatternsTests {

    private func completeHandshake(_ initiator: NoiseSession, _ responder: NoiseSession) throws {
        var isTurn = true
        while !initiator.isHandshakeComplete && !responder.isHandshakeComplete {
            if isTurn {
                try responder.readMessage(initiator.writeMessage())
            } else {
                try initiator.readMessage(responder.writeMessage())
            }
            isTurn = !isTurn
        }
    }

    private func verifyTransport(_ initiator: NoiseSession, _ responder: NoiseSession) throws {
        let initT = try initiator.split()
        let respT = try responder.split()
        let plaintext = Data("deferred pattern transport test".utf8)
        let ct = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let pt = try respT.receiver.decryptWithAd(Data(), ciphertext: ct)
        #expect(plaintext == pt)
    }

    private func createSessions(_ patternName: String) throws -> (NoiseSession, NoiseSession) {
        let proto = "Noise_\(patternName)_25519_ChaChaPoly_SHA256"
        let desc = try PatternParser.parse(proto)
        let dh = Curve25519DH()

        let needsInitStatic = desc.initiatorPreMessages.contains("s") ||
            desc.messagePatterns.enumerated().contains { idx, tokens in tokens.contains("s") && idx % 2 == 0 }
        let needsRespStatic = desc.responderPreMessages.contains("s") ||
            desc.messagePatterns.enumerated().contains { idx, tokens in tokens.contains("s") && idx % 2 == 1 }

        let initStatic: KeyPair? = needsInitStatic ? dh.generateKeyPair() : nil
        let respStatic: KeyPair? = needsRespStatic ? dh.generateKeyPair() : nil

        let initiator = try NoiseSession(
            protocolName: proto, role: .initiator,
            staticKeyPair: initStatic,
            remoteStaticKey: desc.responderPreMessages.contains("s") ? respStatic?.publicKey : nil
        )
        let responder = try NoiseSession(
            protocolName: proto, role: .responder,
            staticKeyPair: respStatic,
            remoteStaticKey: desc.initiatorPreMessages.contains("s") ? initStatic?.publicKey : nil
        )
        return (initiator, responder)
    }

    @Test("NK1 handshake completes end-to-end")
    func nk1() throws {
        let (i, r) = try createSessions("NK1")
        try completeHandshake(i, r)
        try verifyTransport(i, r)
    }

    @Test("all 23 deferred patterns complete end-to-end")
    func allDeferredPatterns() throws {
        let patterns = [
            "NK1", "NX1",
            "X1N", "X1K", "XK1", "X1K1", "X1X", "XX1", "X1X1",
            "K1N", "K1K", "KK1", "K1K1", "K1X", "KX1", "K1X1",
            "I1N", "I1K", "IK1", "I1K1", "I1X", "IX1", "I1X1"
        ]

        for pattern in patterns {
            let (initiator, responder) = try createSessions(pattern)
            try completeHandshake(initiator, responder)
            #expect(initiator.isHandshakeComplete, "\(pattern) initiator should complete")
            #expect(responder.isHandshakeComplete, "\(pattern) responder should complete")
            try verifyTransport(initiator, responder)
        }
    }
}
