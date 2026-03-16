import Testing
import Foundation
@testable import NoiseProtocol

@Suite("One-Way Patterns Tests")
struct OneWayPatternsTests {

    @Test("Pattern N completes single-message handshake and transports data")
    func patternN() throws {
        let respStatic = Curve25519DH().generateKeyPair()

        let initiator = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .initiator,
            remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic)

        let payload = try responder.readMessage(initiator.writeMessage(Data("Hello one-way".utf8)))
        #expect(payload == Data("Hello one-way".utf8))

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let plaintext = Data("One-way message".utf8)
        let ciphertext = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let decrypted = try respT.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("One-way responder sender throws")
    func responderSenderThrows() throws {
        let respStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .initiator,
            remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic)

        try responder.readMessage(initiator.writeMessage())
        let respT = try responder.split()

        #expect(throws: NoiseError.self) {
            try respT.sender.encryptWithAd(Data(), plaintext: Data("should fail".utf8))
        }
    }

    @Test("One-way initiator receiver throws")
    func initiatorReceiverThrows() throws {
        let respStatic = Curve25519DH().generateKeyPair()
        let initiator = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .initiator,
            remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(
            protocolName: "Noise_N_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic)

        try responder.readMessage(initiator.writeMessage())
        let initT = try initiator.split()

        #expect(throws: NoiseError.self) {
            try initT.receiver.decryptWithAd(Data(), ciphertext: Data(count: 32))
        }
    }

    @Test("Pattern K completes with pre-shared static keys")
    func patternK() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let respStatic = Curve25519DH().generateKeyPair()

        let initiator = try NoiseSession(
            protocolName: "Noise_K_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic, remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(
            protocolName: "Noise_K_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic, remoteStaticKey: initStatic.publicKey)

        let payload = try responder.readMessage(initiator.writeMessage(Data("K pattern".utf8)))
        #expect(payload == Data("K pattern".utf8))

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let plaintext = Data("K transport".utf8)
        let ciphertext = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let decrypted = try respT.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == plaintext)

        #expect(throws: NoiseError.self) {
            try respT.sender.encryptWithAd(Data(), plaintext: Data("nope".utf8))
        }
    }

    @Test("Pattern X transmits initiator static and completes")
    func patternX() throws {
        let initStatic = Curve25519DH().generateKeyPair()
        let respStatic = Curve25519DH().generateKeyPair()

        let initiator = try NoiseSession(
            protocolName: "Noise_X_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic, remoteStaticKey: respStatic.publicKey)
        let responder = try NoiseSession(
            protocolName: "Noise_X_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic)

        let payload = try responder.readMessage(initiator.writeMessage(Data("X pattern".utf8)))
        #expect(payload == Data("X pattern".utf8))

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)

        let initT = try initiator.split()
        let respT = try responder.split()

        let plaintext = Data("X transport".utf8)
        let ciphertext = try initT.sender.encryptWithAd(Data(), plaintext: plaintext)
        let decrypted = try respT.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
        #expect(decrypted == plaintext)

        #expect(throws: NoiseError.self) {
            try initT.receiver.decryptWithAd(Data(), ciphertext: Data(count: 32))
        }
    }
}
