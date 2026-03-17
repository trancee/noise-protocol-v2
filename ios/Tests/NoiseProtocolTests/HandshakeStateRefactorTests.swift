import Testing
@testable import NoiseProtocol
import Foundation

struct HandshakeStateRefactorTests {

    // ── KeyStore domain errors ──────────────────────────────────

    @Test func keyStoreThrowsForMissingLocalStatic() throws {
        let store = KeyStore()
        #expect(throws: NoiseError.self) {
            try store.requireKeyPair(.s)
        }
    }

    @Test func keyStoreThrowsForMissingLocalEphemeral() throws {
        let store = KeyStore()
        #expect(throws: NoiseError.self) {
            try store.requireKeyPair(.e)
        }
    }

    @Test func keyStoreThrowsForMissingRemoteStatic() throws {
        let store = KeyStore()
        #expect(throws: NoiseError.self) {
            try store.requirePublicKey(.rs)
        }
    }

    @Test func keyStoreThrowsForMissingRemoteEphemeral() throws {
        let store = KeyStore()
        #expect(throws: NoiseError.self) {
            try store.requirePublicKey(.re)
        }
    }

    @Test func keyStoreReturnsKeysWhenPresent() throws {
        let kp = Curve25519DH().generateKeyPair()
        let rsPub = Curve25519DH().generateKeyPair().publicKey
        let store = KeyStore(staticKeyPair: kp, remoteStaticKey: rsPub)

        let gotKP = try store.requireKeyPair(.s)
        #expect(gotKP.publicKey == kp.publicKey)
        #expect(try store.requirePublicKey(.rs) == rsPub)
    }

    // ── DH dispatch table ───────────────────────────────────────

    @Test func dhDispatchTableMapsAllEntries() throws {
        // ee: both roles use (e, re)
        #expect(DH_DISPATCH["ee"]?[.initiator] == DhOp(local: .e, remote: .re))
        #expect(DH_DISPATCH["ee"]?[.responder] == DhOp(local: .e, remote: .re))
        // es
        #expect(DH_DISPATCH["es"]?[.initiator] == DhOp(local: .e, remote: .rs))
        #expect(DH_DISPATCH["es"]?[.responder] == DhOp(local: .s, remote: .re))
        // se
        #expect(DH_DISPATCH["se"]?[.initiator] == DhOp(local: .s, remote: .re))
        #expect(DH_DISPATCH["se"]?[.responder] == DhOp(local: .e, remote: .rs))
        // ss
        #expect(DH_DISPATCH["ss"]?[.initiator] == DhOp(local: .s, remote: .rs))
        #expect(DH_DISPATCH["ss"]?[.responder] == DhOp(local: .s, remote: .rs))
    }

    // ── HandshakeConfig tracer bullet ───────────────────────────

    @Test func nnHandshakeWorksWithConfig() throws {
        let suite = try DefaultCryptoResolver.default.resolve(
            dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256"
        )
        let descriptor = try PatternParser.parse("Noise_NN_25519_ChaChaPoly_SHA256")

        let iConfig = HandshakeConfig(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .initiator,
            dh: suite.dh, cipher: suite.cipher, hash: suite.hash,
            descriptor: descriptor
        )
        let rConfig = HandshakeConfig(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .responder,
            dh: suite.dh, cipher: suite.cipher, hash: suite.hash,
            descriptor: descriptor
        )

        let initiator = try HandshakeState(config: iConfig)
        let responder = try HandshakeState(config: rConfig)

        let msg1 = try initiator.writeMessage()
        let _ = try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage()
        let _ = try initiator.readMessage(msg2)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }

    // ── Upfront validation ──────────────────────────────────────

    @Test func kkWithoutStaticKeyThrows() throws {
        let suite = try DefaultCryptoResolver.default.resolve(
            dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256"
        )
        let descriptor = try PatternParser.parse("Noise_KK_25519_ChaChaPoly_SHA256")

        let config = HandshakeConfig(
            protocolName: "Noise_KK_25519_ChaChaPoly_SHA256",
            role: .initiator,
            dh: suite.dh, cipher: suite.cipher, hash: suite.hash,
            descriptor: descriptor,
            remoteStaticKey: Curve25519DH().generateKeyPair().publicKey
        )

        #expect(throws: NoiseError.self) {
            try HandshakeState(config: config)
        }
    }

    @Test func nkWithoutRemoteStaticThrows() throws {
        let suite = try DefaultCryptoResolver.default.resolve(
            dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256"
        )
        let descriptor = try PatternParser.parse("Noise_NK_25519_ChaChaPoly_SHA256")

        let config = HandshakeConfig(
            protocolName: "Noise_NK_25519_ChaChaPoly_SHA256",
            role: .initiator,
            dh: suite.dh, cipher: suite.cipher, hash: suite.hash,
            descriptor: descriptor
        )

        #expect(throws: NoiseError.self) {
            try HandshakeState(config: config)
        }
    }

    @Test func nnpsk0WithoutPskThrows() throws {
        let suite = try DefaultCryptoResolver.default.resolve(
            dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256"
        )
        let descriptor = try PatternParser.parse("Noise_NNpsk0_25519_ChaChaPoly_SHA256")

        let config = HandshakeConfig(
            protocolName: "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
            role: .initiator,
            dh: suite.dh, cipher: suite.cipher, hash: suite.hash,
            descriptor: descriptor
        )

        #expect(throws: NoiseError.self) {
            try HandshakeState(config: config)
        }
    }
}
