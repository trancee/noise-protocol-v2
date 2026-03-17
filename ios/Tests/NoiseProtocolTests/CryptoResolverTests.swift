import Testing
import Foundation
@testable import NoiseProtocol

private struct FakeDH: DH {
    var dhLen: Int { 16 }
    func generateKeyPair() -> KeyPair {
        KeyPair(privateKey: Data(count: 16), publicKey: Data(count: 16))
    }
    func dh(keyPair: KeyPair, publicKey: Data) throws -> Data {
        Data(count: 16)
    }
}

@Suite("CryptoResolver Tests")
struct CryptoResolverTests {

    @Test("Default resolver resolves all standard algorithms")
    func defaultResolverResolvesAllAlgorithms() throws {
        let resolver = DefaultCryptoResolver.default

        // DH functions
        let suite25519 = try resolver.resolve(dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256")
        #expect(suite25519.dh.dhLen == 32)

        let suite448 = try resolver.resolve(dhName: "448", cipherName: "ChaChaPoly", hashName: "SHA256")
        #expect(suite448.dh.dhLen == 56)

        // Ciphers – round-trip encrypt/decrypt
        for cipherName in ["ChaChaPoly", "AESGCM"] {
            let suite = try resolver.resolve(dhName: "25519", cipherName: cipherName, hashName: "SHA256")
            let key = Data(0..<32)
            let plaintext = Data("hello".utf8)
            let ct = try suite.cipher.encrypt(key: key, nonce: 0, ad: Data(), plaintext: plaintext)
            let pt = try suite.cipher.decrypt(key: key, nonce: 0, ad: Data(), ciphertext: ct)
            #expect(pt == plaintext)
        }

        // Hashes
        let sha256 = try resolver.resolve(dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256")
        #expect(sha256.hash.hashLen == 32)

        let sha512 = try resolver.resolve(dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA512")
        #expect(sha512.hash.hashLen == 64)

        let blake2b = try resolver.resolve(dhName: "25519", cipherName: "ChaChaPoly", hashName: "BLAKE2b")
        #expect(blake2b.hash.hashLen == 64)

        let blake2s = try resolver.resolve(dhName: "25519", cipherName: "ChaChaPoly", hashName: "BLAKE2s")
        #expect(blake2s.hash.hashLen == 32)
    }

    @Test("Resolved DH generates valid key pairs")
    func resolvedDHGeneratesValidKeyPairs() throws {
        let suite = try DefaultCryptoResolver.default.resolve(
            dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256"
        )
        let kp = suite.dh.generateKeyPair()
        #expect(kp.publicKey.count == 32)
        #expect(!kp.privateKey.isEmpty)
    }

    @Test("Unknown DH name throws")
    func unknownDHNameThrows() throws {
        #expect(throws: NoiseError.self) {
            try DefaultCryptoResolver.default.resolve(
                dhName: "FakeDH", cipherName: "ChaChaPoly", hashName: "SHA256"
            )
        }
    }

    @Test("Unknown cipher name throws")
    func unknownCipherNameThrows() throws {
        #expect(throws: NoiseError.self) {
            try DefaultCryptoResolver.default.resolve(
                dhName: "25519", cipherName: "FakeCipher", hashName: "SHA256"
            )
        }
    }

    @Test("Unknown hash name throws")
    func unknownHashNameThrows() throws {
        #expect(throws: NoiseError.self) {
            try DefaultCryptoResolver.default.resolve(
                dhName: "25519", cipherName: "ChaChaPoly", hashName: "FakeHash"
            )
        }
    }

    @Test("Builder allows registering a custom algorithm")
    func builderAllowsCustomAlgorithm() throws {
        let resolver = DefaultCryptoResolver.Builder()
            .dh("25519") { Curve25519DH() }
            .dh("custom") { FakeDH() }
            .cipher("ChaChaPoly") { ChaChaPoly_() }
            .hash("SHA256") { SHA256Hash_() }
            .build()

        let suite = try resolver.resolve(dhName: "custom", cipherName: "ChaChaPoly", hashName: "SHA256")
        #expect(suite.dh.dhLen == 16)
    }

    @Test("NoiseSession works with explicit CryptoResolver")
    func noiseSessionWorksWithCustomResolver() throws {
        let resolver = DefaultCryptoResolver.default

        let initiator = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .initiator,
            crypto: resolver
        )
        let responder = try NoiseSession(
            protocolName: "Noise_NN_25519_ChaChaPoly_SHA256",
            role: .responder,
            crypto: resolver
        )

        // NN pattern: 2 messages
        let msg1 = try initiator.writeMessage()
        let _ = try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage()
        let _ = try initiator.readMessage(msg2)

        #expect(initiator.isHandshakeComplete)
        #expect(responder.isHandshakeComplete)
    }
}
