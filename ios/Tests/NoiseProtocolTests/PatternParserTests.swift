import Testing
import Foundation
@testable import NoiseProtocol

@Suite("PatternParser Tests")
struct PatternParserTests {

    @Test("parses NN protocol name")
    func parseNN() throws {
        let desc = try PatternParser.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        #expect(desc.pattern == "NN")
        #expect(desc.dhFunction == "25519")
        #expect(desc.cipherFunction == "ChaChaPoly")
        #expect(desc.hashFunction == "SHA256")
        #expect(desc.initiatorPreMessages.isEmpty)
        #expect(desc.responderPreMessages.isEmpty)
        #expect(desc.messagePatterns == [["e"], ["e", "ee"]])
    }

    @Test("parses XX protocol name")
    func parseXX() throws {
        let desc = try PatternParser.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        #expect(desc.pattern == "XX")
        #expect(desc.messagePatterns == [["e"], ["e", "ee", "s", "es"], ["s", "se"]])
    }

    @Test("parses IK with pre-messages")
    func parseIK() throws {
        let desc = try PatternParser.parse("Noise_IK_25519_ChaChaPoly_SHA256")
        #expect(desc.pattern == "IK")
        #expect(desc.initiatorPreMessages.isEmpty)
        #expect(desc.responderPreMessages == ["s"])
    }

    @Test("all 15 patterns are defined")
    func allPatternsExist() throws {
        let names = ["NN", "NK", "NX", "KN", "KK", "KX", "XN", "XK", "XX",
                     "IN", "IK", "IX", "N", "K", "X"]
        for name in names {
            let desc = try PatternParser.parse("Noise_\(name)_25519_ChaChaPoly_SHA256")
            #expect(desc.pattern == name)
        }
    }

    @Test("rejects malformed protocol name")
    func rejectsMalformed() throws {
        #expect(throws: NoiseError.self) {
            try PatternParser.parse("Invalid_Protocol")
        }
    }

    @Test("rejects unknown pattern")
    func rejectsUnknownPattern() throws {
        #expect(throws: NoiseError.self) {
            try PatternParser.parse("Noise_ZZ_25519_ChaChaPoly_SHA256")
        }
    }

    @Test("rejects unknown DH")
    func rejectsUnknownDH() throws {
        #expect(throws: NoiseError.self) {
            try PatternParser.parse("Noise_NN_P256_ChaChaPoly_SHA256")
        }
    }

    @Test("rejects unknown cipher")
    func rejectsUnknownCipher() throws {
        #expect(throws: NoiseError.self) {
            try PatternParser.parse("Noise_NN_25519_AES128_SHA256")
        }
    }

    @Test("rejects unknown hash")
    func rejectsUnknownHash() throws {
        #expect(throws: NoiseError.self) {
            try PatternParser.parse("Noise_NN_25519_ChaChaPoly_MD5")
        }
    }
}
