import Foundation

public struct HandshakeDescriptor: Sendable {
    public let pattern: String
    public let dhFunction: String
    public let cipherFunction: String
    public let hashFunction: String
    public let initiatorPreMessages: [String]
    public let responderPreMessages: [String]
    public let messagePatterns: [[String]]
}

public enum PatternParser {

    private static let validDH: Set<String> = ["25519", "448"]
    private static let validCipher: Set<String> = ["ChaChaPoly", "AESGCM"]
    private static let validHash: Set<String> = ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"]

    private struct PatternDef {
        let initiatorPreMessages: [String]
        let responderPreMessages: [String]
        let messagePatterns: [[String]]
    }

    // Fundamental interactive patterns (Section 7.4)
    private static let patterns: [String: PatternDef] = [
        "NN": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee"]]),
        "NK": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                         messagePatterns: [["e", "es"], ["e", "ee"]]),
        "NX": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee", "s", "es"]]),
        "KN": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee", "se"]]),
        "KK": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                         messagePatterns: [["e", "es", "ss"], ["e", "ee", "se"]]),
        "KX": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee", "se", "s", "es"]]),
        "XN": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee"], ["s", "se"]]),
        "XK": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                         messagePatterns: [["e", "es"], ["e", "ee"], ["s", "se"]]),
        "XX": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e"], ["e", "ee", "s", "es"], ["s", "se"]]),
        "IN": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e", "s"], ["e", "ee", "se"]]),
        "IK": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                         messagePatterns: [["e", "es", "s", "ss"], ["e", "ee", "se"]]),
        "IX": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                         messagePatterns: [["e", "s"], ["e", "ee", "se", "s", "es"]]),
        // One-way patterns (Section 7.3)
        "N": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es"]]),
        "K": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es", "ss"]]),
        "X": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es", "s", "ss"]]),
    ]

    public static func parse(_ protocolName: String) throws -> HandshakeDescriptor {
        let parts = protocolName.split(separator: "_").map(String.init)
        guard parts.count == 5, parts[0] == "Noise" else {
            throw NoiseError.invalidPattern(protocolName)
        }

        let patternName = parts[1]
        let dh = parts[2]
        let cipher = parts[3]
        let hash = parts[4]

        guard validDH.contains(dh) else {
            throw NoiseError.invalidPattern("Unknown DH: \(dh)")
        }
        guard validCipher.contains(cipher) else {
            throw NoiseError.invalidPattern("Unknown cipher: \(cipher)")
        }
        guard validHash.contains(hash) else {
            throw NoiseError.invalidPattern("Unknown hash: \(hash)")
        }

        guard let patternDef = patterns[patternName] else {
            throw NoiseError.invalidPattern("Unknown pattern: \(patternName)")
        }

        return HandshakeDescriptor(
            pattern: patternName,
            dhFunction: dh,
            cipherFunction: cipher,
            hashFunction: hash,
            initiatorPreMessages: patternDef.initiatorPreMessages,
            responderPreMessages: patternDef.responderPreMessages,
            messagePatterns: patternDef.messagePatterns
        )
    }
}
