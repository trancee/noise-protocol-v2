import Foundation

public struct HandshakeDescriptor: Sendable {
    public let pattern: String
    public let dhFunction: String
    public let cipherFunction: String
    public let hashFunction: String
    public let initiatorPreMessages: [String]
    public let responderPreMessages: [String]
    public let messagePatterns: [[String]]
    public let isNoisePSK: Bool
    public let pskPositions: [Int]

    public init(pattern: String, dhFunction: String, cipherFunction: String, hashFunction: String,
                initiatorPreMessages: [String], responderPreMessages: [String],
                messagePatterns: [[String]], isNoisePSK: Bool = false, pskPositions: [Int] = []) {
        self.pattern = pattern
        self.dhFunction = dhFunction
        self.cipherFunction = cipherFunction
        self.hashFunction = hashFunction
        self.initiatorPreMessages = initiatorPreMessages
        self.responderPreMessages = responderPreMessages
        self.messagePatterns = messagePatterns
        self.isNoisePSK = isNoisePSK
        self.pskPositions = pskPositions
    }
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
        // Deferred patterns (Appendix 18.1)
        "NK1": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                          messagePatterns: [["e"], ["e", "ee", "es"]]),
        "NX1": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee", "s"], ["es"]]),
        "X1N": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee"], ["s"], ["se"]]),
        "X1K": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                          messagePatterns: [["e", "es"], ["e", "ee"], ["s"], ["se"]]),
        "XK1": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                          messagePatterns: [["e"], ["e", "ee", "es"], ["s", "se"]]),
        "X1K1": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                           messagePatterns: [["e"], ["e", "ee", "es"], ["s"], ["se"]]),
        "X1X": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee", "s", "es"], ["s"], ["se"]]),
        "XX1": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee", "s"], ["es", "s", "se"]]),
        "X1X1": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                           messagePatterns: [["e"], ["e", "ee", "s"], ["es", "s"], ["se"]]),
        "K1N": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee"], ["se"]]),
        "K1K": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                          messagePatterns: [["e", "es"], ["e", "ee"], ["se"]]),
        "KK1": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                          messagePatterns: [["e"], ["e", "ee", "se", "es"]]),
        "K1K1": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                           messagePatterns: [["e"], ["e", "ee", "es"], ["se"]]),
        "K1X": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee", "s", "es"], ["se"]]),
        "KX1": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                          messagePatterns: [["e"], ["e", "ee", "se", "s"], ["es"]]),
        "K1X1": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: [],
                           messagePatterns: [["e"], ["e", "ee", "s"], ["se", "es"]]),
        "I1N": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e", "s"], ["e", "ee"], ["se"]]),
        "I1K": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                          messagePatterns: [["e", "es", "s"], ["e", "ee"], ["se"]]),
        "IK1": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                          messagePatterns: [["e", "s"], ["e", "ee", "se", "es"]]),
        "I1K1": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                           messagePatterns: [["e", "s"], ["e", "ee", "es"], ["se"]]),
        "I1X": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e", "s"], ["e", "ee", "s", "es"], ["se"]]),
        "IX1": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                          messagePatterns: [["e", "s"], ["e", "ee", "se", "s"], ["es"]]),
        "I1X1": PatternDef(initiatorPreMessages: [], responderPreMessages: [],
                           messagePatterns: [["e", "s"], ["e", "ee", "s"], ["se", "es"]]),
    ]

    public static func parse(_ protocolName: String) throws -> HandshakeDescriptor {
        let parts = protocolName.split(separator: "_").map(String.init)

        let isNoisePSKPrefix: Bool
        let patternField: String
        let dh: String
        let cipher: String
        let hash: String

        if parts.count == 5 && parts[0] == "NoisePSK" {
            isNoisePSKPrefix = true
            patternField = parts[1]
            dh = parts[2]
            cipher = parts[3]
            hash = parts[4]
        } else if parts.count == 5 && parts[0] == "Noise" {
            isNoisePSKPrefix = false
            patternField = parts[1]
            dh = parts[2]
            cipher = parts[3]
            hash = parts[4]
        } else {
            throw NoiseError.invalidPattern(protocolName)
        }

        guard validDH.contains(dh) else {
            throw NoiseError.invalidPattern("Unknown DH: \(dh)")
        }
        guard validCipher.contains(cipher) else {
            throw NoiseError.invalidPattern("Unknown cipher: \(cipher)")
        }
        guard validHash.contains(hash) else {
            throw NoiseError.invalidPattern("Unknown hash: \(hash)")
        }

        let (baseName, pskPositions) = extractPskModifiers(patternField)

        guard let patternDef = patterns[baseName] else {
            throw NoiseError.invalidPattern("Unknown pattern: \(baseName)")
        }

        let messagePatterns: [[String]]
        if isNoisePSKPrefix {
            messagePatterns = patternDef.messagePatterns
        } else {
            messagePatterns = insertPskTokens(patternDef.messagePatterns, pskPositions: pskPositions)
        }

        return HandshakeDescriptor(
            pattern: baseName,
            dhFunction: dh,
            cipherFunction: cipher,
            hashFunction: hash,
            initiatorPreMessages: patternDef.initiatorPreMessages,
            responderPreMessages: patternDef.responderPreMessages,
            messagePatterns: messagePatterns,
            isNoisePSK: isNoisePSKPrefix,
            pskPositions: pskPositions
        )
    }

    private static func extractPskModifiers(_ patternField: String) -> (String, [Int]) {
        let regex = try! NSRegularExpression(pattern: "psk(\\d+)")
        let range = NSRange(patternField.startIndex..., in: patternField)
        let matches = regex.matches(in: patternField, range: range)
        let positions = matches.compactMap { match -> Int? in
            guard let numRange = Range(match.range(at: 1), in: patternField) else { return nil }
            return Int(patternField[numRange])
        }
        let baseName = patternField.replacingOccurrences(of: "(psk\\d+\\+?)+", with: "", options: .regularExpression)
        return (baseName, positions)
    }

    private static func insertPskTokens(_ patterns: [[String]], pskPositions: [Int]) -> [[String]] {
        if pskPositions.isEmpty { return patterns }
        var result = patterns.map { Array($0) }
        for pos in pskPositions {
            if pos == 0 {
                result[0].insert("psk", at: 0)
            } else {
                let msgIdx = pos - 1
                if msgIdx < result.count {
                    result[msgIdx].append("psk")
                }
            }
        }
        return result
    }
}
