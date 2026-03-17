import Foundation

/// Describes a parsed Noise Protocol handshake, including the pattern, cryptographic
/// algorithm choices, pre-message tokens, and message patterns.
///
/// This struct is produced by ``PatternParser/parse(_:)`` and consumed by
/// ``HandshakeState`` to drive the handshake.
public struct HandshakeDescriptor: Sendable {
    /// The base pattern name (e.g., `"XX"`, `"IK"`, `"N"`).
    public let pattern: String
    /// The DH function name (e.g., `"25519"`, `"448"`).
    public let dhFunction: String
    /// The cipher function name (e.g., `"ChaChaPoly"`, `"AESGCM"`).
    public let cipherFunction: String
    /// The hash function name (e.g., `"SHA256"`, `"BLAKE2b"`).
    public let hashFunction: String
    /// Tokens for the initiator's pre-message (e.g., `["s"]` for patterns where the initiator's static key is known).
    public let initiatorPreMessages: [String]
    /// Tokens for the responder's pre-message (e.g., `["s"]` for patterns where the responder's static key is known).
    public let responderPreMessages: [String]
    /// The ordered list of message patterns, each containing a list of tokens (e.g., `["e", "es", "ss"]`).
    public let messagePatterns: [[String]]
    /// Whether this descriptor uses the legacy `NoisePSK_` prefix convention.
    public let isNoisePSK: Bool
    /// The PSK modifier positions (e.g., `[0, 2]` for `psk0+psk2`).
    public let pskPositions: [Int]

    /// Creates a new handshake descriptor with the given configuration.
    ///
    /// - Parameters:
    ///   - pattern: The base pattern name.
    ///   - dhFunction: The DH function name.
    ///   - cipherFunction: The cipher function name.
    ///   - hashFunction: The hash function name.
    ///   - initiatorPreMessages: Tokens for the initiator's pre-message.
    ///   - responderPreMessages: Tokens for the responder's pre-message.
    ///   - messagePatterns: The ordered message patterns with their tokens.
    ///   - isNoisePSK: Whether the legacy `NoisePSK_` prefix is used (default: `false`).
    ///   - pskPositions: PSK modifier positions (default: empty).
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

/// Parses Noise Protocol name strings into ``HandshakeDescriptor`` values.
///
/// Thin orchestrator that delegates to ``PatternRegistry`` for pattern lookup
/// and ``Modifiers`` for fallback/PSK transformations. Algorithm validation
/// is handled downstream by ``CryptoResolver``.
public enum PatternParser {

    /// Parses a full Noise protocol name string into a ``HandshakeDescriptor``.
    ///
    /// The protocol name must follow the format:
    /// `Noise_<pattern>[modifiers]_<DH>_<cipher>_<hash>` or
    /// `NoisePSK_<pattern>_<DH>_<cipher>_<hash>`.
    ///
    /// - Parameter protocolName: The full Noise protocol name (e.g., `"Noise_XX_25519_ChaChaPoly_SHA256"`).
    /// - Returns: A ``HandshakeDescriptor`` containing all parsed pattern information.
    /// - Throws: ``NoiseError/invalidPattern(_:)`` if the name is malformed or references an unknown pattern.
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

        let (remainingPattern, isFallback) = extractFallbackModifier(patternField)
        let (baseName, pskPositions) = extractPskModifiers(remainingPattern)

        guard let basePatternDef = PatternRegistry[baseName] else {
            throw NoiseError.invalidPattern("Unknown pattern: \(baseName)")
        }

        let patternDef = isFallback ? Modifiers.applyFallback(basePatternDef) : basePatternDef

        let messagePatterns: [[String]]
        if isNoisePSKPrefix {
            messagePatterns = patternDef.messagePatterns
        } else {
            messagePatterns = try Modifiers.insertPskTokens(patternDef.messagePatterns, positions: pskPositions)
        }

        let displayName = baseName + (isFallback ? "fallback" : "")

        return HandshakeDescriptor(
            pattern: displayName,
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

    private static func extractFallbackModifier(_ patternField: String) -> (String, Bool) {
        let fallbackSuffix = "fallback"
        if let range = patternField.range(of: fallbackSuffix) {
            var remaining = patternField
            remaining.removeSubrange(range)
            return (remaining, true)
        }
        return (patternField, false)
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
}
