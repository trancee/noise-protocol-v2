import Foundation

/// Defines a base Noise handshake pattern: pre-messages and token sequences.
struct PatternDef {
    let initiatorPreMessages: [String]
    let responderPreMessages: [String]
    let messagePatterns: [[String]]
}
