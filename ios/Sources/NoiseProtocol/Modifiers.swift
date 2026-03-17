import Foundation

/// Pure transformation functions for Noise pattern modifiers.
enum Modifiers {

    /// Applies the fallback modifier: moves first message's key tokens to pre-messages.
    static func applyFallback(_ base: PatternDef) -> PatternDef {
        let firstMessage = base.messagePatterns[0]
        let preTokens = firstMessage.filter { $0 == "e" || $0 == "s" }
        return PatternDef(
            initiatorPreMessages: base.initiatorPreMessages + preTokens,
            responderPreMessages: base.responderPreMessages,
            messagePatterns: Array(base.messagePatterns.dropFirst())
        )
    }

    /// Inserts "psk" tokens into message patterns at specified positions.
    static func insertPskTokens(_ messages: [[String]], positions: [Int]) throws -> [[String]] {
        if positions.isEmpty { return messages }
        var result = messages.map { Array($0) }
        for pos in positions {
            if pos == 0 {
                result[0].insert("psk", at: 0)
            } else if pos >= 1 && pos <= result.count {
                result[pos - 1].append("psk")
            } else {
                throw NoiseError.invalidPattern("psk\(pos) out of range for \(result.count)-message pattern")
            }
        }
        return result
    }
}
