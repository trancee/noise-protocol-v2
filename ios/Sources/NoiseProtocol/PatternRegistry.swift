import Foundation

/// Authoritative registry of all 38 standard Noise Protocol handshake patterns.
enum PatternRegistry {

    /// 12 fundamental interactive patterns (Noise spec Section 7.4).
    static let fundamental: [String: PatternDef] = [
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
    ]

    /// 3 one-way patterns (Noise spec Section 7.3).
    static let oneWay: [String: PatternDef] = [
        "N": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es"]]),
        "K": PatternDef(initiatorPreMessages: ["s"], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es", "ss"]]),
        "X": PatternDef(initiatorPreMessages: [], responderPreMessages: ["s"],
                        messagePatterns: [["e", "es", "s", "ss"]]),
    ]

    /// 23 deferred patterns (Noise spec Appendix 18.1).
    static let deferred: [String: PatternDef] = [
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

    /// All 38 patterns merged.
    static let all: [String: PatternDef] = {
        var combined = fundamental
        combined.merge(oneWay) { a, _ in a }
        combined.merge(deferred) { a, _ in a }
        return combined
    }()

    static subscript(name: String) -> PatternDef? {
        return all[name]
    }
}
