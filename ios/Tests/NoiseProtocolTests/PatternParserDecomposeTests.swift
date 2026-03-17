import Testing
import Foundation
@testable import NoiseProtocol

@Suite("PatternParser Decompose Tests")
struct PatternParserDecomposeTests {

    @Test("registry contains 38 patterns")
    func registryContains38Patterns() {
        #expect(PatternRegistry.all.count == 38)
    }

    @Test("category counts")
    func categoryCounts() {
        #expect(PatternRegistry.fundamental.count == 12)
        #expect(PatternRegistry.oneWay.count == 3)
        #expect(PatternRegistry.deferred.count == 23)
    }

    @Test("categories are disjoint and exhaustive")
    func categoriesAreDisjointAndExhaustive() {
        let combined = Set(PatternRegistry.fundamental.keys)
            .union(PatternRegistry.oneWay.keys)
            .union(PatternRegistry.deferred.keys)
        #expect(combined.count == 38)
        #expect(combined == Set(PatternRegistry.all.keys))
    }

    @Test("all tokens are valid Noise tokens")
    func allTokensAreValidNoiseTokens() {
        let valid: Set<String> = ["e", "s", "ee", "es", "se", "ss"]
        for (name, def) in PatternRegistry.all {
            for token in def.messagePatterns.flatMap({ $0 }) {
                #expect(valid.contains(token), "Unknown token '\(token)' in \(name)")
            }
        }
    }

    @Test("every pattern first message starts with e or s")
    func everyPatternFirstMessageStartsWithEOrS() {
        for (name, def) in PatternRegistry.all {
            let first = def.messagePatterns[0][0]
            #expect(first == "e" || first == "s", "\(name) first msg doesn't start with e or s")
        }
    }

    @Test("pre-message tokens are only e or s")
    func preMessageTokensAreOnlyEOrS() {
        for (name, def) in PatternRegistry.all {
            for token in def.initiatorPreMessages + def.responderPreMessages {
                #expect(token == "e" || token == "s", "\(name): invalid pre-msg token '\(token)'")
            }
        }
    }

    @Test("applyFallback moves first message tokens")
    func applyFallbackMovesFirstMessageTokens() throws {
        let xx = PatternRegistry["XX"]!
        let result = Modifiers.applyFallback(xx)
        #expect(result.initiatorPreMessages == ["e"])
        #expect(result.messagePatterns.count == 2)
    }

    @Test("applyFallback preserves existing pre-messages")
    func applyFallbackPreservesExistingPreMessages() throws {
        let ik = PatternRegistry["IK"]!
        let result = Modifiers.applyFallback(ik)
        #expect(result.initiatorPreMessages.contains("e"))
        #expect(result.initiatorPreMessages.contains("s"))
        #expect(result.responderPreMessages == ik.responderPreMessages)
    }

    @Test("psk0 prepends to first message")
    func psk0PrependsToFirstMessage() throws {
        let msgs = [["e", "es"], ["e", "ee"]]
        let result = try Modifiers.insertPskTokens(msgs, positions: [0])
        #expect(result[0] == ["psk", "e", "es"])
        #expect(result[1] == ["e", "ee"])
    }

    @Test("pskN appends to message N-1")
    func pskNAppendsToMessageNMinus1() throws {
        let msgs = [["e"], ["e", "ee"]]
        let result = try Modifiers.insertPskTokens(msgs, positions: [2])
        #expect(result[0] == ["e"])
        #expect(result[1] == ["e", "ee", "psk"])
    }

    @Test("out-of-range psk position throws")
    func outOfRangePskPositionThrows() throws {
        #expect(throws: NoiseError.self) {
            try Modifiers.insertPskTokens([["e"]], positions: [5])
        }
    }
}
