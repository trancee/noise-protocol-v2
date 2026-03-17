package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for the PatternParser decomposition (issue #19):
 * PatternRegistry categories, Modifiers as testable functions, structural validation.
 */
class PatternParserDecomposeTest {

    // ── Slice 1: PatternRegistry categorized ────────────────────────

    @Test
    fun `registry contains exactly 38 patterns`() {
        assertEquals(38, PatternRegistry.all.size)
    }

    @Test
    fun `12 fundamental, 3 one-way, 23 deferred`() {
        assertEquals(12, PatternRegistry.fundamental.size)
        assertEquals(3, PatternRegistry.oneWay.size)
        assertEquals(23, PatternRegistry.deferred.size)
    }

    @Test
    fun `categories are disjoint and exhaustive`() {
        val combined = PatternRegistry.fundamental.keys +
            PatternRegistry.oneWay.keys +
            PatternRegistry.deferred.keys
        assertEquals(combined.toSet().size, combined.size, "Duplicate pattern names across categories")
        assertEquals(PatternRegistry.all.keys, combined.toSet())
    }

    // ── Slice 2: Structural validation ──────────────────────────────

    @Test
    fun `all tokens are valid Noise tokens`() {
        val valid = setOf("e", "s", "ee", "es", "se", "ss")
        PatternRegistry.all.values.forEach { def ->
            def.messagePatterns.flatten().forEach { token ->
                assertTrue(token in valid, "Unknown token '$token' in pattern")
            }
        }
    }

    @Test
    fun `every pattern first message starts with e or s`() {
        PatternRegistry.all.forEach { (name, def) ->
            assertTrue(
                def.messagePatterns[0][0] in setOf("e", "s"),
                "$name first message doesn't start with 'e' or 's'"
            )
        }
    }

    @Test
    fun `pre-message tokens are only e or s`() {
        PatternRegistry.all.forEach { (name, def) ->
            (def.initiatorPreMessages + def.responderPreMessages).forEach { token ->
                assertTrue(
                    token in setOf("e", "s"),
                    "$name: invalid pre-message token '$token'"
                )
            }
        }
    }

    // ── Slice 3: Modifiers.applyFallback ────────────────────────────

    @Test
    fun `applyFallback moves first message key tokens to pre-messages`() {
        val xx = PatternRegistry["XX"]!!
        val result = Modifiers.applyFallback(xx)
        assertEquals(listOf("e"), result.initiatorPreMessages)
        assertEquals(2, result.messagePatterns.size) // 3 messages → 2
    }

    @Test
    fun `applyFallback preserves existing pre-messages`() {
        val ik = PatternRegistry["IK"]!!
        val result = Modifiers.applyFallback(ik)
        // IK first message: [e, es, s, ss] → pre "e" and "s"
        assertTrue(result.initiatorPreMessages.contains("e"))
        assertTrue(result.initiatorPreMessages.contains("s"))
        // Responder pre-messages should be preserved
        assertEquals(ik.responderPreMessages, result.responderPreMessages)
    }

    // ── Slice 4: Modifiers.insertPskTokens ──────────────────────────

    @Test
    fun `psk0 prepends to first message`() {
        val msgs = listOf(listOf("e", "es"), listOf("e", "ee"))
        val result = Modifiers.insertPskTokens(msgs, listOf(0))
        assertEquals(listOf("psk", "e", "es"), result[0])
        assertEquals(listOf("e", "ee"), result[1])
    }

    @Test
    fun `pskN appends to message N-1`() {
        val msgs = listOf(listOf("e"), listOf("e", "ee"))
        val result = Modifiers.insertPskTokens(msgs, listOf(2))
        assertEquals(listOf("e"), result[0])
        assertEquals(listOf("e", "ee", "psk"), result[1])
    }

    @Test
    fun `multiple psk positions`() {
        val msgs = listOf(listOf("e"), listOf("e", "ee"))
        val result = Modifiers.insertPskTokens(msgs, listOf(0, 2))
        assertEquals(listOf("psk", "e"), result[0])
        assertEquals(listOf("e", "ee", "psk"), result[1])
    }

    @Test
    fun `out of range psk position throws`() {
        assertThrows<NoiseException.InvalidPattern> {
            Modifiers.insertPskTokens(listOf(listOf("e")), listOf(5))
        }
    }
}
