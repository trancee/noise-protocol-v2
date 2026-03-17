package noise.protocol

/**
 * Pure transformation functions for Noise pattern modifiers.
 *
 * Contains the fallback and PSK modifier logic, extracted from PatternParser
 * for independent testability.
 *
 * @see PatternParser
 */
object Modifiers {

    /**
     * Applies the fallback modifier: moves first message's key tokens to pre-messages.
     *
     * Only public key tokens (`e`, `s`) become pre-messages; DH tokens are dropped.
     * The remaining messages shift down by one.
     */
    fun applyFallback(base: PatternDef): PatternDef {
        val firstMsg = base.messagePatterns[0]
        val preTokens = firstMsg.filter { it == "e" || it == "s" }
        return PatternDef(
            initiatorPreMessages = base.initiatorPreMessages + preTokens,
            responderPreMessages = base.responderPreMessages,
            messagePatterns = base.messagePatterns.drop(1)
        )
    }

    /**
     * Inserts "psk" tokens into message patterns at the specified positions.
     *
     * Convention (Noise spec §10):
     * - `psk0` → prepend "psk" to `messages[0]`
     * - `pskN` (N>0) → append "psk" to `messages[N-1]`
     *
     * @throws NoiseException.InvalidPattern if a position is out of range.
     */
    fun insertPskTokens(
        messages: List<List<String>>,
        pskPositions: List<Int>
    ): List<List<String>> {
        if (pskPositions.isEmpty()) return messages
        val result = messages.map { it.toMutableList() }
        for (pos in pskPositions) {
            when {
                pos == 0 -> result[0].add(0, "psk")
                pos in 1..result.size -> result[pos - 1].add("psk")
                else -> throw NoiseException.InvalidPattern(
                    "psk$pos out of range for ${result.size}-message pattern"
                )
            }
        }
        return result.map { it.toList() }
    }
}
