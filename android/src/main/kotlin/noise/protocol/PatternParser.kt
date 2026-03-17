package noise.protocol

data class HandshakeDescriptor(
    val pattern: String,
    val dhFunction: String,
    val cipherFunction: String,
    val hashFunction: String,
    val initiatorPreMessages: List<String>,
    val responderPreMessages: List<String>,
    val messagePatterns: List<List<String>>,
    val pskPositions: List<Int> = emptyList(),
    val isNoisePSK: Boolean = false
)

sealed class NoiseException(message: String) : Exception(message) {
    class InvalidPattern(pattern: String) : NoiseException("Invalid pattern: $pattern")
    class InvalidKey(message: String) : NoiseException(message)
    class InvalidState(message: String) : NoiseException(message)
    class HandshakeIncomplete : NoiseException("Handshake not complete")
    class DecryptionFailed : NoiseException("Decryption failed")
    class NonceExhausted : NoiseException("Nonce exhausted")
    class SessionInvalidated : NoiseException("Session invalidated")
}

object PatternParser {

    private val VALID_DH = setOf("25519", "448")
    private val VALID_CIPHER = setOf("ChaChaPoly", "AESGCM")
    private val VALID_HASH = setOf("SHA256", "SHA512", "BLAKE2s", "BLAKE2b")

    private data class PatternDef(
        val initiatorPreMessages: List<String>,
        val responderPreMessages: List<String>,
        val messagePatterns: List<List<String>>
    )

    // Fundamental interactive patterns (Section 7.4)
    private val PATTERNS = mapOf(
        "NN" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"))
        ),
        "NK" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"))
        ),
        "NX" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"))
        ),
        "KN" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se"))
        ),
        "KK" to PatternDef(
            listOf("s"), listOf("s"),
            listOf(listOf("e", "es", "ss"), listOf("e", "ee", "se"))
        ),
        "KX" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se", "s", "es"))
        ),
        "XN" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("s", "se"))
        ),
        "XK" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("s", "se"))
        ),
        "XX" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("s", "se"))
        ),
        "IN" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se"))
        ),
        "IK" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s", "ss"), listOf("e", "ee", "se"))
        ),
        "IX" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "s", "es"))
        ),
        // One-way patterns (Section 7.3)
        "N" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es"))
        ),
        "K" to PatternDef(
            listOf("s"), listOf("s"),
            listOf(listOf("e", "es", "ss"))
        ),
        "X" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s", "ss"))
        ),
        // Deferred patterns (Appendix 18.1)
        "NK1" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"))
        ),
        "NX1" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es"))
        ),
        "X1N" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("s"), listOf("se"))
        ),
        "X1K" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("s"), listOf("se"))
        ),
        "XK1" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("s", "se"))
        ),
        "X1K1" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("s"), listOf("se"))
        ),
        "X1X" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("s"), listOf("se"))
        ),
        "XX1" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es", "s", "se"))
        ),
        "X1X1" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("es", "s"), listOf("se"))
        ),
        "K1N" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee"), listOf("se"))
        ),
        "K1K" to PatternDef(
            listOf("s"), listOf("s"),
            listOf(listOf("e", "es"), listOf("e", "ee"), listOf("se"))
        ),
        "KK1" to PatternDef(
            listOf("s"), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "se", "es"))
        ),
        "K1K1" to PatternDef(
            listOf("s"), listOf("s"),
            listOf(listOf("e"), listOf("e", "ee", "es"), listOf("se"))
        ),
        "K1X" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s", "es"), listOf("se"))
        ),
        "KX1" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "se", "s"), listOf("es"))
        ),
        "K1X1" to PatternDef(
            listOf("s"), emptyList(),
            listOf(listOf("e"), listOf("e", "ee", "s"), listOf("se", "es"))
        ),
        "I1N" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee"), listOf("se"))
        ),
        "I1K" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "es", "s"), listOf("e", "ee"), listOf("se"))
        ),
        "IK1" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "es"))
        ),
        "I1K1" to PatternDef(
            emptyList(), listOf("s"),
            listOf(listOf("e", "s"), listOf("e", "ee", "es"), listOf("se"))
        ),
        "I1X" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "s", "es"), listOf("se"))
        ),
        "IX1" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "se", "s"), listOf("es"))
        ),
        "I1X1" to PatternDef(
            emptyList(), emptyList(),
            listOf(listOf("e", "s"), listOf("e", "ee", "s"), listOf("se", "es"))
        ),
    )

    fun parse(protocolName: String): HandshakeDescriptor {
        val parts = protocolName.split("_")

        // Handle NoisePSK_ prefix format
        val isNoisePSK = parts.size == 5 && parts[0] == "NoisePSK"
        val isNoise = parts.size == 5 && parts[0] == "Noise"

        if (!isNoise && !isNoisePSK) {
            throw NoiseException.InvalidPattern(protocolName)
        }

        val patternField = parts[1]
        val dh = parts[2]
        val cipher = parts[3]
        val hash = parts[4]

        if (dh !in VALID_DH) throw NoiseException.InvalidPattern("Unknown DH: $dh")
        if (cipher !in VALID_CIPHER) throw NoiseException.InvalidPattern("Unknown cipher: $cipher")
        if (hash !in VALID_HASH) throw NoiseException.InvalidPattern("Unknown hash: $hash")

        // Extract fallback modifier and psk positions
        val (afterFallback, isFallback) = extractFallbackModifier(patternField)

        val (patternName, pskPositions) = if (isNoisePSK) {
            afterFallback to emptyList<Int>()
        } else {
            extractPskModifiers(afterFallback)
        }

        val patternDef = PATTERNS[patternName]
            ?: throw NoiseException.InvalidPattern("Unknown pattern: $patternName")

        // Apply fallback modifier: convert first message to pre-message, swap roles
        val effectiveDef = if (isFallback) applyFallback(patternDef) else patternDef

        // NoisePSK_ uses a different mechanism: PSK mixed before pre-messages,
        // MixKey(e.pub) after each 'e' token. No psk tokens in message patterns.
        // Modern pskN modifiers insert explicit 'psk' tokens into message patterns.
        val modifiedPatterns = if (isNoisePSK) {
            effectiveDef.messagePatterns
        } else {
            insertPskTokens(effectiveDef.messagePatterns, pskPositions)
        }

        val displayPattern = if (isFallback) "${patternName}fallback" else patternName

        return HandshakeDescriptor(
            pattern = displayPattern,
            dhFunction = dh,
            cipherFunction = cipher,
            hashFunction = hash,
            initiatorPreMessages = effectiveDef.initiatorPreMessages,
            responderPreMessages = effectiveDef.responderPreMessages,
            messagePatterns = modifiedPatterns,
            pskPositions = pskPositions,
            isNoisePSK = isNoisePSK
        )
    }

    private fun extractFallbackModifier(patternField: String): Pair<String, Boolean> {
        val fallbackSuffix = "fallback"
        if (patternField.contains(fallbackSuffix)) {
            val idx = patternField.indexOf(fallbackSuffix)
            val remaining = patternField.removeRange(idx, idx + fallbackSuffix.length)
            return remaining to true
        }
        return patternField to false
    }

    private fun applyFallback(baseDef: PatternDef): PatternDef {
        // The fallback modifier converts the initiator's first message into a pre-message.
        // Only public key tokens (e, s) become pre-messages; DH tokens are dropped.
        // Roles are NOT swapped — the responder simply writes first after the fallback.
        val firstMessage = baseDef.messagePatterns[0]
        val preMessageTokens = firstMessage.filter { it == "e" || it == "s" }
        return PatternDef(
            initiatorPreMessages = baseDef.initiatorPreMessages + preMessageTokens,
            responderPreMessages = baseDef.responderPreMessages,
            messagePatterns = baseDef.messagePatterns.drop(1)
        )
    }

    private fun extractPskModifiers(patternField: String): Pair<String, List<Int>> {
        val pskRegex = Regex("psk(\\d+)")
        val matches = pskRegex.findAll(patternField)
        val positions = matches.map { it.groupValues[1].toInt() }.toList()
        val baseName = patternField.replace(Regex("(psk\\d+\\+?)+"), "")
        return baseName to positions
    }

    private fun insertPskTokens(patterns: List<List<String>>, pskPositions: List<Int>): List<List<String>> {
        if (pskPositions.isEmpty()) return patterns
        val result = patterns.map { it.toMutableList() }
        for (pos in pskPositions) {
            if (pos == 0) {
                result[0].add(0, "psk") // beginning of first message
            } else {
                // pskN (N>0) = end of Nth message (1-indexed)
                val msgIdx = pos - 1
                if (msgIdx < result.size) {
                    result[msgIdx].add("psk")
                }
            }
        }
        return result.map { it.toList() }
    }
}
