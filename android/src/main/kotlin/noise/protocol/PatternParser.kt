package noise.protocol

/**
 * Describes a fully-parsed Noise Protocol handshake including the pattern name,
 * cryptographic algorithm choices, pre-message tokens, and the ordered message
 * patterns that define the handshake flow.
 *
 * Instances are produced by [PatternParser.parse] and consumed by [HandshakeState].
 *
 * @property pattern The base handshake pattern name (e.g. `"XX"`, `"IK"`, `"N"`).
 * @property dhFunction The Diffie-Hellman function identifier (e.g. `"25519"`, `"448"`).
 * @property cipherFunction The AEAD cipher identifier (e.g. `"ChaChaPoly"`, `"AESGCM"`).
 * @property hashFunction The hash function identifier (e.g. `"SHA256"`, `"BLAKE2b"`).
 * @property initiatorPreMessages Tokens that the initiator has pre-shared (e.g. `["s"]`).
 * @property responderPreMessages Tokens that the responder has pre-shared (e.g. `["s"]`).
 * @property messagePatterns Ordered list of message patterns; each entry is a list of tokens
 *   (e.g. `["e", "es", "ss"]`) that define one handshake message.
 * @property pskPositions Positions at which PSK tokens are inserted (modern `pskN` modifier).
 * @property isNoisePSK `true` when using the legacy `NoisePSK_` prefix convention.
 * @see PatternParser
 * @see HandshakeState
 */
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

/**
 * Base exception type for all errors originating from the Noise Protocol library.
 *
 * This is a sealed class, so callers can exhaustively `when`-match over the
 * specific exception subtypes.
 *
 * @param message Human-readable description of the error.
 * @see NoiseSession
 */
sealed class NoiseException(message: String) : Exception(message) {
    /**
     * The protocol name string could not be parsed, or references an
     * unsupported pattern, DH function, cipher, or hash.
     *
     * @param pattern Description of what was invalid.
     */
    class InvalidPattern(pattern: String) : NoiseException("Invalid pattern: $pattern")

    /**
     * A required key (static, ephemeral, or PSK) was missing or malformed.
     *
     * @param message Details about the missing or invalid key.
     */
    class InvalidKey(message: String) : NoiseException(message)

    /**
     * An operation was attempted in an invalid protocol state
     * (e.g. sending data after the handshake completed without calling [NoiseSession.split]).
     *
     * @param message Details about the invalid state transition.
     */
    class InvalidState(message: String) : NoiseException(message)

    /**
     * A [HandshakeState.split] was called before the handshake finished.
     */
    class HandshakeIncomplete : NoiseException("Handshake not complete")

    /**
     * An AEAD decryption operation failed (authentication tag mismatch).
     *
     * When this exception is thrown the [CipherState] is permanently invalidated
     * to prevent further use of a potentially compromised session.
     */
    class DecryptionFailed : NoiseException("Decryption failed")

    /**
     * The nonce counter reached its maximum value ([Long.MAX_VALUE])
     * and no more messages can be encrypted or decrypted with this [CipherState].
     */
    class NonceExhausted : NoiseException("Nonce exhausted")

    /**
     * The [CipherState] was permanently invalidated (typically after a
     * [DecryptionFailed] error) and can no longer be used.
     */
    class SessionInvalidated : NoiseException("Session invalidated")
}

/**
 * Parses Noise Protocol name strings into [HandshakeDescriptor] instances.
 *
 * Supports all standard interactive patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX,
 * IN, IK, IX), one-way patterns (N, K, X), and deferred variants (NK1, X1K, etc.).
 * Also handles the `fallback` modifier and both legacy `NoisePSK_` and modern
 * `pskN` pre-shared key conventions.
 *
 * Parsed descriptors are cached internally for performance.
 *
 * Example protocol name: `"Noise_XX_25519_ChaChaPoly_SHA256"`
 *
 * @see HandshakeDescriptor
 * @see NoiseSession
 */
object PatternParser {
    private val parseCache = java.util.concurrent.ConcurrentHashMap<String, HandshakeDescriptor>()

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

    /**
     * Parses a full Noise Protocol name into a [HandshakeDescriptor].
     *
     * The protocol name must follow the format:
     * `Noise_<pattern>[modifiers]_<DH>_<cipher>_<hash>`
     * or the legacy PSK format:
     * `NoisePSK_<pattern>_<DH>_<cipher>_<hash>`
     *
     * Results are cached so repeated calls with the same name are cheap.
     * Each call returns a defensive copy of the cached descriptor.
     *
     * @param protocolName The full protocol name string (e.g. `"Noise_XX_25519_ChaChaPoly_SHA256"`).
     * @return The parsed [HandshakeDescriptor].
     * @throws NoiseException.InvalidPattern If the protocol name is malformed or references
     *   unsupported algorithms.
     */
    fun parse(protocolName: String): HandshakeDescriptor {
        parseCache[protocolName]?.let { return it.copy() }

        val result = parseImpl(protocolName)
        parseCache[protocolName] = result
        return result.copy()
    }

    private fun parseImpl(protocolName: String): HandshakeDescriptor {
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
