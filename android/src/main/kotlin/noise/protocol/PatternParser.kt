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

    /**
     * Parses a full Noise Protocol name into a [HandshakeDescriptor].
     *
     * Results are cached so repeated calls with the same name are cheap.
     *
     * @param protocolName The full protocol name string (e.g. `"Noise_XX_25519_ChaChaPoly_SHA256"`).
     * @return The parsed [HandshakeDescriptor].
     * @throws NoiseException.InvalidPattern If the protocol name is malformed or unsupported.
     */
    fun parse(protocolName: String): HandshakeDescriptor {
        parseCache[protocolName]?.let { return it.copy() }

        val result = parseImpl(protocolName)
        parseCache[protocolName] = result
        return result.copy()
    }

    private fun parseImpl(protocolName: String): HandshakeDescriptor {
        val parts = protocolName.split("_")

        val isNoisePSK = parts.size == 5 && parts[0] == "NoisePSK"
        val isNoise = parts.size == 5 && parts[0] == "Noise"

        if (!isNoise && !isNoisePSK) {
            throw NoiseException.InvalidPattern(protocolName)
        }

        val patternField = parts[1]
        val dh = parts[2]
        val cipher = parts[3]
        val hash = parts[4]

        // Extract modifiers
        val (afterFallback, isFallback) = extractFallbackModifier(patternField)
        val (patternName, pskPositions) = if (isNoisePSK) {
            afterFallback to emptyList<Int>()
        } else {
            extractPskModifiers(afterFallback)
        }

        val baseDef = PatternRegistry[patternName]
            ?: throw NoiseException.InvalidPattern("Unknown pattern: $patternName")

        // Apply modifier pipeline: fallback → PSK
        val effectiveDef = if (isFallback) Modifiers.applyFallback(baseDef) else baseDef
        val modifiedPatterns = if (isNoisePSK) {
            effectiveDef.messagePatterns
        } else {
            Modifiers.insertPskTokens(effectiveDef.messagePatterns, pskPositions)
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

    private fun extractPskModifiers(patternField: String): Pair<String, List<Int>> {
        val pskRegex = Regex("psk(\\d+)")
        val matches = pskRegex.findAll(patternField)
        val positions = matches.map { it.groupValues[1].toInt() }.toList()
        val baseName = patternField.replace(Regex("(psk\\d+\\+?)+"), "")
        return baseName to positions
    }
}
