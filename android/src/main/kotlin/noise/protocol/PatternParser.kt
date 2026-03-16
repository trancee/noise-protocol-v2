package noise.protocol

data class HandshakeDescriptor(
    val pattern: String,
    val dhFunction: String,
    val cipherFunction: String,
    val hashFunction: String,
    val initiatorPreMessages: List<String>,
    val responderPreMessages: List<String>,
    val messagePatterns: List<List<String>>
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
    )

    fun parse(protocolName: String): HandshakeDescriptor {
        val parts = protocolName.split("_")
        if (parts.size != 5 || parts[0] != "Noise") {
            throw NoiseException.InvalidPattern(protocolName)
        }

        val patternName = parts[1]
        val dh = parts[2]
        val cipher = parts[3]
        val hash = parts[4]

        if (dh !in VALID_DH) throw NoiseException.InvalidPattern("Unknown DH: $dh")
        if (cipher !in VALID_CIPHER) throw NoiseException.InvalidPattern("Unknown cipher: $cipher")
        if (hash !in VALID_HASH) throw NoiseException.InvalidPattern("Unknown hash: $hash")

        val patternDef = PATTERNS[patternName]
            ?: throw NoiseException.InvalidPattern("Unknown pattern: $patternName")

        return HandshakeDescriptor(
            pattern = patternName,
            dhFunction = dh,
            cipherFunction = cipher,
            hashFunction = hash,
            initiatorPreMessages = patternDef.initiatorPreMessages,
            responderPreMessages = patternDef.responderPreMessages,
            messagePatterns = patternDef.messagePatterns
        )
    }
}
