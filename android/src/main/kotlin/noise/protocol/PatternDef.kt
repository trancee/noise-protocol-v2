package noise.protocol

/**
 * Defines a base Noise handshake pattern: pre-messages and token sequences.
 *
 * Used by [PatternRegistry] to store the 38 standard Noise patterns,
 * and by [Modifiers] to transform patterns with fallback/PSK modifiers.
 */
data class PatternDef(
    val initiatorPreMessages: List<String>,
    val responderPreMessages: List<String>,
    val messagePatterns: List<List<String>>
)
