package noise.protocol

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
