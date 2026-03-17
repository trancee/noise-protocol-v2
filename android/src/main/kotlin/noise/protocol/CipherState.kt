package noise.protocol

/**
 * Manages the encryption/decryption state for a single direction of a Noise
 * Protocol transport channel (Section 5.1 of the Noise spec).
 *
 * Maintains an AEAD key and a monotonically-increasing nonce counter. Once the
 * nonce reaches [Long.MAX_VALUE] the cipher state automatically rekeys. If a
 * decryption failure occurs, the state is permanently invalidated to prevent
 * further use of a compromised session.
 *
 * This class is thread-safe; all mutable operations are `@Synchronized`.
 *
 * @param cipher The AEAD cipher function to use (e.g. [ChaChaPoly], [AESGCM]).
 * @param key Optional initial key. If `null`, encryption/decryption is a no-op
 *   (pass-through) until [setKey] is called.
 * @see SymmetricState
 * @see TransportSession
 */
open class CipherState(private val cipher: CipherFunction, key: ByteArray? = null) {
    private var k: ByteArray? = key?.copyOf()
    private var n: Long = 0
    @Volatile private var invalidated: Boolean = false

    /**
     * Returns `true` if this cipher state has a key set and will perform actual
     * AEAD encryption/decryption. Returns `false` if operating in pass-through mode.
     */
    fun hasKey(): Boolean = k != null

    /**
     * Sets the AEAD key and resets the nonce counter to zero.
     *
     * A defensive copy of [key] is stored internally.
     *
     * @param key The 256-bit (32-byte) AEAD key.
     */
    @Synchronized
    fun setKey(key: ByteArray) {
        k = key.copyOf()
        n = 0
    }

    /**
     * Encrypts [plaintext] with associated data [ad], then increments the nonce.
     *
     * If no key is set, returns [plaintext] unchanged (pass-through mode).
     *
     * @param ad Associated data to authenticate but not encrypt.
     * @param plaintext The data to encrypt.
     * @return The ciphertext with an appended 16-byte authentication tag,
     *   or [plaintext] unchanged if no key is set.
     * @throws NoiseException.SessionInvalidated If this state was invalidated by a prior decryption failure.
     * @throws NoiseException.NonceExhausted If the nonce has reached its maximum value.
     */
    @Synchronized
    open fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        if (invalidated) throw NoiseException.SessionInvalidated()
        val key = k ?: return plaintext
        if (n == Long.MAX_VALUE) throw NoiseException.NonceExhausted()
        val ciphertext = cipher.encrypt(key, n, ad, plaintext)
        n++
        if (n == Long.MAX_VALUE) rekey()
        return ciphertext
    }

    /**
     * Decrypts [ciphertext] with associated data [ad], then increments the nonce.
     *
     * If no key is set, returns [ciphertext] unchanged (pass-through mode).
     * On decryption failure the state is permanently invalidated and a
     * [NoiseException.DecryptionFailed] is thrown.
     *
     * @param ad Associated data that was authenticated during encryption.
     * @param ciphertext The data to decrypt (including the 16-byte authentication tag).
     * @return The decrypted plaintext, or [ciphertext] unchanged if no key is set.
     * @throws NoiseException.SessionInvalidated If this state was previously invalidated.
     * @throws NoiseException.NonceExhausted If the nonce has reached its maximum value.
     * @throws NoiseException.DecryptionFailed If AEAD authentication fails
     *   (the state is invalidated as a side-effect).
     */
    @Synchronized
    open fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        if (invalidated) throw NoiseException.SessionInvalidated()
        val key = k ?: return ciphertext
        if (n == Long.MAX_VALUE) throw NoiseException.NonceExhausted()
        try {
            val plaintext = cipher.decrypt(key, n, ad, ciphertext)
            n++
            if (n == Long.MAX_VALUE) rekey()
            return plaintext
        } catch (_: Exception) {
            invalidated = true
            throw NoiseException.DecryptionFailed()
        }
    }

    private fun rekey() {
        val maxNonce = Long.MAX_VALUE
        k = cipher.encrypt(k!!, maxNonce, byteArrayOf(), ByteArray(32))
            .let { if (it.size > 32) it.copyOf(32) else it }
        n = 0
    }

    /**
     * Sets the nonce to an explicit value. **For testing only.**
     *
     * @param nonce The nonce value to set.
     */
    @Synchronized
    fun setNonceForTesting(nonce: Long) {
        n = nonce
    }
}
