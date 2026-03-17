package noise.protocol

open class CipherState(private val cipher: CipherFunction, key: ByteArray? = null) {
    private var k: ByteArray? = key?.copyOf()
    private var n: Long = 0
    @Volatile private var invalidated: Boolean = false

    fun hasKey(): Boolean = k != null

    @Synchronized
    fun setKey(key: ByteArray) {
        k = key.copyOf()
        n = 0
    }

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

    @Synchronized
    fun setNonceForTesting(nonce: Long) {
        n = nonce
    }
}
