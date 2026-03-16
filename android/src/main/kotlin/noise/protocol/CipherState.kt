package noise.protocol

class CipherState(private val cipher: CipherFunction, key: ByteArray? = null) {
    private var k: ByteArray? = key?.copyOf()
    private var n: Long = 0

    fun hasKey(): Boolean = k != null

    fun setKey(key: ByteArray) {
        k = key.copyOf()
        n = 0
    }

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val key = k ?: return plaintext
        val ciphertext = cipher.encrypt(key, n, ad, plaintext)
        n++
        return ciphertext
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = k ?: return ciphertext
        val plaintext = cipher.decrypt(key, n, ad, ciphertext)
        n++
        return plaintext
    }
}
