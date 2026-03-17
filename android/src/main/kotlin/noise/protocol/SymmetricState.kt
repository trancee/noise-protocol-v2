package noise.protocol

class SymmetricState(
    protocolName: String,
    private val cipher: CipherFunction,
    private val hash: HashFunction
) {
    private var ck: ByteArray
    private var h: ByteArray
    private val cipherState = CipherState(cipher)

    init {
        val protocolBytes = protocolName.toByteArray(Charsets.US_ASCII)
        h = if (protocolBytes.size <= hash.hashLen) {
            protocolBytes + ByteArray(hash.hashLen - protocolBytes.size)
        } else {
            hash.hash(protocolBytes)
        }
        ck = h.copyOf()
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val (newCk, tempK) = hash.hkdf(ck, inputKeyMaterial, 2)
        ck = newCk
        val truncatedK = if (tempK.size > 32) tempK.copyOf(32) else tempK
        cipherState.setKey(truncatedK)
    }

    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val outputs = hash.hkdf(ck, inputKeyMaterial, 3)
        ck = outputs[0]
        mixHash(outputs[1])
        val truncatedK = if (outputs[2].size > 32) outputs[2].copyOf(32) else outputs[2]
        cipherState.setKey(truncatedK)
    }

    // Old NoisePSK_ convention: 2-output HKDF, updates ck + MixHash, no cipher key
    fun mixPsk(psk: ByteArray) {
        val (newCk, tempH) = hash.hkdf(ck, psk, 2)
        ck = newCk
        mixHash(tempH)
    }

    fun mixHash(data: ByteArray) {
        h = hash.hash(h + data)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = cipherState.encryptWithAd(h, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = cipherState.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    fun split(): Pair<CipherState, CipherState> {
        val (tempK1, tempK2) = hash.hkdf(ck, ByteArray(0), 2)
        val c1 = CipherState(cipher)
        c1.setKey(truncateKey(tempK1))
        val c2 = CipherState(cipher)
        c2.setKey(truncateKey(tempK2))
        // Zero chaining key and HKDF intermediates
        ck.fill(0)
        tempK1.fill(0)
        tempK2.fill(0)
        return Pair(c1, c2)
    }

    fun hasKey(): Boolean = cipherState.hasKey()

    fun getHandshakeHash(): ByteArray = h.copyOf()

    fun getChainingKey(): ByteArray = ck.copyOf()

    private fun truncateKey(key: ByteArray): ByteArray =
        if (key.size > 32) key.copyOf(32) else key
}
