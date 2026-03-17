package noise.protocol

/**
 * Implements the Noise Protocol Framework SymmetricState (Section 5.2).
 *
 * Maintains the chaining key (`ck`), handshake hash (`h`), and an internal
 * [CipherState] that is used to encrypt/decrypt handshake payloads once a key
 * has been established via [mixKey]. When the handshake completes, [split]
 * derives two independent [CipherState] instances for the transport phase.
 *
 * @param protocolName The full Noise protocol name (e.g. `"Noise_XX_25519_ChaChaPoly_SHA256"`),
 *   used to initialize the handshake hash.
 * @param cipher The AEAD cipher function to use.
 * @param hash The hash function to use for key derivation and hashing.
 * @see HandshakeState
 * @see CipherState
 */
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

    /**
     * Mixes [inputKeyMaterial] into the chaining key using HKDF and sets a new
     * cipher key on the internal [CipherState], enabling encryption of subsequent
     * handshake payloads.
     *
     * @param inputKeyMaterial The DH shared secret or other key material to mix in.
     */
    fun mixKey(inputKeyMaterial: ByteArray) {
        val (newCk, tempK) = hash.hkdf(ck, inputKeyMaterial, 2)
        ck = newCk
        val truncatedK = if (tempK.size > 32) tempK.copyOf(32) else tempK
        cipherState.setKey(truncatedK)
    }

    /**
     * Performs a combined mix of [inputKeyMaterial] into the chaining key, the
     * handshake hash, and the cipher key using a 3-output HKDF. Used by modern
     * `pskN` modifier handling.
     *
     * @param inputKeyMaterial The PSK or other key material to mix in.
     */
    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val outputs = hash.hkdf(ck, inputKeyMaterial, 3)
        ck = outputs[0]
        mixHash(outputs[1])
        val truncatedK = if (outputs[2].size > 32) outputs[2].copyOf(32) else outputs[2]
        cipherState.setKey(truncatedK)
    }

    /**
     * Mixes a pre-shared key into the chaining key and handshake hash using the
     * legacy `NoisePSK_` convention (2-output HKDF, no cipher key update).
     *
     * @param psk The pre-shared key to mix in.
     */
    // Old NoisePSK_ convention: 2-output HKDF, updates ck + MixHash, no cipher key
    fun mixPsk(psk: ByteArray) {
        val (newCk, tempH) = hash.hkdf(ck, psk, 2)
        ck = newCk
        mixHash(tempH)
    }

    /**
     * Mixes [data] into the running handshake hash: `h = HASH(h || data)`.
     *
     * @param data The bytes to mix into the handshake hash.
     */
    fun mixHash(data: ByteArray) {
        // Avoid h + data allocation by using incremental hashing
        h = hash.hash(h, data)
    }

    /**
     * Encrypts [plaintext] using the current handshake hash as associated data,
     * then mixes the resulting ciphertext into the handshake hash.
     *
     * If no cipher key has been set yet (no [mixKey] call), returns [plaintext]
     * unchanged and simply mixes it into the hash.
     *
     * @param plaintext The data to encrypt.
     * @return The ciphertext (or plaintext if no key is set).
     */
    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = cipherState.encryptWithAd(h, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    /**
     * Decrypts [ciphertext] using the current handshake hash as associated data,
     * then mixes the original [ciphertext] into the handshake hash.
     *
     * @param ciphertext The data to decrypt.
     * @return The decrypted plaintext.
     * @throws NoiseException.DecryptionFailed If authentication fails.
     */
    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = cipherState.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    /**
     * Derives two independent [CipherState] instances for the transport phase
     * using a 2-output HKDF, then securely zeroes the chaining key.
     *
     * @return A pair of cipher states: the first for the initiator-to-responder
     *   direction, the second for responder-to-initiator.
     */
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

    /**
     * Returns `true` if the internal cipher state has a key set.
     *
     * @return `true` after [mixKey] has been called at least once.
     */
    fun hasKey(): Boolean = cipherState.hasKey()

    /**
     * Returns a copy of the current handshake hash value.
     *
     * After the handshake completes this value can be used as a unique
     * session identifier (channel binding).
     *
     * @return A copy of the current handshake hash.
     */
    fun getHandshakeHash(): ByteArray = h.copyOf()

    /**
     * Returns a copy of the current chaining key.
     *
     * @return A copy of the current chaining key.
     */
    fun getChainingKey(): ByteArray = ck.copyOf()

    private fun truncateKey(key: ByteArray): ByteArray =
        if (key.size > 32) key.copyOf(32) else key
}
