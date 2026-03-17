package noise.protocol

/**
 * Represents a Diffie-Hellman key pair containing raw private and public key bytes.
 *
 * Key material is stored as raw byte arrays without ASN.1 or other encoding wrappers.
 * The key sizes depend on the DH function in use (32 bytes for Curve25519, 56 bytes for X448).
 *
 * **Important:** Because this class holds sensitive private key material, callers should
 * zero out [privateKey] when it is no longer needed to reduce the window of exposure.
 *
 * Uses content-based equality rather than reference equality for [ByteArray] fields.
 *
 * @property privateKey The raw private key bytes.
 * @property publicKey The raw public key bytes.
 * @see DH
 * @see SecureBuffer
 */
data class KeyPair(val privateKey: ByteArray, val publicKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = 31 * privateKey.contentHashCode() + publicKey.contentHashCode()
}
