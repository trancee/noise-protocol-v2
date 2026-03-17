package noise.protocol

/**
 * Groups the three resolved cryptographic primitives needed by a Noise handshake.
 *
 * Produced by [CryptoResolver.resolve] and consumed by [HandshakeState].
 */
data class CryptoSuite(
    val dh: DH,
    val cipher: CipherFunction,
    val hash: HashFunction
)
