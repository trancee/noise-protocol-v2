package noise.protocol

/**
 * Immutable configuration for a [HandshakeState] session.
 *
 * Replaces the 11-parameter HandshakeState constructor with a single
 * self-documenting config object. All optional keys default to absent.
 *
 * @see HandshakeState
 */
data class HandshakeConfig(
    val protocolName: String,
    val role: Role,
    val dh: DH,
    val cipher: CipherFunction,
    val hash: HashFunction,
    val descriptor: HandshakeDescriptor,
    val staticKeyPair: KeyPair? = null,
    val remoteStaticKey: ByteArray? = null,
    val prologue: ByteArray = byteArrayOf(),
    val localEphemeral: KeyPair? = null,
    val remoteEphemeral: ByteArray? = null,
    val psks: List<ByteArray> = emptyList()
)
