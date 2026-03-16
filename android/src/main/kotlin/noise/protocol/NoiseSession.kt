package noise.protocol

class NoiseSession(
    private val protocolName: String,
    private val role: Role,
    staticKeyPair: KeyPair? = null,
    remoteStaticKey: ByteArray? = null,
    prologue: ByteArray = byteArrayOf(),
    localEphemeral: KeyPair? = null
) {
    private val handshakeState: HandshakeState

    val isHandshakeComplete: Boolean
        get() = handshakeState.isHandshakeComplete

    init {
        handshakeState = HandshakeState(
            protocolName = protocolName,
            role = role,
            dh = Curve25519DH,
            cipher = ChaChaPoly,
            hash = SHA256Hash,
            staticKeyPair = staticKeyPair,
            remoteStaticKey = remoteStaticKey,
            prologue = prologue,
            localEphemeral = localEphemeral
        )
    }

    fun writeMessage(payload: ByteArray = byteArrayOf()): ByteArray {
        check(!isHandshakeComplete) { "Handshake already complete, use split() for transport" }
        return handshakeState.writeMessage(payload)
    }

    fun readMessage(message: ByteArray): ByteArray {
        check(!isHandshakeComplete) { "Handshake already complete, use split() for transport" }
        return handshakeState.readMessage(message)
    }

    fun split(): TransportSession {
        val (c1, c2) = handshakeState.split()
        return if (role == Role.INITIATOR) {
            TransportSession(sender = c1, receiver = c2)
        } else {
            TransportSession(sender = c2, receiver = c1)
        }
    }
}

class TransportSession(
    val sender: CipherState,
    val receiver: CipherState
)
