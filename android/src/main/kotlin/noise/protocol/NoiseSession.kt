package noise.protocol

class NoiseSession(
    private val protocolName: String,
    private val role: Role,
    staticKeyPair: KeyPair? = null,
    remoteStaticKey: ByteArray? = null,
    prologue: ByteArray = byteArrayOf(),
    localEphemeral: KeyPair? = null,
    remoteEphemeral: ByteArray? = null,
    psks: List<ByteArray> = emptyList()
) {
    private val handshakeState: HandshakeState
    private val isOneWay: Boolean

    val isHandshakeComplete: Boolean
        get() = handshakeState.isHandshakeComplete

    init {
        val descriptor = PatternParser.parse(protocolName)
        isOneWay = descriptor.messagePatterns.size == 1

        handshakeState = HandshakeState(
            protocolName = protocolName,
            role = role,
            dh = resolveDH(descriptor.dhFunction),
            cipher = resolveCipher(descriptor.cipherFunction),
            hash = resolveHash(descriptor.hashFunction),
            descriptor = descriptor,
            staticKeyPair = staticKeyPair,
            remoteStaticKey = remoteStaticKey,
            prologue = prologue,
            localEphemeral = localEphemeral,
            remoteEphemeral = remoteEphemeral,
            psks = psks
        )
    }

    companion object {
        fun resolveDH(name: String): DH = when (name) {
            "25519" -> Curve25519DH
            "448" -> X448DH
            else -> throw NoiseException.InvalidPattern("Unsupported DH: $name")
        }

        fun resolveCipher(name: String): CipherFunction = when (name) {
            "ChaChaPoly" -> ChaChaPoly
            "AESGCM" -> AESGCM
            else -> throw NoiseException.InvalidPattern("Unsupported cipher: $name")
        }

        fun resolveHash(name: String): HashFunction = when (name) {
            "SHA256" -> SHA256Hash
            "SHA512" -> SHA512Hash
            "BLAKE2b" -> Blake2bHash
            "BLAKE2s" -> Blake2sHash
            else -> throw NoiseException.InvalidPattern("Unsupported hash: $name")
        }
    }

    fun writeMessage(payload: ByteArray = byteArrayOf()): ByteArray {
        if (isHandshakeComplete) throw NoiseException.InvalidState("Handshake already complete, use split() for transport")
        return handshakeState.writeMessage(payload)
    }

    fun readMessage(message: ByteArray): ByteArray {
        if (isHandshakeComplete) throw NoiseException.InvalidState("Handshake already complete, use split() for transport")
        return handshakeState.readMessage(message)
    }

    fun getLocalEphemeralPrivateKey(): ByteArray? = handshakeState.getLocalEphemeralPrivateKey()

    fun split(): TransportSession {
        val (c1, c2) = handshakeState.split()
        val disabled = DisabledCipherState()
        return if (role == Role.INITIATOR) {
            TransportSession(sender = c1, receiver = if (isOneWay) disabled else c2)
        } else {
            TransportSession(sender = if (isOneWay) disabled else c2, receiver = c1)
        }
    }
}

class DisabledCipherState : CipherState(ChaChaPoly) {
    override fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        throw NoiseException.InvalidState("Cannot send on a one-way pattern receive-only channel")
    }
    override fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        throw NoiseException.InvalidState("Cannot receive on a one-way pattern send-only channel")
    }
}

class TransportSession(
    val sender: CipherState,
    val receiver: CipherState
)
