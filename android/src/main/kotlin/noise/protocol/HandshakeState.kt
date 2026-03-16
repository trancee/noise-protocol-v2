package noise.protocol

class HandshakeState(
    protocolName: String,
    private val role: Role,
    private val dh: DH,
    cipher: CipherFunction,
    hash: HashFunction,
    private val descriptor: HandshakeDescriptor,
    staticKeyPair: KeyPair? = null,
    remoteStaticKey: ByteArray? = null,
    prologue: ByteArray = byteArrayOf(),
    localEphemeral: KeyPair? = null
) {
    private val symmetricState = SymmetricState(protocolName, cipher, hash)
    private var s: KeyPair? = staticKeyPair
    private var e: KeyPair? = null
    private var rs: ByteArray? = remoteStaticKey
    private var re: ByteArray? = null
    private var messageIndex = 0
    private val messagePatterns: List<List<String>> = descriptor.messagePatterns
    var isHandshakeComplete = false
        private set
    private var cipherStatePair: Pair<CipherState, CipherState>? = null
    private val fixedEphemeral: KeyPair? = localEphemeral

    init {
        symmetricState.mixHash(prologue)

        // Process pre-messages: mix known public keys into handshake hash
        for (token in descriptor.initiatorPreMessages) {
            when (token) {
                "s" -> {
                    val key = if (role == Role.INITIATOR) s!!.publicKey else rs!!
                    symmetricState.mixHash(key)
                }
            }
        }
        for (token in descriptor.responderPreMessages) {
            when (token) {
                "s" -> {
                    val key = if (role == Role.RESPONDER) s!!.publicKey else rs!!
                    symmetricState.mixHash(key)
                }
            }
        }
    }

    fun writeMessage(payload: ByteArray = byteArrayOf()): ByteArray {
        val pattern = messagePatterns[messageIndex]
        var buffer = ByteArray(0)

        for (token in pattern) {
            when (token) {
                "e" -> {
                    e = fixedEphemeral ?: dh.generateKeyPair()
                    buffer += e!!.publicKey
                    symmetricState.mixHash(e!!.publicKey)
                }
                "s" -> {
                    buffer += symmetricState.encryptAndHash(s!!.publicKey)
                }
                else -> processDHToken(token)
            }
        }

        buffer += symmetricState.encryptAndHash(payload)
        advanceHandshake()
        return buffer
    }

    fun readMessage(message: ByteArray): ByteArray {
        val pattern = messagePatterns[messageIndex]
        var offset = 0

        for (token in pattern) {
            when (token) {
                "e" -> {
                    re = message.copyOfRange(offset, offset + dh.dhLen)
                    offset += dh.dhLen
                    symmetricState.mixHash(re!!)
                }
                "s" -> {
                    val len = if (symmetricState.hasKey()) dh.dhLen + 16 else dh.dhLen
                    val temp = message.copyOfRange(offset, offset + len)
                    offset += len
                    rs = symmetricState.decryptAndHash(temp)
                }
                else -> processDHToken(token)
            }
        }

        val payload = symmetricState.decryptAndHash(message.copyOfRange(offset, message.size))
        advanceHandshake()
        return payload
    }

    fun split(): Pair<CipherState, CipherState> {
        if (!isHandshakeComplete) throw NoiseException.HandshakeIncomplete()
        return cipherStatePair!!
    }

    private fun processDHToken(token: String) {
        val sharedSecret = when (token) {
            "ee" -> dh.dh(e!!, re!!)
            "es" -> if (role == Role.INITIATOR) dh.dh(e!!, rs!!) else dh.dh(s!!, re!!)
            "se" -> if (role == Role.INITIATOR) dh.dh(s!!, re!!) else dh.dh(e!!, rs!!)
            "ss" -> dh.dh(s!!, rs!!)
            else -> throw NoiseException.InvalidPattern("Unknown token: $token")
        }
        symmetricState.mixKey(sharedSecret)
    }

    private fun advanceHandshake() {
        messageIndex++
        if (messageIndex >= messagePatterns.size) {
            isHandshakeComplete = true
            cipherStatePair = symmetricState.split()
        }
    }
}
