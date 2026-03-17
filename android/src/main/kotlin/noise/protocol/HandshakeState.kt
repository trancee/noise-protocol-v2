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
    localEphemeral: KeyPair? = null,
    remoteEphemeral: ByteArray? = null,
    psks: List<ByteArray> = emptyList()
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
    private var eSecure: SecureBuffer? = null
    private val pskList = psks.toList()
    private var pskIndex = 0
    private val isNoisePSK = descriptor.isNoisePSK
    private val isPskHandshake = isNoisePSK || descriptor.pskPositions.isNotEmpty()

    init {
        symmetricState.mixHash(prologue)

        // Old NoisePSK_ convention: mix PSK before pre-messages
        if (isNoisePSK) {
            if (pskList.isEmpty()) throw NoiseException.InvalidKey("PSK required for NoisePSK_ protocol")
            symmetricState.mixPsk(pskList[0])
        }

        // Process pre-messages: mix known public keys into handshake hash
        for (token in descriptor.initiatorPreMessages) {
            when (token) {
                "e" -> {
                    val key = if (role == Role.INITIATOR) {
                        e = localEphemeral
                        localEphemeral?.publicKey ?: throw NoiseException.InvalidKey("Initiator ephemeral key required for ${descriptor.pattern} pattern")
                    } else {
                        re = remoteEphemeral
                        remoteEphemeral ?: throw NoiseException.InvalidKey("Remote ephemeral key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
                "s" -> {
                    val key = if (role == Role.INITIATOR) {
                        s?.publicKey ?: throw NoiseException.InvalidKey("Initiator static key required for ${descriptor.pattern} pattern")
                    } else {
                        rs ?: throw NoiseException.InvalidKey("Remote static key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
            }
        }
        for (token in descriptor.responderPreMessages) {
            when (token) {
                "e" -> {
                    val key = if (role == Role.RESPONDER) {
                        e = localEphemeral
                        localEphemeral?.publicKey ?: throw NoiseException.InvalidKey("Responder ephemeral key required for ${descriptor.pattern} pattern")
                    } else {
                        re = remoteEphemeral
                        remoteEphemeral ?: throw NoiseException.InvalidKey("Remote ephemeral key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
                "s" -> {
                    val key = if (role == Role.RESPONDER) {
                        s?.publicKey ?: throw NoiseException.InvalidKey("Responder static key required for ${descriptor.pattern} pattern")
                    } else {
                        rs ?: throw NoiseException.InvalidKey("Remote static key required for ${descriptor.pattern} pattern")
                    }
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
                    eSecure = SecureBuffer.wrap(e!!.privateKey)
                    buffer += e!!.publicKey
                    symmetricState.mixHash(e!!.publicKey)
                    if (isPskHandshake) symmetricState.mixKey(e!!.publicKey)
                }
                "s" -> {
                    buffer += symmetricState.encryptAndHash(s!!.publicKey)
                }
                "psk" -> {
                    if (pskIndex >= pskList.size) throw NoiseException.InvalidKey("Missing PSK at index $pskIndex")
                    symmetricState.mixKeyAndHash(pskList[pskIndex++])
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
                    if (isPskHandshake) symmetricState.mixKey(re!!)
                }
                "s" -> {
                    val len = if (symmetricState.hasKey()) dh.dhLen + 16 else dh.dhLen
                    val temp = message.copyOfRange(offset, offset + len)
                    offset += len
                    rs = symmetricState.decryptAndHash(temp)
                }
                "psk" -> {
                    if (pskIndex >= pskList.size) throw NoiseException.InvalidKey("Missing PSK at index $pskIndex")
                    symmetricState.mixKeyAndHash(pskList[pskIndex++])
                }
                else -> processDHToken(token)
            }
        }

        val payload = symmetricState.decryptAndHash(message.copyOfRange(offset, message.size))
        advanceHandshake()
        return payload
    }

    fun getLocalEphemeralPrivateKey(): ByteArray? = e?.privateKey

    fun getChainingKey(): ByteArray = symmetricState.getChainingKey()

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
            // Zero ephemeral private key material
            eSecure?.zero()
            e?.privateKey?.fill(0)
        }
    }
}
