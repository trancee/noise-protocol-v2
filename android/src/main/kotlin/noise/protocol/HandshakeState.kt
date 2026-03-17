package noise.protocol

/**
 * Implements the Noise Protocol Framework HandshakeState (Section 5.3).
 *
 * Orchestrates a multi-message handshake by processing tokens (e, s, ee, es, se, ss, psk)
 * according to the chosen handshake pattern. Each call to [writeMessage] or [readMessage]
 * processes one message pattern from the [HandshakeDescriptor]. When all messages have been
 * exchanged, [isHandshakeComplete] becomes `true` and [split] can be called to obtain
 * the transport cipher states.
 *
 * Ephemeral private key material is securely zeroed when the handshake completes.
 *
 * @param protocolName The full Noise protocol name used to initialize the [SymmetricState].
 * @param role Whether this party is the [Role.INITIATOR] or [Role.RESPONDER].
 * @param dh The Diffie-Hellman function to use.
 * @param cipher The AEAD cipher function.
 * @param hash The hash function.
 * @param descriptor The parsed handshake pattern descriptor.
 * @param staticKeyPair The local static key pair, if required by the pattern.
 * @param remoteStaticKey The remote party's static public key, if known in advance.
 * @param prologue Application-specific prologue data to mix into the handshake hash.
 * @param localEphemeral A fixed local ephemeral key pair (for testing or pre-message patterns).
 * @param remoteEphemeral The remote party's ephemeral public key (for pre-message patterns).
 * @param psks Pre-shared keys, consumed in order by `psk` tokens.
 * @throws NoiseException.InvalidKey If a required key is missing for the chosen pattern.
 * @see NoiseSession
 * @see SymmetricState
 */
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
    /** Constructs a HandshakeState from a [HandshakeConfig]. */
    constructor(config: HandshakeConfig) : this(
        protocolName = config.protocolName,
        role = config.role,
        dh = config.dh,
        cipher = config.cipher,
        hash = config.hash,
        descriptor = config.descriptor,
        staticKeyPair = config.staticKeyPair,
        remoteStaticKey = config.remoteStaticKey,
        prologue = config.prologue,
        localEphemeral = config.localEphemeral,
        remoteEphemeral = config.remoteEphemeral,
        psks = config.psks
    )
    private val symmetricState = SymmetricState(protocolName, cipher, hash)
    private val keys = KeyStore(staticKeyPair, remoteStaticKey)
    private var messageIndex = 0
    private val messagePatterns: List<List<String>> = descriptor.messagePatterns
    /** `true` once all handshake message patterns have been processed. */
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

        // Upfront PSK count validation
        val pskTokenCount = messagePatterns.flatten().count { it == "psk" }
        val requiredPskCount = pskTokenCount + (if (isNoisePSK) 1 else 0)
        if (requiredPskCount > pskList.size) {
            throw NoiseException.InvalidKey(
                "Pattern requires $requiredPskCount PSK(s) but ${pskList.size} provided"
            )
        }

        // Old NoisePSK_ convention: mix PSK before pre-messages
        if (isNoisePSK) {
            symmetricState.mixPsk(pskList[0])
        }

        // Process pre-messages: mix known public keys into handshake hash
        for (token in descriptor.initiatorPreMessages) {
            when (token) {
                "e" -> {
                    val key = if (role == Role.INITIATOR) {
                        keys.e = localEphemeral
                        localEphemeral?.publicKey ?: throw NoiseException.InvalidKey("Initiator ephemeral key required for ${descriptor.pattern} pattern")
                    } else {
                        keys.re = remoteEphemeral
                        remoteEphemeral ?: throw NoiseException.InvalidKey("Remote ephemeral key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
                "s" -> {
                    val key = if (role == Role.INITIATOR) {
                        keys.s?.publicKey ?: throw NoiseException.InvalidKey("Initiator static key required for ${descriptor.pattern} pattern")
                    } else {
                        keys.rs ?: throw NoiseException.InvalidKey("Remote static key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
            }
        }
        for (token in descriptor.responderPreMessages) {
            when (token) {
                "e" -> {
                    val key = if (role == Role.RESPONDER) {
                        keys.e = localEphemeral
                        localEphemeral?.publicKey ?: throw NoiseException.InvalidKey("Responder ephemeral key required for ${descriptor.pattern} pattern")
                    } else {
                        keys.re = remoteEphemeral
                        remoteEphemeral ?: throw NoiseException.InvalidKey("Remote ephemeral key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
                "s" -> {
                    val key = if (role == Role.RESPONDER) {
                        keys.s?.publicKey ?: throw NoiseException.InvalidKey("Responder static key required for ${descriptor.pattern} pattern")
                    } else {
                        keys.rs ?: throw NoiseException.InvalidKey("Remote static key required for ${descriptor.pattern} pattern")
                    }
                    symmetricState.mixHash(key)
                }
            }
        }
    }

    /**
     * Processes the next outgoing handshake message pattern and appends
     * an optional [payload].
     *
     * Generates an ephemeral key pair (for `e` tokens), encrypts the local static
     * public key (for `s` tokens), performs DH operations, and encrypts the payload.
     *
     * @param payload Optional application data to include in this handshake message.
     * @return The serialized handshake message bytes to send to the remote party.
     * @throws NoiseException.InvalidKey If a required PSK is missing.
     */
    fun writeMessage(payload: ByteArray = byteArrayOf()): ByteArray {
        val pattern = messagePatterns[messageIndex]
        var buffer = ByteArray(0)

        for (token in pattern) {
            when (token) {
                "e" -> {
                    keys.e = fixedEphemeral ?: dh.generateKeyPair()
                    val ePub = keys.requirePublicKey(KeyRef.E)
                    eSecure = SecureBuffer.wrap(keys.requireKeyPair(KeyRef.E).privateKey)
                    buffer += ePub
                    symmetricState.mixHash(ePub)
                    if (isPskHandshake) symmetricState.mixKey(ePub)
                }
                "s" -> {
                    buffer += symmetricState.encryptAndHash(keys.requirePublicKey(KeyRef.S))
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

    /**
     * Processes the next incoming handshake [message] and extracts the payload.
     *
     * Reads the remote ephemeral public key (for `e` tokens), decrypts the remote
     * static public key (for `s` tokens), performs DH operations, and decrypts the
     * payload.
     *
     * @param message The raw handshake message bytes received from the remote party.
     * @return The decrypted payload contained in this handshake message.
     * @throws NoiseException.InvalidKey If a required PSK is missing.
     * @throws NoiseException.DecryptionFailed If any decryption step fails.
     */
    fun readMessage(message: ByteArray): ByteArray {
        val pattern = messagePatterns[messageIndex]
        var offset = 0

        for (token in pattern) {
            when (token) {
                "e" -> {
                    keys.re = message.copyOfRange(offset, offset + dh.dhLen)
                    offset += dh.dhLen
                    symmetricState.mixHash(keys.requirePublicKey(KeyRef.RE))
                    if (isPskHandshake) symmetricState.mixKey(keys.requirePublicKey(KeyRef.RE))
                }
                "s" -> {
                    val len = if (symmetricState.hasKey()) dh.dhLen + 16 else dh.dhLen
                    val temp = message.copyOfRange(offset, offset + len)
                    offset += len
                    keys.rs = symmetricState.decryptAndHash(temp)
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

    /**
     * Returns the raw private key bytes of the local ephemeral key pair, or `null`
     * if no ephemeral key has been generated yet.
     *
     * @return The ephemeral private key bytes, or `null`.
     */
    fun getLocalEphemeralPrivateKey(): ByteArray? = keys.e?.privateKey

    /**
     * Returns a copy of the current chaining key from the underlying [SymmetricState].
     *
     * @return The current chaining key bytes.
     */
    fun getChainingKey(): ByteArray = symmetricState.getChainingKey()

    /**
     * Returns the pair of [CipherState] instances derived at handshake completion.
     *
     * The first element is the initiator-to-responder cipher state; the second is
     * the responder-to-initiator cipher state.
     *
     * @return The transport cipher state pair.
     * @throws NoiseException.HandshakeIncomplete If the handshake has not finished yet.
     */
    fun split(): Pair<CipherState, CipherState> {
        if (!isHandshakeComplete) throw NoiseException.HandshakeIncomplete()
        return cipherStatePair!!
    }

    private fun processDHToken(token: String) {
        val op = DH_DISPATCH[token to role]
            ?: throw NoiseException.InvalidPattern("Unknown DH token: $token")
        val localKP = keys.requireKeyPair(op.local)
        val remoteKey = keys.requirePublicKey(op.remote)
        symmetricState.mixKey(dh.dh(localKP, remoteKey))
    }

    private fun advanceHandshake() {
        messageIndex++
        if (messageIndex >= messagePatterns.size) {
            isHandshakeComplete = true
            cipherStatePair = symmetricState.split()
            // Zero ephemeral private key material
            eSecure?.zero()
            keys.e?.privateKey?.fill(0)
        }
    }
}
