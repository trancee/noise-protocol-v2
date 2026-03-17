package noise.protocol

/**
 * The main public API for establishing a Noise Protocol session.
 *
 * Parses a Noise protocol name string, resolves the corresponding cryptographic
 * algorithms, and drives the handshake through [writeMessage] / [readMessage] calls.
 * Once the handshake completes, call [split] to obtain a [TransportSession] for
 * encrypted application data exchange.
 *
 * ### Example: XX handshake with Curve25519 and ChaChaPoly
 * ```kotlin
 * // Initiator side
 * val initiator = NoiseSession(
 *     protocolName = "Noise_XX_25519_ChaChaPoly_SHA256",
 *     role = Role.INITIATOR,
 *     staticKeyPair = Curve25519DH.generateKeyPair()
 * )
 *
 * // Responder side
 * val responder = NoiseSession(
 *     protocolName = "Noise_XX_25519_ChaChaPoly_SHA256",
 *     role = Role.RESPONDER,
 *     staticKeyPair = Curve25519DH.generateKeyPair()
 * )
 *
 * // Perform 3-message XX handshake
 * val msg1 = initiator.writeMessage()
 * responder.readMessage(msg1)
 * val msg2 = responder.writeMessage()
 * initiator.readMessage(msg2)
 * val msg3 = initiator.writeMessage()
 * responder.readMessage(msg3)
 *
 * // Split into transport sessions
 * val iTransport = initiator.split()
 * val rTransport = responder.split()
 *
 * // Exchange encrypted application data
 * val ciphertext = iTransport.sender.encryptWithAd(byteArrayOf(), "hello".toByteArray())
 * val plaintext = rTransport.receiver.decryptWithAd(byteArrayOf(), ciphertext)
 * ```
 *
 * @param protocolName The full Noise protocol name
 *   (e.g. `"Noise_XX_25519_ChaChaPoly_SHA256"`).
 * @param role Whether this party is the [Role.INITIATOR] or [Role.RESPONDER].
 * @param staticKeyPair The local static key pair, if required by the pattern.
 * @param remoteStaticKey The remote party's static public key, if known in advance.
 * @param prologue Application-specific prologue data to bind into the handshake hash.
 * @param localEphemeral A fixed local ephemeral key pair (primarily for testing).
 * @param remoteEphemeral The remote ephemeral public key (for pre-message patterns).
 * @param psks Pre-shared keys, consumed in order by `psk` tokens.
 * @throws NoiseException.InvalidPattern If the protocol name is malformed or unsupported.
 * @throws NoiseException.InvalidKey If a required key is missing for the chosen pattern.
 * @see TransportSession
 * @see HandshakeState
 */
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

    /** `true` once all handshake message patterns have been exchanged. */
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
        /**
         * Resolves a DH function name to its implementation.
         *
         * @param name The DH identifier (`"25519"` or `"448"`).
         * @return The corresponding [DH] implementation.
         * @throws NoiseException.InvalidPattern If [name] is not recognized.
         */
        fun resolveDH(name: String): DH = when (name) {
            "25519" -> Curve25519DH
            "448" -> X448DH
            else -> throw NoiseException.InvalidPattern("Unsupported DH: $name")
        }

        /**
         * Resolves a cipher function name to its implementation.
         *
         * @param name The cipher identifier (`"ChaChaPoly"` or `"AESGCM"`).
         * @return The corresponding [CipherFunction] implementation.
         * @throws NoiseException.InvalidPattern If [name] is not recognized.
         */
        fun resolveCipher(name: String): CipherFunction = when (name) {
            "ChaChaPoly" -> ChaChaPoly
            "AESGCM" -> AESGCM
            else -> throw NoiseException.InvalidPattern("Unsupported cipher: $name")
        }

        /**
         * Resolves a hash function name to its implementation.
         *
         * @param name The hash identifier (`"SHA256"`, `"SHA512"`, `"BLAKE2b"`, or `"BLAKE2s"`).
         * @return The corresponding [HashFunction] implementation.
         * @throws NoiseException.InvalidPattern If [name] is not recognized.
         */
        fun resolveHash(name: String): HashFunction = when (name) {
            "SHA256" -> SHA256Hash
            "SHA512" -> SHA512Hash
            "BLAKE2b" -> Blake2bHash
            "BLAKE2s" -> Blake2sHash
            else -> throw NoiseException.InvalidPattern("Unsupported hash: $name")
        }
    }

    /**
     * Writes the next outgoing handshake message with an optional [payload].
     *
     * Must be called only while [isHandshakeComplete] is `false`.
     *
     * @param payload Optional application data to include in the handshake message.
     * @return The serialized handshake message bytes.
     * @throws NoiseException.InvalidState If the handshake has already completed.
     */
    fun writeMessage(payload: ByteArray = byteArrayOf()): ByteArray {
        if (isHandshakeComplete) throw NoiseException.InvalidState("Handshake already complete, use split() for transport")
        return handshakeState.writeMessage(payload)
    }

    /**
     * Reads the next incoming handshake [message] and returns the decrypted payload.
     *
     * Must be called only while [isHandshakeComplete] is `false`.
     *
     * @param message The raw handshake message bytes received from the remote party.
     * @return The decrypted payload.
     * @throws NoiseException.InvalidState If the handshake has already completed.
     * @throws NoiseException.DecryptionFailed If any decryption step fails.
     */
    fun readMessage(message: ByteArray): ByteArray {
        if (isHandshakeComplete) throw NoiseException.InvalidState("Handshake already complete, use split() for transport")
        return handshakeState.readMessage(message)
    }

    /**
     * Returns the raw private key bytes of the local ephemeral key pair, or `null`
     * if no ephemeral key has been generated yet.
     *
     * @return The ephemeral private key bytes, or `null`.
     */
    fun getLocalEphemeralPrivateKey(): ByteArray? = handshakeState.getLocalEphemeralPrivateKey()

    /**
     * Returns a copy of the current chaining key from the underlying symmetric state.
     *
     * @return The current chaining key bytes.
     */
    fun getChainingKey(): ByteArray = handshakeState.getChainingKey()

    /**
     * Splits the completed handshake into a [TransportSession] with separate
     * sender and receiver [CipherState] instances.
     *
     * For interactive (two-way) patterns both sender and receiver are usable.
     * For one-way patterns (N, K, X), the disabled direction will throw
     * [NoiseException.InvalidState] on any encrypt/decrypt attempt.
     *
     * @return A [TransportSession] for sending and receiving encrypted application data.
     * @throws NoiseException.HandshakeIncomplete If the handshake has not finished yet.
     */
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

/**
 * A [CipherState] that always throws [NoiseException.InvalidState], used to
 * represent the disabled direction of a one-way Noise pattern.
 *
 * In one-way patterns (N, K, X) data flows in only one direction. The
 * receiver cannot send and the sender cannot receive, so the corresponding
 * cipher state is replaced with this stub.
 *
 * @see NoiseSession.split
 */
class DisabledCipherState : CipherState(ChaChaPoly) {
    /**
     * Always throws [NoiseException.InvalidState].
     *
     * @throws NoiseException.InvalidState Always.
     */
    override fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        throw NoiseException.InvalidState("Cannot send on a one-way pattern receive-only channel")
    }
    /**
     * Always throws [NoiseException.InvalidState].
     *
     * @throws NoiseException.InvalidState Always.
     */
    override fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        throw NoiseException.InvalidState("Cannot receive on a one-way pattern send-only channel")
    }
}

/**
 * Holds the sender and receiver [CipherState] pair for the transport phase
 * after a Noise handshake completes.
 *
 * Use [sender] to encrypt outgoing application data and [receiver] to decrypt
 * incoming data. For one-way patterns one of the cipher states will be a
 * [DisabledCipherState] that throws on any operation.
 *
 * @property sender The [CipherState] for encrypting outgoing messages.
 * @property receiver The [CipherState] for decrypting incoming messages.
 * @see NoiseSession.split
 */
class TransportSession(
    val sender: CipherState,
    val receiver: CipherState
)
