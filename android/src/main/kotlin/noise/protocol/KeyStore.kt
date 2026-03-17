package noise.protocol

/**
 * Manages handshake key state with domain-error accessors.
 *
 * Replaces nullable vars + force-unwraps (`!!`) in HandshakeState with
 * explicit [requireKeyPair] / [requirePublicKey] methods that throw
 * [NoiseException.InvalidKey] with descriptive messages.
 */
class KeyStore(
    staticKeyPair: KeyPair? = null,
    remoteStaticKey: ByteArray? = null
) {
    internal var s: KeyPair? = staticKeyPair
        private set
    internal var e: KeyPair? = null
    internal var rs: ByteArray? = remoteStaticKey
    internal var re: ByteArray? = null

    /** Returns the local key pair for [ref], or throws [NoiseException.InvalidKey]. */
    fun requireKeyPair(ref: KeyRef): KeyPair = when (ref) {
        KeyRef.S -> s ?: throw NoiseException.InvalidKey("Local static key not available")
        KeyRef.E -> e ?: throw NoiseException.InvalidKey("Local ephemeral key not yet generated")
        else -> throw NoiseException.InvalidKey("$ref is not a local key pair reference")
    }

    /** Returns the public key for [ref], or throws [NoiseException.InvalidKey]. */
    fun requirePublicKey(ref: KeyRef): ByteArray = when (ref) {
        KeyRef.S -> s?.publicKey ?: throw NoiseException.InvalidKey("Local static key not available")
        KeyRef.E -> e?.publicKey ?: throw NoiseException.InvalidKey("Local ephemeral key not yet generated")
        KeyRef.RS -> rs ?: throw NoiseException.InvalidKey("Remote static key not yet received")
        KeyRef.RE -> re ?: throw NoiseException.InvalidKey("Remote ephemeral key not yet received")
    }
}
