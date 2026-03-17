package noise.protocol

/**
 * Defines the role of a participant in a Noise Protocol handshake.
 *
 * In every Noise handshake exactly two parties are involved: one that
 * initiates the connection and one that responds. The role determines
 * message ordering and which DH operations are performed at each step.
 *
 * @see HandshakeState
 * @see NoiseSession
 */
enum class Role {
    /** The party that sends the first handshake message. */
    INITIATOR,

    /** The party that receives the first handshake message and replies. */
    RESPONDER
}
