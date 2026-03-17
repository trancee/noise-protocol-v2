package noise.protocol

/** Which key slot to reference in a DH operation. */
enum class KeyRef { S, E, RS, RE }

/** A DH operation descriptor: local key pair + remote public key. */
data class DhOp(val local: KeyRef, val remote: KeyRef)

/**
 * Complete DH dispatch table — maps (token, role) to key references.
 *
 * Replaces the role-conditional `when`/`if` branches in processDHToken
 * with a pure data lookup. Exhaustive and independently testable.
 */
val DH_DISPATCH: Map<Pair<String, Role>, DhOp> = mapOf(
    ("ee" to Role.INITIATOR) to DhOp(KeyRef.E, KeyRef.RE),
    ("ee" to Role.RESPONDER) to DhOp(KeyRef.E, KeyRef.RE),
    ("es" to Role.INITIATOR) to DhOp(KeyRef.E, KeyRef.RS),
    ("es" to Role.RESPONDER) to DhOp(KeyRef.S, KeyRef.RE),
    ("se" to Role.INITIATOR) to DhOp(KeyRef.S, KeyRef.RE),
    ("se" to Role.RESPONDER) to DhOp(KeyRef.E, KeyRef.RS),
    ("ss" to Role.INITIATOR) to DhOp(KeyRef.S, KeyRef.RS),
    ("ss" to Role.RESPONDER) to DhOp(KeyRef.S, KeyRef.RS),
)
