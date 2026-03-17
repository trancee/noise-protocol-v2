package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertTrue

class DeferredPatternsTest {

    private fun verifyTransport(initiator: NoiseSession, responder: NoiseSession) {
        val initT = initiator.split()
        val respT = responder.split()
        val plaintext = "deferred pattern transport test".toByteArray()
        val ct = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val pt = respT.receiver.decryptWithAd(byteArrayOf(), ct)
        assertTrue(plaintext.contentEquals(pt))
    }

    private fun completeHandshake(initiator: NoiseSession, responder: NoiseSession) {
        var isTurn = true // initiator goes first
        while (!initiator.isHandshakeComplete && !responder.isHandshakeComplete) {
            if (isTurn) {
                responder.readMessage(initiator.writeMessage())
            } else {
                initiator.readMessage(responder.writeMessage())
            }
            isTurn = !isTurn
        }
    }

    // Helper to determine what keys each side needs based on pattern name
    private fun createSessions(patternName: String): Pair<NoiseSession, NoiseSession> {
        val proto = "Noise_${patternName}_25519_ChaChaPoly_SHA256"
        val desc = PatternParser.parse(proto)

        val initStatic = if (desc.initiatorPreMessages.contains("s") ||
            desc.messagePatterns.any { tokens -> tokens.contains("s") && desc.messagePatterns.indexOf(tokens) % 2 == 0 }
        ) Curve25519DH.generateKeyPair() else null

        val respStatic = if (desc.responderPreMessages.contains("s") ||
            desc.messagePatterns.any { tokens -> tokens.contains("s") && desc.messagePatterns.indexOf(tokens) % 2 == 1 }
        ) Curve25519DH.generateKeyPair() else null

        val initiator = NoiseSession(
            proto, Role.INITIATOR,
            staticKeyPair = initStatic,
            remoteStaticKey = if (desc.responderPreMessages.contains("s")) respStatic?.publicKey else null
        )
        val responder = NoiseSession(
            proto, Role.RESPONDER,
            staticKeyPair = respStatic,
            remoteStaticKey = if (desc.initiatorPreMessages.contains("s")) initStatic?.publicKey else null
        )
        return initiator to responder
    }

    @Test
    fun `NK1 handshake completes end-to-end`() {
        val (i, r) = createSessions("NK1")
        completeHandshake(i, r)
        verifyTransport(i, r)
    }

    @Test
    fun `all 23 deferred patterns complete end-to-end`() {
        val patterns = listOf(
            "NK1", "NX1",
            "X1N", "X1K", "XK1", "X1K1", "X1X", "XX1", "X1X1",
            "K1N", "K1K", "KK1", "K1K1", "K1X", "KX1", "K1X1",
            "I1N", "I1K", "IK1", "I1K1", "I1X", "IX1", "I1X1"
        )

        for (pattern in patterns) {
            val (initiator, responder) = createSessions(pattern)
            completeHandshake(initiator, responder)
            assertTrue(initiator.isHandshakeComplete, "$pattern initiator should complete")
            assertTrue(responder.isHandshakeComplete, "$pattern responder should complete")
            verifyTransport(initiator, responder)
        }
    }
}
