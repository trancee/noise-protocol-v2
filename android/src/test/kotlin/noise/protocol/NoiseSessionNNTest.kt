package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NoiseSessionNNTest {

    @Test
    fun `NN handshake completes between initiator and responder`() {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)

        // NN pattern: → e, ← e, ee
        // Message 1: initiator → responder
        val msg1 = initiator.writeMessage()
        responder.readMessage(msg1)

        // Message 2: responder → initiator
        val msg2 = responder.writeMessage()
        initiator.readMessage(msg2)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
    }

    @Test
    fun `transport encrypt by initiator can be decrypted by responder and vice versa`() {
        val (initTransport, respTransport) = completeNNHandshake()

        val message = "Hello from initiator".toByteArray()
        val ciphertext = initTransport.sender.encryptWithAd(byteArrayOf(), message)
        val decrypted = respTransport.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(message, decrypted)

        val reply = "Hello from responder".toByteArray()
        val replyCiphertext = respTransport.sender.encryptWithAd(byteArrayOf(), reply)
        val replyDecrypted = initTransport.receiver.decryptWithAd(byteArrayOf(), replyCiphertext)
        assertContentEquals(reply, replyDecrypted)
    }

    @Test
    fun `NN handshake matches cacophony test vector`() {
        // Test vector keys
        val initEphemeral = KeyPair(
            privateKey = hexToBytes("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey = hexToBytes("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        val respEphemeral = KeyPair(
            privateKey = hexToBytes("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey = hexToBytes("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )
        val prologue = hexToBytes("4a6f686e2047616c74")

        val initiator = NoiseSession(
            "Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            prologue = prologue,
            localEphemeral = initEphemeral
        )
        val responder = NoiseSession(
            "Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            prologue = prologue,
            localEphemeral = respEphemeral
        )

        // Message 1: initiator writes with payload
        val payload1 = hexToBytes("4c756477696720766f6e204d69736573")
        val msg1 = initiator.writeMessage(payload1)
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        // Message 2: responder writes with payload
        val payload2 = hexToBytes("4d757272617920526f746862617264")
        val msg2 = responder.writeMessage(payload2)
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a0ff96bdf86b579ef7dbf94e812a7470b903c20a85a87e3a1fe863264ae547",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        // Transport messages
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val tPayload1 = hexToBytes("462e20412e20486179656b")
        val tMsg1 = initTransport.sender.encryptWithAd(byteArrayOf(), tPayload1)
        assertEquals("eb1a3e3d80c1792b1bb9cb0e1382f8d8322bfb1ca7c4c8517bb686", bytesToHex(tMsg1))

        val tPayload2 = hexToBytes("4361726c204d656e676572")
        val tMsg2 = respTransport.sender.encryptWithAd(byteArrayOf(), tPayload2)
        assertEquals("c781b198d2a974eb1da2c7d518c000cf6396de87ca540963c03713", bytesToHex(tMsg2))
    }

    private fun hexToBytes(hex: String): ByteArray {
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun completeNNHandshake(): Pair<TransportSession, TransportSession> {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
        val msg1 = initiator.writeMessage()
        responder.readMessage(msg1)
        val msg2 = responder.writeMessage()
        initiator.readMessage(msg2)
        return Pair(initiator.split(), responder.split())
    }

    @Test
    fun `split throws when handshake is not complete`() {
        val session = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        assertFalse(session.isHandshakeComplete)
        assertThrows<NoiseException.HandshakeIncomplete> { session.split() }
    }

    @Test
    fun `writeMessage after split throws`() {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER)
        initiator.writeMessage().also { responder.readMessage(it) }
        responder.writeMessage().also { initiator.readMessage(it) }
        initiator.split()
        assertThrows<NoiseException.InvalidState> { initiator.writeMessage() }
    }
}
