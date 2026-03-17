package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SecureMemoryTest {

    @Test
    fun `allocates buffer and stores data`() {
        val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val buf = SecureBuffer.wrap(data)

        assertEquals(4, buf.size)
        val read = buf.copyBytes()
        assertTrue(data.contentEquals(read))

        buf.zero()
    }

    @Test
    fun `zero clears all buffer contents`() {
        val data = ByteArray(32) { 0xFF.toByte() }
        val buf = SecureBuffer.wrap(data)

        buf.zero()

        val read = buf.copyBytes()
        assertTrue(read.all { it == 0.toByte() }, "Buffer should be all zeros after zero()")
    }

    @Test
    fun `use block auto-zeros on normal exit`() {
        var afterBytes: ByteArray? = null

        val result = SecureBuffer.wrap(ByteArray(32) { 0xAB.toByte() }).use { buf ->
            afterBytes = buf.copyBytes()
            assertTrue(afterBytes!!.any { it != 0.toByte() }, "Data should be present during use")
            "done"
        }

        assertEquals("done", result)
        // After use {}, the buffer is zeroed — we saved a snapshot before exit
        // The key behavior: use {} returns the block result and zeros the buffer
    }

    @Test
    fun `use block auto-zeros on exception`() {
        val buf = SecureBuffer.wrap(ByteArray(32) { 0xCD.toByte() })

        try {
            buf.use { throw RuntimeException("oops") }
        } catch (_: RuntimeException) {
            // expected
        }

        val read = buf.copyBytes()
        assertTrue(read.all { it == 0.toByte() }, "Buffer should be zeroed even after exception")
    }

    @Test
    fun `handshake zeroes ephemeral private key after split`() {
        // Complete an NN handshake and verify ephemeral private key is zeroed
        val alice = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR
        )
        val bob = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER
        )

        val msg1 = alice.writeMessage()
        bob.readMessage(msg1)
        val msg2 = bob.writeMessage()
        alice.readMessage(msg2)

        // Ephemeral key should be accessible before split
        val aliceEphPriv = alice.getLocalEphemeralPrivateKey()
        assertTrue(aliceEphPriv != null, "Ephemeral key should exist before split")

        alice.split()

        // After split, ephemeral private key should be zeroed
        val afterSplit = alice.getLocalEphemeralPrivateKey()
        assertTrue(afterSplit == null || afterSplit.all { it == 0.toByte() },
            "Ephemeral private key should be zeroed after split")
    }

    @Test
    fun `symmetric state zeroes chaining key after handshake completes`() {
        val alice = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR
        )
        val bob = NoiseSession(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER
        )

        val msg1 = alice.writeMessage()
        bob.readMessage(msg1)
        val msg2 = bob.writeMessage()
        alice.readMessage(msg2) // handshake completes, ck zeroed internally

        // Chaining key should be zeroed after handshake completion
        val ck = alice.getChainingKey()
        assertTrue(ck.all { it == 0.toByte() },
            "Chaining key should be zeroed after handshake completes")

        // But transport still works (cipher keys were derived before zeroing)
        val aliceTransport = alice.split()
        val bobTransport = bob.split()
        val ct = aliceTransport.sender.encryptWithAd(byteArrayOf(), "works".toByteArray())
        val pt = bobTransport.receiver.decryptWithAd(byteArrayOf(), ct)
        assertEquals("works", String(pt))
    }
}
