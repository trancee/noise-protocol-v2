package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NoiseSessionXXTest {

    @Test
    fun `XX handshake completes end-to-end with static keys`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val respStatic = Curve25519DH.generateKeyPair()

        val initiator = NoiseSession(
            "Noise_XX_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic
        )
        val responder = NoiseSession(
            "Noise_XX_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic
        )

        // XX: → e | ← e, ee, s, es | → s, se
        val msg1 = initiator.writeMessage()
        responder.readMessage(msg1)

        val msg2 = responder.writeMessage()
        initiator.readMessage(msg2)

        val msg3 = initiator.writeMessage()
        responder.readMessage(msg3)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport works
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val plaintext = "Hello XX".toByteArray()
        val ciphertext = initTransport.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respTransport.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `XX handshake matches test vector`() {
        val initStatic = KeyPair(
            privateKey = hexToBytes("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
            publicKey = hexToBytes("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a")
        )
        val respStatic = KeyPair(
            privateKey = hexToBytes("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
            publicKey = hexToBytes("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62")
        )
        val initEph = KeyPair(
            privateKey = hexToBytes("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey = hexToBytes("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        val respEph = KeyPair(
            privateKey = hexToBytes("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey = hexToBytes("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )
        val prologue = hexToBytes("4a6f686e2047616c74")

        val initiator = NoiseSession(
            "Noise_XX_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic, prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_XX_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic, prologue = prologue, localEphemeral = respEph
        )

        // Message 1
        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        // Message 2
        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        // Message 3
        val msg3 = initiator.writeMessage(hexToBytes("462e20412e20486179656b"))
        assertEquals(
            "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030",
            bytesToHex(msg3)
        )
        responder.readMessage(msg3)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport
        val initTransport = initiator.split()
        val respTransport = responder.split()

        // XX last handshake message is from initiator, so first transport is from responder
        val tMsg1 = respTransport.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df", bytesToHex(tMsg1))

        val tMsg2 = initTransport.sender.encryptWithAd(byteArrayOf(), hexToBytes("4a65616e2d426170746973746520536179"))
        assertEquals("3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5", bytesToHex(tMsg2))
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
