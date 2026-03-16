package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for AESGCM and SHA512 crypto providers across all 4 cipher/hash combinations.
 */
class CryptoProvidersTest {

    @Test
    fun `NN handshake with AESGCM+SHA256`() {
        val initiator = NoiseSession("Noise_NN_25519_AESGCM_SHA256", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_AESGCM_SHA256", Role.RESPONDER)

        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "AESGCM works".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun `NN handshake with ChaChaPoly+SHA512`() {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA512", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_SHA512", Role.RESPONDER)

        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "SHA512 works".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    // Shared test vector keys
    private val initEph = KeyPair(
        privateKey = hexToBytes("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        publicKey = hexToBytes("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
    )
    private val respEph = KeyPair(
        privateKey = hexToBytes("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        publicKey = hexToBytes("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
    )
    private val prologue = hexToBytes("4a6f686e2047616c74")

    @Test
    fun `NN AESGCM+SHA256 matches test vector`() {
        val initiator = NoiseSession(
            "Noise_NN_25519_AESGCM_SHA256", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_NN_25519_AESGCM_SHA256", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph
        )

        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843934ff73eebb9d930ebf62b8e4db8133ca936872b5551efd7c9989c646d8cf0",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()

        val t1 = initT.sender.encryptWithAd(byteArrayOf(), hexToBytes("462e20412e20486179656b"))
        assertEquals("8d372b94914e80018211a344b8b1c5a2869492a0db46990c0362f3", bytesToHex(t1))

        val t2 = respT.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("e183b0abd55550f9955fb05476d988c6f27628d7bbde111c39ccbc", bytesToHex(t2))
    }

    @Test
    fun `NN ChaChaPoly+SHA512 matches test vector`() {
        val initiator = NoiseSession(
            "Noise_NN_25519_ChaChaPoly_SHA512", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_NN_25519_ChaChaPoly_SHA512", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph
        )

        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a4b5da00b0bf707701c15f5f54d13dfaa53404c812aaac98d55e2a9463bb94",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()

        val t1 = initT.sender.encryptWithAd(byteArrayOf(), hexToBytes("462e20412e20486179656b"))
        assertEquals("7cc120945f3d00ce194bc60172accedcc168607551c226ef02e602", bytesToHex(t1))

        val t2 = respT.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("09adc97d36e5b47f3b81bebd1920595e9480f450af4e71df38babf", bytesToHex(t2))
    }

    @Test
    fun `NN AESGCM+SHA512 matches test vector`() {
        val initiator = NoiseSession(
            "Noise_NN_25519_AESGCM_SHA512", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_NN_25519_AESGCM_SHA512", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph
        )

        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843f01eddcfafa2580bf4b9670208b19eea75586d8b0352dd82aae394a668e50f",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()

        val t1 = initT.sender.encryptWithAd(byteArrayOf(), hexToBytes("462e20412e20486179656b"))
        assertEquals("a267e88b70a00fbc099d3bd4438073cea04835321f89f028f421bd", bytesToHex(t1))

        val t2 = respT.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("d0dce53724a6e38d5c0ee4bcb19bdc896c8e62d7a26fe71f7c3424", bytesToHex(t2))
    }

    @Test
    fun `AESGCM+SHA512 combo works end-to-end`() {
        val initiator = NoiseSession("Noise_NN_25519_AESGCM_SHA512", Role.INITIATOR)
        val responder = NoiseSession("Noise_NN_25519_AESGCM_SHA512", Role.RESPONDER)

        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        val initT = initiator.split()
        val respT = responder.split()

        val plaintext = "AESGCM+SHA512".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
