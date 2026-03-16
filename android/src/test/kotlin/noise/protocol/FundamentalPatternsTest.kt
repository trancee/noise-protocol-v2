package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for all fundamental interactive handshake patterns (excluding NN and XX which have their own test files).
 * Uses test vectors from test-vectors/noise_25519_ChaChaPoly_SHA256.json where available,
 * plus random-key end-to-end tests for patterns without vectors.
 */
class FundamentalPatternsTest {

    // Shared test vector keys
    private val initStatic = KeyPair(
        privateKey = hexToBytes("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
        publicKey = hexToBytes("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a")
    )
    private val respStatic = KeyPair(
        privateKey = hexToBytes("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
        publicKey = hexToBytes("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62")
    )
    private val initEph = KeyPair(
        privateKey = hexToBytes("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        publicKey = hexToBytes("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
    )
    private val respEph = KeyPair(
        privateKey = hexToBytes("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        publicKey = hexToBytes("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
    )
    private val prologue = hexToBytes("4a6f686e2047616c74")

    // --- NK: pre-message ← s ---

    @Test
    fun `NK handshake matches test vector`() {
        // NK: initiator knows responder's static key
        val initiator = NoiseSession(
            "Noise_NK_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            remoteStaticKey = respStatic.publicKey, prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_NK_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic, prologue = prologue, localEphemeral = respEph
        )

        // Message 1: → e, es
        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448134d00711fdb390a0d178fa008f6d47d2891e5ea18ae136c3b4c23ac384efb0",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        // Message 2: ← e, ee
        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438ea16e3701bc0d77744f117bee22451c9afa7f4cdbbcff00c04a8ee0913c88",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport: NK has 2 messages, last from responder → first transport from initiator
        val initT = initiator.split()
        val respT = responder.split()

        val tMsg1 = initT.sender.encryptWithAd(byteArrayOf(), hexToBytes("462e20412e20486179656b"))
        assertEquals("a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0", bytesToHex(tMsg1))

        val tMsg2 = respT.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff", bytesToHex(tMsg2))
    }

    // --- KK: pre-messages → s, ← s ---

    @Test
    fun `KK handshake matches test vector`() {
        // KK: both sides know each other's static keys
        val initiator = NoiseSession(
            "Noise_KK_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic, remoteStaticKey = respStatic.publicKey,
            prologue = prologue, localEphemeral = initEph
        )
        val responder = NoiseSession(
            "Noise_KK_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic, remoteStaticKey = initStatic.publicKey,
            prologue = prologue, localEphemeral = respEph
        )

        // Message 1: → e, es, ss
        val msg1 = initiator.writeMessage(hexToBytes("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440177015efc1fe7a37c629af7120a96274e6ab7afcc9261901d0e09ae32a5bb96",
            bytesToHex(msg1)
        )
        responder.readMessage(msg1)

        // Message 2: ← e, ee, se
        val msg2 = responder.writeMessage(hexToBytes("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843b274d3429adc47ca093ba63ef90f8da89fda108db471dccfa4894aa7b00003",
            bytesToHex(msg2)
        )
        initiator.readMessage(msg2)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)

        // Transport: KK has 2 messages, last from responder → first transport from initiator
        val initT = initiator.split()
        val respT = responder.split()

        val tMsg1 = initT.sender.encryptWithAd(byteArrayOf(), hexToBytes("462e20412e20486179656b"))
        assertEquals("966b05bc69ec01b8454d3160a214e6f24a3d884eb31ec2408af63f", bytesToHex(tMsg1))

        val tMsg2 = respT.sender.encryptWithAd(byteArrayOf(), hexToBytes("4361726c204d656e676572"))
        assertEquals("0ad887fba4f611bbb4afe44ba3556b8164332ca7d5934634d63d80", bytesToHex(tMsg2))
    }

    // --- NX: no pre-messages, responder transmits static ---

    @Test
    fun `NX handshake completes end-to-end`() {
        val respStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession("Noise_NX_25519_ChaChaPoly_SHA256", Role.INITIATOR)
        val responder = NoiseSession("Noise_NX_25519_ChaChaPoly_SHA256", Role.RESPONDER, staticKeyPair = respStatic)

        // NX: → e | ← e, ee, s, es
        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
        verifyTransport(initiator, responder)
    }

    // --- KN: pre-message → s ---

    @Test
    fun `KN handshake completes end-to-end`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_KN_25519_ChaChaPoly_SHA256", Role.INITIATOR, staticKeyPair = initStatic
        )
        val responder = NoiseSession(
            "Noise_KN_25519_ChaChaPoly_SHA256", Role.RESPONDER, remoteStaticKey = initStatic.publicKey
        )

        // KN: → e | ← e, ee, se
        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
        verifyTransport(initiator, responder)
    }

    // --- KX: pre-message → s ---

    @Test
    fun `KX handshake completes end-to-end`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val respStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_KX_25519_ChaChaPoly_SHA256", Role.INITIATOR, staticKeyPair = initStatic
        )
        val responder = NoiseSession(
            "Noise_KX_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic, remoteStaticKey = initStatic.publicKey
        )

        // KX: → e | ← e, ee, se, s, es
        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
        verifyTransport(initiator, responder)
    }

    // --- XN: no pre-messages, initiator transmits static late ---

    @Test
    fun `XN handshake completes end-to-end`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_XN_25519_ChaChaPoly_SHA256", Role.INITIATOR, staticKeyPair = initStatic
        )
        val responder = NoiseSession("Noise_XN_25519_ChaChaPoly_SHA256", Role.RESPONDER)

        // XN: → e | ← e, ee | → s, se
        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())
        responder.readMessage(initiator.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
        verifyTransport(initiator, responder)
    }

    // --- XK: pre-message ← s, initiator transmits static late ---

    @Test
    fun `XK handshake completes end-to-end`() {
        val initStatic = Curve25519DH.generateKeyPair()
        val respStatic = Curve25519DH.generateKeyPair()
        val initiator = NoiseSession(
            "Noise_XK_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic, remoteStaticKey = respStatic.publicKey
        )
        val responder = NoiseSession(
            "Noise_XK_25519_ChaChaPoly_SHA256", Role.RESPONDER, staticKeyPair = respStatic
        )

        // XK: → e, es | ← e, ee | → s, se
        responder.readMessage(initiator.writeMessage())
        initiator.readMessage(responder.writeMessage())
        responder.readMessage(initiator.writeMessage())

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
        verifyTransport(initiator, responder)
    }

    // --- Error handling: missing required keys ---

    @Test
    fun `KK without initiator static throws InvalidKey`() {
        org.junit.jupiter.api.assertThrows<NoiseException.InvalidKey> {
            val initiator = NoiseSession(
                "Noise_KK_25519_ChaChaPoly_SHA256", Role.INITIATOR,
                remoteStaticKey = respStatic.publicKey
            )
        }
    }

    @Test
    fun `NK without responder remote static throws InvalidKey`() {
        org.junit.jupiter.api.assertThrows<NoiseException.InvalidKey> {
            val initiator = NoiseSession(
                "Noise_NK_25519_ChaChaPoly_SHA256", Role.INITIATOR
            )
        }
    }

    // --- Helper ---

    private fun verifyTransport(initiator: NoiseSession, responder: NoiseSession) {
        val initT = initiator.split()
        val respT = responder.split()
        val plaintext = "Hello from initiator".toByteArray()
        val ciphertext = initT.sender.encryptWithAd(byteArrayOf(), plaintext)
        val decrypted = respT.receiver.decryptWithAd(byteArrayOf(), ciphertext)
        assertContentEquals(plaintext, decrypted)

        val reply = "Hello from responder".toByteArray()
        val replyCipher = respT.sender.encryptWithAd(byteArrayOf(), reply)
        val replyDecrypted = initT.receiver.decryptWithAd(byteArrayOf(), replyCipher)
        assertContentEquals(reply, replyDecrypted)
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
