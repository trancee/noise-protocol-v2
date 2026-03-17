package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class PskTest {

    private fun hex(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `NoisePSK XX ChaChaPoly SHA256 matches cacophony test vector`() {
        val prologue = hex("4a6f686e2047616c74")
        val psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")

        val initStatic = KeyPair(
            privateKey = hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
            publicKey = Curve25519DH.generatePublicKey(hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"))
        )
        val respStatic = KeyPair(
            privateKey = hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
            publicKey = Curve25519DH.generatePublicKey(hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"))
        )
        val initEphemeral = KeyPair(
            privateKey = hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey = hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        val respEphemeral = KeyPair(
            privateKey = hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey = hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )

        val initiator = NoiseSession(
            "NoisePSK_XX_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            staticKeyPair = initStatic,
            prologue = prologue,
            localEphemeral = initEphemeral,
            psks = listOf(psk)
        )
        val responder = NoiseSession(
            "NoisePSK_XX_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            staticKeyPair = respStatic,
            prologue = prologue,
            localEphemeral = respEphemeral,
            psks = listOf(psk)
        )

        // Message 0: → e
        val msg0 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79449f8ddea3e713f8813c3ba5765fa26b90688fa9055bffed80f696dd59a7173551",
            toHex(msg0))
        responder.readMessage(msg0)

        // Message 1: ← e, ee, s, es
        val msg1 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088433863d49e43f6eb913421be46743e68ec5a939305ea758606b59811eb2c3ba441cf28102e3516dc7ad18f43fac2889463a01bb28f155272d020edfa3bd149a6ab9dcc60a5c6c9cdf3f9b5085211ed58",
            toHex(msg1))
        initiator.readMessage(msg1)

        // Message 2: → s, se
        val msg2 = initiator.writeMessage(hex("462e20412e20486179656b"))
        assertEquals(
            "aa98156e541a2308e05b1610fa23be4c22b7cfbd617ba68542a6afc7b224c6681feae2eb47cb028ada168466ea4d424404359106638a1c5060a8a4750b2a1b0bee93c00a2d437ed6a850a7",
            toHex(msg2))
        responder.readMessage(msg2)

        // Transport
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val t1 = respTransport.sender.encryptWithAd(byteArrayOf(), hex("4361726c204d656e676572"))
        assertEquals("4fda7e55ea65eb577840f187102e80035f5b1fbb0a621204f23e26", toHex(t1))
    }

    @Test
    fun `NoisePSK without PSK throws InvalidKey`() {
        assertThrows<NoiseException.InvalidKey> {
            val session = NoiseSession(
                "NoisePSK_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR,
                psks = emptyList()
            )
            session.writeMessage()
        }
    }

    @Test
    fun `NoisePSK NN ChaChaPoly SHA256 matches cacophony test vector`() {
        val prologue = hex("4a6f686e2047616c74")
        val psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")

        val initEphemeral = KeyPair(
            privateKey = hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey = hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        val respEphemeral = KeyPair(
            privateKey = hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey = hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )

        val initiator = NoiseSession(
            "NoisePSK_NN_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            prologue = prologue,
            localEphemeral = initEphemeral,
            psks = listOf(psk)
        )
        val responder = NoiseSession(
            "NoisePSK_NN_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            prologue = prologue,
            localEphemeral = respEphemeral,
            psks = listOf(psk)
        )

        // Message 0: → e (with PSK mixed before, and MixKey(e) after)
        val msg0 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794420495e1c45aa6d48bec75e6c0194a30b8482f680a58d92fbc94d16ccd31473b0",
            toHex(msg0))
        responder.readMessage(msg0)

        // Message 1: ← e, ee
        val msg1 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a6c0a0af9e78614cb0ef972d4bddcd2160ef8f5bb482437adccb926e6577b1",
            toHex(msg1))
        initiator.readMessage(msg1)

        // Transport
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val t1 = initTransport.sender.encryptWithAd(byteArrayOf(), hex("462e20412e20486179656b"))
        assertEquals("9759720a3d79f72c9f8dfbf0212aa18f33e2ce417cfc4cd336a6c3", toHex(t1))

        val t2 = respTransport.sender.encryptWithAd(byteArrayOf(), hex("4361726c204d656e676572"))
        assertEquals("2dacca87bae103cefaedcafe626484a98e325fc38060ec1ec9ffbd", toHex(t2))
    }

    @Test
    fun `Noise NNpsk0 modern format matches Python reference`() {
        // Test vector generated by Python noiseprotocol library using Noise_NNpsk0 format
        val prologue = hex("4a6f686e2047616c74")
        val psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")

        val initEphemeral = KeyPair(
            privateKey = hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey = hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        val respEphemeral = KeyPair(
            privateKey = hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey = hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )

        val initiator = NoiseSession(
            "Noise_NNpsk0_25519_ChaChaPoly_SHA256", Role.INITIATOR,
            prologue = prologue,
            localEphemeral = initEphemeral,
            psks = listOf(psk)
        )
        val responder = NoiseSession(
            "Noise_NNpsk0_25519_ChaChaPoly_SHA256", Role.RESPONDER,
            prologue = prologue,
            localEphemeral = respEphemeral,
            psks = listOf(psk)
        )

        // Message 0: → psk, e (modern: MixKeyAndHash(psk) then e)
        val msg0 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54",
            toHex(msg0))
        responder.readMessage(msg0)

        // Message 1: ← e, ee
        val msg1 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d6062704d5a9c422a8e834423f8c1feada7e8d0d910a1a2cd030fb584221e3",
            toHex(msg1))
        initiator.readMessage(msg1)

        // Transport
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val t1 = initTransport.sender.encryptWithAd(byteArrayOf(), hex("462e20412e20486179656b"))
        assertEquals("e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f", toHex(t1))

        val t2 = respTransport.sender.encryptWithAd(byteArrayOf(), hex("4361726c204d656e676572"))
        assertEquals("64c6bee32ea91c8474bb4c21d7a700109ad45af77b29764ba5eb1e", toHex(t2))
    }
}
