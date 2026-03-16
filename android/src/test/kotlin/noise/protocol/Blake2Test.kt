package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class Blake2Test {

    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    private fun hex(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `BLAKE2b-512 of abc matches RFC 7693 Appendix A`() {
        val hash = Blake2bHash
        val result = hash.hash("abc".toByteArray())
        assertEquals(64, result.size)
        assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            toHex(result)
        )
    }

    @Test
    fun `BLAKE2s-256 of abc matches RFC 7693 Appendix B`() {
        val hash = Blake2sHash
        val result = hash.hash("abc".toByteArray())
        assertEquals(32, result.size)
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            toHex(result)
        )
    }

    // Cacophony test vector keys (shared across all vectors)
    private val initEph = KeyPair(
        hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
    private val respEph = KeyPair(
        hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
    private val prologue = hex("4a6f686e2047616c74")

    @Test
    fun `NN ChaChaPoly+BLAKE2b matches cacophony test vector`() {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_BLAKE2b", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_BLAKE2b", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph)

        // msg[0]: initiator → responder (handshake, e token, no encryption yet)
        val msg1 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573", toHex(msg1))
        responder.readMessage(msg1)

        // msg[1]: responder → initiator (handshake, e+ee tokens, encrypted payload)
        val msg2 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d10cf8ef4ab895bed3e4673211f0c9337039d63a450c7b28196b8a0ebade00", toHex(msg2))
        initiator.readMessage(msg2)

        // Transport messages
        val initT = initiator.split()
        val respT = responder.split()
        val t1 = initT.sender.encryptWithAd(ByteArray(0), hex("462e20412e20486179656b"))
        assertEquals("e50ec882703a1f34bf4957d8cafd036d34e02930f672f424c676e1", toHex(t1))
        val t2 = respT.sender.encryptWithAd(ByteArray(0), hex("4361726c204d656e676572"))
        assertEquals("35bb2a728d3e8e5f47781d486089e4a37c5c2e4261256f44569a9f", toHex(t2))
    }

    @Test
    fun `NN ChaChaPoly+BLAKE2s matches cacophony test vector`() {
        val initiator = NoiseSession("Noise_NN_25519_ChaChaPoly_BLAKE2s", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph)
        val responder = NoiseSession("Noise_NN_25519_ChaChaPoly_BLAKE2s", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph)

        val msg1 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573", toHex(msg1))
        responder.readMessage(msg1)

        val msg2 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ff34a6759d06e7733c83aeb5556c15bc762b664b3ba0556b1e7eaea4168bb6", toHex(msg2))
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()
        val t1 = initT.sender.encryptWithAd(ByteArray(0), hex("462e20412e20486179656b"))
        assertEquals("79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e", toHex(t1))
        val t2 = respT.sender.encryptWithAd(ByteArray(0), hex("4361726c204d656e676572"))
        assertEquals("ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf", toHex(t2))
    }

    @Test
    fun `NN AESGCM+BLAKE2b matches cacophony test vector`() {
        val initiator = NoiseSession("Noise_NN_25519_AESGCM_BLAKE2b", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph)
        val responder = NoiseSession("Noise_NN_25519_AESGCM_BLAKE2b", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph)

        val msg1 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        responder.readMessage(msg1)
        val msg2 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088430b4b427c7ab9fac9f434513fa08726db51b1b447074227725c16a35f6b37c4", toHex(msg2))
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()
        val t1 = initT.sender.encryptWithAd(ByteArray(0), hex("462e20412e20486179656b"))
        assertEquals("9d37117df3063b2dd15b76ab8feb70d1a863ed48809447faffba69", toHex(t1))
        val t2 = respT.sender.encryptWithAd(ByteArray(0), hex("4361726c204d656e676572"))
        assertEquals("0637f52a8c2a4fc85335e3e54ff6f354c640a748db72134abc544a", toHex(t2))
    }

    @Test
    fun `NN AESGCM+BLAKE2s matches cacophony test vector`() {
        val initiator = NoiseSession("Noise_NN_25519_AESGCM_BLAKE2s", Role.INITIATOR,
            prologue = prologue, localEphemeral = initEph)
        val responder = NoiseSession("Noise_NN_25519_AESGCM_BLAKE2s", Role.RESPONDER,
            prologue = prologue, localEphemeral = respEph)

        val msg1 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        responder.readMessage(msg1)
        val msg2 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435637c95d5175db82241df5bb90db690493dacfa51454f80512c3e223de17f7", toHex(msg2))
        initiator.readMessage(msg2)

        val initT = initiator.split()
        val respT = responder.split()
        val t1 = initT.sender.encryptWithAd(ByteArray(0), hex("462e20412e20486179656b"))
        assertEquals("017e18dffa3706f97c3f08d9318fa68784302749e9389ff63a31b3", toHex(t1))
        val t2 = respT.sender.encryptWithAd(ByteArray(0), hex("4361726c204d656e676572"))
        assertEquals("ce88f443e45f17ada7021df6150b2dd590d985e2eae4ea17c47f5d", toHex(t2))
    }
}
