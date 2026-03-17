package noise.protocol

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class X448Test {

    private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    private fun hex(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `X448 scalar multiplication matches RFC 7748 Section 5-2 vector 1`() {
        val scalar = hex(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121" +
            "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
        val u = hex(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9" +
            "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")
        val expected =
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f" +
            "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"

        val result = X448.scalarMult(scalar, u)
        assertEquals(expected, toHex(result))
    }

    @Test
    fun `X448 scalar multiplication matches RFC 7748 Section 5-2 vector 2`() {
        val scalar = hex(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5" +
            "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
        val u = hex(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b" +
            "165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")
        val expected =
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7" +
            "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"

        val result = X448.scalarMult(scalar, u)
        assertEquals(expected, toHex(result))
    }

    @Test
    fun `X448 DH key agreement matches RFC 7748 Section 6-2`() {
        val basePoint = ByteArray(56).also { it[0] = 5 }

        val alicePrivate = hex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d" +
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
        val alicePublic = X448.scalarMult(alicePrivate, basePoint)
        assertEquals(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c" +
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
            toHex(alicePublic))

        val bobPrivate = hex(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d" +
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
        val bobPublic = X448.scalarMult(bobPrivate, basePoint)
        assertEquals(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430" +
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
            toHex(bobPublic))

        val sharedAlice = X448.scalarMult(alicePrivate, bobPublic)
        val sharedBob = X448.scalarMult(bobPrivate, alicePublic)
        val expectedShared =
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b" +
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        assertEquals(expectedShared, toHex(sharedAlice))
        assertEquals(expectedShared, toHex(sharedBob))
    }

    @Test
    fun `X448 iterated 1000 times matches RFC 7748`() {
        var k = ByteArray(56).also { it[0] = 5 }
        var u = ByteArray(56).also { it[0] = 5 }

        // After 1 iteration
        var result = X448.scalarMult(k, u)
        u = k
        k = result
        assertEquals(
            "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a" +
            "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
            toHex(k))

        // After 1000 iterations total (999 more)
        for (i in 2..1000) {
            result = X448.scalarMult(k, u)
            u = k
            k = result
        }
        assertEquals(
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4" +
            "af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
            toHex(k))
    }

    @Test
    fun `Noise NN 448 ChaChaPoly SHA256 matches cacophony test vector`() {
        val basePoint = ByteArray(56).also { it[0] = 5 }
        val prologue = hex("4a6f686e2047616c74")

        val initPriv = hex("7fd26c8b8a0d5c98c85ff9ca1d7bc66d78578b9f2c4c170850748b27992767e6ea6cc9992a561c9d19dfc342e260c280ef4f3f9b8f879d4e")
        val initPub = X448.scalarMult(initPriv, basePoint)
        val respPriv = hex("3facf7503ebee252465689f1d4e3b1dd219639ef9de4ffd6049d6d71a0f62126840febb99042421ce12af6626d98d9170260390fbc8399a5")
        val respPub = X448.scalarMult(respPriv, basePoint)

        val initiator = NoiseSession(
            "Noise_NN_448_ChaChaPoly_SHA256", Role.INITIATOR,
            prologue = prologue,
            localEphemeral = KeyPair(initPriv, initPub)
        )
        val responder = NoiseSession(
            "Noise_NN_448_ChaChaPoly_SHA256", Role.RESPONDER,
            prologue = prologue,
            localEphemeral = KeyPair(respPriv, respPub)
        )

        // Message 1: → e (56 bytes ephemeral pubkey + unencrypted payload)
        val msg1 = initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        assertEquals(
            "6cfcb98ae6b1bc5659cadc595bf664e17094404eae6b45fde6fc40ca937d1dbe1464cb66eb21fdbaa487cd0d11d6dce5aa07b8219bfdc49a4c756477696720766f6e204d69736573",
            toHex(msg1))
        responder.readMessage(msg1)

        // Message 2: ← e, ee (56 bytes + encrypted payload)
        val msg2 = responder.writeMessage(hex("4d757272617920526f746862617264"))
        assertEquals(
            "f7eb9a09468f9564819de07ada77a6cf5d5eacd84682067538bf2c4e4c905e5cc35cc3ff41241e47ae3bd296477a236ef185e5a8a0f18d65e5542247f888a7287c99e43a2b0a95bd6080d248cf2b6d9f9b05e2563f6f07",
            toHex(msg2))
        initiator.readMessage(msg2)

        // Transport messages
        val initTransport = initiator.split()
        val respTransport = responder.split()

        val t1 = initTransport.sender.encryptWithAd(byteArrayOf(), hex("462e20412e20486179656b"))
        assertEquals("b8004e4570dbf47915c337816d44cc5f63d3622ea7932dbbffbbcb", toHex(t1))

        val t2 = respTransport.sender.encryptWithAd(byteArrayOf(), hex("4361726c204d656e676572"))
        assertEquals("651507604443049e8d21f7e9a0e49b67c770b8f3ec208fb4e4f030", toHex(t2))
    }
}
