package noise.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests for the HandshakeState refactor (issue #18):
 * HandshakeConfig, DH dispatch table, KeyStore, upfront validation.
 */
class HandshakeStateRefactorTest {

    // ── Slice 3: KeyStore domain errors ─────────────────────────────

    @Test
    fun `KeyStore throws InvalidKey for missing local static`() {
        val store = KeyStore(staticKeyPair = null, remoteStaticKey = null)
        val ex = assertThrows<NoiseException.InvalidKey> {
            store.requireKeyPair(KeyRef.S)
        }
        assertTrue(ex.message!!.contains("static"))
    }

    @Test
    fun `KeyStore throws InvalidKey for missing local ephemeral`() {
        val store = KeyStore(staticKeyPair = null, remoteStaticKey = null)
        val ex = assertThrows<NoiseException.InvalidKey> {
            store.requireKeyPair(KeyRef.E)
        }
        assertTrue(ex.message!!.contains("ephemeral"))
    }

    @Test
    fun `KeyStore throws InvalidKey for missing remote static`() {
        val store = KeyStore(staticKeyPair = null, remoteStaticKey = null)
        val ex = assertThrows<NoiseException.InvalidKey> {
            store.requirePublicKey(KeyRef.RS)
        }
        assertTrue(ex.message!!.contains("static"))
    }

    @Test
    fun `KeyStore throws InvalidKey for missing remote ephemeral`() {
        val store = KeyStore(staticKeyPair = null, remoteStaticKey = null)
        val ex = assertThrows<NoiseException.InvalidKey> {
            store.requirePublicKey(KeyRef.RE)
        }
        assertTrue(ex.message!!.contains("ephemeral"))
    }

    @Test
    fun `KeyStore returns keys when present`() {
        val kp = Curve25519DH.generateKeyPair()
        val rs = Curve25519DH.generateKeyPair().publicKey
        val store = KeyStore(staticKeyPair = kp, remoteStaticKey = rs)

        assertEquals(kp, store.requireKeyPair(KeyRef.S))
        assertTrue(store.requirePublicKey(KeyRef.RS).contentEquals(rs))
    }

    // ── Slice 4: Upfront validation — missing static key ───────────

    @Test
    fun `KK pattern without static key throws InvalidKey at construction`() {
        val suite = CryptoResolver.default.resolve("25519", "ChaChaPoly", "SHA256")
        val descriptor = PatternParser.parse("Noise_KK_25519_ChaChaPoly_SHA256")

        val config = HandshakeConfig(
            protocolName = "Noise_KK_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            dh = suite.dh, cipher = suite.cipher, hash = suite.hash,
            descriptor = descriptor,
            remoteStaticKey = Curve25519DH.generateKeyPair().publicKey
            // staticKeyPair deliberately omitted
        )

        val ex = assertThrows<NoiseException.InvalidKey> {
            HandshakeState(config)
        }
        assertTrue(ex.message!!.contains("static"))
    }

    // ── Slice 5: Upfront validation — missing remote static ─────────

    @Test
    fun `NK initiator without remote static key throws InvalidKey`() {
        val suite = CryptoResolver.default.resolve("25519", "ChaChaPoly", "SHA256")
        val descriptor = PatternParser.parse("Noise_NK_25519_ChaChaPoly_SHA256")

        val config = HandshakeConfig(
            protocolName = "Noise_NK_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            dh = suite.dh, cipher = suite.cipher, hash = suite.hash,
            descriptor = descriptor
            // remoteStaticKey deliberately omitted — NK needs it for initiator
        )

        val ex = assertThrows<NoiseException.InvalidKey> {
            HandshakeState(config)
        }
        assertTrue(ex.message!!.contains("static"))
    }

    // ── Slice 6: Upfront validation — insufficient PSKs ─────────────

    @Test
    fun `NNpsk0 without PSK throws InvalidKey at construction`() {
        val suite = CryptoResolver.default.resolve("25519", "ChaChaPoly", "SHA256")
        val descriptor = PatternParser.parse("Noise_NNpsk0_25519_ChaChaPoly_SHA256")

        val config = HandshakeConfig(
            protocolName = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            dh = suite.dh, cipher = suite.cipher, hash = suite.hash,
            descriptor = descriptor
            // psks deliberately empty
        )

        val ex = assertThrows<NoiseException.InvalidKey> {
            HandshakeState(config)
        }
        assertTrue(ex.message!!.lowercase().contains("psk"))
    }

    // ── Slice 1: HandshakeConfig tracer bullet ──────────────────────

    // ── Slice 2: DH dispatch table ────────────────────────────────

    @Test
    fun `DH dispatch table maps all 8 token-role pairs`() {
        // ee: both roles use (E, RE)
        assertEquals(DhOp(KeyRef.E, KeyRef.RE), DH_DISPATCH["ee" to Role.INITIATOR])
        assertEquals(DhOp(KeyRef.E, KeyRef.RE), DH_DISPATCH["ee" to Role.RESPONDER])

        // es: INITIATOR uses (E, RS), RESPONDER uses (S, RE)
        assertEquals(DhOp(KeyRef.E, KeyRef.RS), DH_DISPATCH["es" to Role.INITIATOR])
        assertEquals(DhOp(KeyRef.S, KeyRef.RE), DH_DISPATCH["es" to Role.RESPONDER])

        // se: INITIATOR uses (S, RE), RESPONDER uses (E, RS)
        assertEquals(DhOp(KeyRef.S, KeyRef.RE), DH_DISPATCH["se" to Role.INITIATOR])
        assertEquals(DhOp(KeyRef.E, KeyRef.RS), DH_DISPATCH["se" to Role.RESPONDER])

        // ss: both roles use (S, RS)
        assertEquals(DhOp(KeyRef.S, KeyRef.RS), DH_DISPATCH["ss" to Role.INITIATOR])
        assertEquals(DhOp(KeyRef.S, KeyRef.RS), DH_DISPATCH["ss" to Role.RESPONDER])
    }

    @Test
    fun `DH dispatch table has exactly 8 entries`() {
        assertEquals(8, DH_DISPATCH.size)
    }

    // ── Slice 1: HandshakeConfig tracer bullet ──────────────────────

    @Test
    fun `NN handshake works through HandshakeConfig`() {
        val suite = CryptoResolver.default.resolve("25519", "ChaChaPoly", "SHA256")
        val descriptor = PatternParser.parse("Noise_NN_25519_ChaChaPoly_SHA256")

        val iConfig = HandshakeConfig(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.INITIATOR,
            dh = suite.dh,
            cipher = suite.cipher,
            hash = suite.hash,
            descriptor = descriptor
        )
        val rConfig = HandshakeConfig(
            protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
            role = Role.RESPONDER,
            dh = suite.dh,
            cipher = suite.cipher,
            hash = suite.hash,
            descriptor = descriptor
        )

        val initiator = HandshakeState(iConfig)
        val responder = HandshakeState(rConfig)

        val msg1 = initiator.writeMessage()
        responder.readMessage(msg1)
        val msg2 = responder.writeMessage()
        initiator.readMessage(msg2)

        assertTrue(initiator.isHandshakeComplete)
        assertTrue(responder.isHandshakeComplete)
    }
}
