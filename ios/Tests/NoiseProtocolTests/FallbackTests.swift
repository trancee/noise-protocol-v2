import XCTest
@testable import NoiseProtocol

final class FallbackTests: XCTestCase {

    func testXXfallbackHandshakeCompletesWithPreMessageEphemeral() throws {
        let dh = Curve25519DH()
        let aliceStatic = dh.generateKeyPair()
        let bobStatic = dh.generateKeyPair()
        let aliceEphemeral = dh.generateKeyPair()

        let alice = try NoiseSession(
            protocolName: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role: .initiator,
            staticKeyPair: aliceStatic,
            localEphemeral: aliceEphemeral
        )

        let bob = try NoiseSession(
            protocolName: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role: .responder,
            staticKeyPair: bobStatic,
            remoteEphemeral: aliceEphemeral.publicKey
        )

        // Bob writes first in fallback
        let msg1 = try bob.writeMessage(Data("hello from bob".utf8))
        let payload1 = try alice.readMessage(msg1)
        XCTAssertEqual(String(data: payload1, encoding: .utf8), "hello from bob")

        let msg2 = try alice.writeMessage(Data("hello from alice".utf8))
        let payload2 = try bob.readMessage(msg2)
        XCTAssertEqual(String(data: payload2, encoding: .utf8), "hello from alice")

        XCTAssertTrue(bob.isHandshakeComplete)
        XCTAssertTrue(alice.isHandshakeComplete)

        let bobTransport = try bob.split()
        let aliceTransport = try alice.split()

        let ct = try aliceTransport.sender.encryptWithAd(Data(), plaintext: Data("transport test".utf8))
        let pt = try bobTransport.receiver.decryptWithAd(Data(), ciphertext: ct)
        XCTAssertEqual(String(data: pt, encoding: .utf8), "transport test")
    }

    func testIKFailureTransitionsToXXfallbackCompound() throws {
        let dh = Curve25519DH()
        let aliceStatic = dh.generateKeyPair()
        let bobStatic = dh.generateKeyPair()
        let wrongBobStatic = dh.generateKeyPair()

        // Step 1: Alice initiates IK with wrong key
        let aliceIK = try NoiseSession(
            protocolName: "Noise_IK_25519_ChaChaPoly_SHA256",
            role: .initiator,
            staticKeyPair: aliceStatic,
            remoteStaticKey: wrongBobStatic.publicKey
        )
        let ikMsg = try aliceIK.writeMessage()

        // Step 2: Bob can't decrypt
        let bobIK = try NoiseSession(
            protocolName: "Noise_IK_25519_ChaChaPoly_SHA256",
            role: .responder,
            staticKeyPair: bobStatic
        )
        XCTAssertThrowsError(try bobIK.readMessage(ikMsg)) { error in
            XCTAssertEqual(error as? NoiseError, NoiseError.decryptionFailed)
        }

        // Step 3: Extract Alice's ephemeral (first 32 bytes of IK message)
        let aliceEphemeralPublic = ikMsg.prefix(32)

        // Step 4: Bob starts XXfallback
        let bobFallback = try NoiseSession(
            protocolName: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role: .responder,
            staticKeyPair: bobStatic,
            remoteEphemeral: aliceEphemeralPublic
        )

        // Step 5: Alice recreates with her IK ephemeral
        let aliceEphemeralKeyPair = KeyPair(
            privateKey: aliceIK.getLocalEphemeralPrivateKey()!,
            publicKey: aliceEphemeralPublic
        )
        let aliceFallback = try NoiseSession(
            protocolName: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
            role: .initiator,
            staticKeyPair: aliceStatic,
            localEphemeral: aliceEphemeralKeyPair
        )

        // Step 6: Complete fallback (Bob writes first)
        let fbMsg1 = try bobFallback.writeMessage()
        let _ = try aliceFallback.readMessage(fbMsg1)

        let fbMsg2 = try aliceFallback.writeMessage()
        let _ = try bobFallback.readMessage(fbMsg2)

        XCTAssertTrue(bobFallback.isHandshakeComplete)
        XCTAssertTrue(aliceFallback.isHandshakeComplete)

        // Step 7: Transport works
        let bobTransport = try bobFallback.split()
        let aliceTransport = try aliceFallback.split()

        let ct = try aliceTransport.sender.encryptWithAd(Data(), plaintext: Data("fallback success".utf8))
        let pt = try bobTransport.receiver.decryptWithAd(Data(), ciphertext: ct)
        XCTAssertEqual(String(data: pt, encoding: .utf8), "fallback success")

        let ct2 = try bobTransport.sender.encryptWithAd(Data(), plaintext: Data("bob replies".utf8))
        let pt2 = try aliceTransport.receiver.decryptWithAd(Data(), ciphertext: ct2)
        XCTAssertEqual(String(data: pt2, encoding: .utf8), "bob replies")
    }
}
