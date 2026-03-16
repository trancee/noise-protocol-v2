import Testing
import Foundation
@testable import NoiseProtocol

@Suite("Crypto Providers Tests")
struct CryptoProvidersTests {

    private let initEph = KeyPair(
        privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
    private let respEph = KeyPair(
        privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
    private let prologue = hex("4a6f686e2047616c74")

    @Test("NN AESGCM+SHA256 end-to-end")
    func aesgcmSha256() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA256", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA256", role: .responder)
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        #expect(initiator.isHandshakeComplete)
        let initT = try initiator.split()
        let respT = try responder.split()
        let ct = try initT.sender.encryptWithAd(Data(), plaintext: Data("AESGCM works".utf8))
        let pt = try respT.receiver.decryptWithAd(Data(), ciphertext: ct)
        #expect(pt == Data("AESGCM works".utf8))
    }

    @Test("NN ChaChaPoly+SHA512 end-to-end")
    func chachapolySha512() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA512", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA512", role: .responder)
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        #expect(initiator.isHandshakeComplete)
        let initT = try initiator.split()
        let respT = try responder.split()
        let ct = try initT.sender.encryptWithAd(Data(), plaintext: Data("SHA512 works".utf8))
        let pt = try respT.receiver.decryptWithAd(Data(), ciphertext: ct)
        #expect(pt == Data("SHA512 works".utf8))
    }

    @Test("NN AESGCM+SHA256 matches test vector")
    func aesgcmSha256Vector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA256", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA256", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        #expect(toHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843934ff73eebb9d930ebf62b8e4db8133ca936872b5551efd7c9989c646d8cf0")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "8d372b94914e80018211a344b8b1c5a2869492a0db46990c0362f3")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "e183b0abd55550f9955fb05476d988c6f27628d7bbde111c39ccbc")
    }

    @Test("NN ChaChaPoly+SHA512 matches test vector")
    func chachapolySha512Vector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA512", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_SHA512", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a4b5da00b0bf707701c15f5f54d13dfaa53404c812aaac98d55e2a9463bb94")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "7cc120945f3d00ce194bc60172accedcc168607551c226ef02e602")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "09adc97d36e5b47f3b81bebd1920595e9480f450af4e71df38babf")
    }

    @Test("NN AESGCM+SHA512 matches test vector")
    func aesgcmSha512Vector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA512", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA512", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843f01eddcfafa2580bf4b9670208b19eea75586d8b0352dd82aae394a668e50f")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "a267e88b70a00fbc099d3bd4438073cea04835321f89f028f421bd")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "d0dce53724a6e38d5c0ee4bcb19bdc896c8e62d7a26fe71f7c3424")
    }

    @Test("AESGCM+SHA512 end-to-end")
    func aesgcmSha512() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA512", role: .initiator)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_SHA512", role: .responder)
        try responder.readMessage(initiator.writeMessage())
        try initiator.readMessage(responder.writeMessage())
        #expect(initiator.isHandshakeComplete)
        let initT = try initiator.split()
        let respT = try responder.split()
        let ct = try initT.sender.encryptWithAd(Data(), plaintext: Data("AESGCM+SHA512".utf8))
        let pt = try respT.receiver.decryptWithAd(Data(), ciphertext: ct)
        #expect(pt == Data("AESGCM+SHA512".utf8))
    }

    // Helpers
    private func hexD(_ hex: String) -> Data { Self.hex(hex) }
    private func toHex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private static func hex(_ hex: String) -> Data {
        var data = Data()
        var i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2)
            data.append(UInt8(hex[i..<next], radix: 16)!)
            i = next
        }
        return data
    }
}
