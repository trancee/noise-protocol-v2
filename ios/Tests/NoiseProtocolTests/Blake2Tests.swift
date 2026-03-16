import Testing
import Foundation
@testable import NoiseProtocol

@Suite("BLAKE2 Tests")
struct Blake2Tests {

    @Test("BLAKE2b-512 of abc matches RFC 7693 Appendix A")
    func blake2bRfc7693() {
        let hash = Blake2bHash_()
        let result = hash.hash(Data("abc".utf8))
        #expect(result.count == 64)
        #expect(toHex(result) ==
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    }

    @Test("BLAKE2s-256 of abc matches RFC 7693 Appendix B")
    func blake2sRfc7693() {
        let hash = Blake2sHash_()
        let result = hash.hash(Data("abc".utf8))
        #expect(result.count == 32)
        #expect(toHex(result) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    }

    private let initEph = KeyPair(
        privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
        publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
    private let respEph = KeyPair(
        privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
        publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
    private let prologue = hex("4a6f686e2047616c74")

    @Test("NN ChaChaPoly+BLAKE2b matches cacophony test vector")
    func chachapolyBlake2bVector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_BLAKE2b", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_BLAKE2b", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        #expect(toHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d10cf8ef4ab895bed3e4673211f0c9337039d63a450c7b28196b8a0ebade00")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "e50ec882703a1f34bf4957d8cafd036d34e02930f672f424c676e1")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "35bb2a728d3e8e5f47781d486089e4a37c5c2e4261256f44569a9f")
    }

    @Test("NN ChaChaPoly+BLAKE2s matches cacophony test vector")
    func chachapolyBlake2sVector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_BLAKE2s", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_ChaChaPoly_BLAKE2s", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        #expect(toHex(msg1) == "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573")
        try responder.readMessage(msg1)

        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ff34a6759d06e7733c83aeb5556c15bc762b664b3ba0556b1e7eaea4168bb6")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf")
    }

    @Test("NN AESGCM+BLAKE2b matches cacophony test vector")
    func aesgcmBlake2bVector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_BLAKE2b", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_BLAKE2b", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088430b4b427c7ab9fac9f434513fa08726db51b1b447074227725c16a35f6b37c4")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "9d37117df3063b2dd15b76ab8feb70d1a863ed48809447faffba69")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "0637f52a8c2a4fc85335e3e54ff6f354c640a748db72134abc544a")
    }

    @Test("NN AESGCM+BLAKE2s matches cacophony test vector")
    func aesgcmBlake2sVector() throws {
        let initiator = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_BLAKE2s", role: .initiator,
                                         prologue: prologue, localEphemeral: initEph)
        let responder = try NoiseSession(protocolName: "Noise_NN_25519_AESGCM_BLAKE2s", role: .responder,
                                         prologue: prologue, localEphemeral: respEph)

        let msg1 = try initiator.writeMessage(hexD("4c756477696720766f6e204d69736573"))
        try responder.readMessage(msg1)
        let msg2 = try responder.writeMessage(hexD("4d757272617920526f746862617264"))
        #expect(toHex(msg2) == "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435637c95d5175db82241df5bb90db690493dacfa51454f80512c3e223de17f7")
        try initiator.readMessage(msg2)

        let initT = try initiator.split()
        let respT = try responder.split()
        let t1 = try initT.sender.encryptWithAd(Data(), plaintext: hexD("462e20412e20486179656b"))
        #expect(toHex(t1) == "017e18dffa3706f97c3f08d9318fa68784302749e9389ff63a31b3")
        let t2 = try respT.sender.encryptWithAd(Data(), plaintext: hexD("4361726c204d656e676572"))
        #expect(toHex(t2) == "ce88f443e45f17ada7021df6150b2dd590d985e2eae4ea17c47f5d")
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
