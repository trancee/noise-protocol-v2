import XCTest
@testable import NoiseProtocol

final class PskTests: XCTestCase {
    
    private func hex(_ string: String) -> Data {
        var data = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let nextIndex = string.index(index, offsetBy: 2)
            let byteString = String(string[index..<nextIndex])
            data.append(UInt8(byteString, radix: 16)!)
            index = nextIndex
        }
        return data
    }
    
    private func toHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
    
    func testNoisePSK_NN_ChaChaPoly_SHA256_cacophony() throws {
        let prologue = hex("4a6f686e2047616c74")
        let psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")
        
        let initEphemeral = KeyPair(
            privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        )
        let respEphemeral = KeyPair(
            privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843")
        )
        
        let initiator = try NoiseSession(
            protocolName: "NoisePSK_NN_25519_ChaChaPoly_SHA256", role: .initiator,
            prologue: prologue, localEphemeral: initEphemeral, psks: [psk])
        let responder = try NoiseSession(
            protocolName: "NoisePSK_NN_25519_ChaChaPoly_SHA256", role: .responder,
            prologue: prologue, localEphemeral: respEphemeral, psks: [psk])
        
        let msg0 = try initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        XCTAssertEqual(toHex(msg0),
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794420495e1c45aa6d48bec75e6c0194a30b8482f680a58d92fbc94d16ccd31473b0")
        try responder.readMessage(msg0)
        
        let msg1 = try responder.writeMessage(hex("4d757272617920526f746862617264"))
        XCTAssertEqual(toHex(msg1),
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a6c0a0af9e78614cb0ef972d4bddcd2160ef8f5bb482437adccb926e6577b1")
        try initiator.readMessage(msg1)
        
        let initTransport = try initiator.split()
        let respTransport = try responder.split()
        
        let t1 = try initTransport.sender.encryptWithAd(Data(), plaintext: hex("462e20412e20486179656b"))
        XCTAssertEqual(toHex(t1), "9759720a3d79f72c9f8dfbf0212aa18f33e2ce417cfc4cd336a6c3")
        
        let t2 = try respTransport.sender.encryptWithAd(Data(), plaintext: hex("4361726c204d656e676572"))
        XCTAssertEqual(toHex(t2), "2dacca87bae103cefaedcafe626484a98e325fc38060ec1ec9ffbd")
    }
    
    func testNoisePSK_XX_ChaChaPoly_SHA256_cacophony() throws {
        let prologue = hex("4a6f686e2047616c74")
        let psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")
        
        let dh = Curve25519DH()
        let initStaticPriv = hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
        let initStaticPub = dh.generatePublicKey(privateKey: initStaticPriv)
        let respStaticPriv = hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893")
        let respStaticPub = dh.generatePublicKey(privateKey: respStaticPriv)
        
        let initStatic = KeyPair(privateKey: initStaticPriv, publicKey: initStaticPub)
        let respStatic = KeyPair(privateKey: respStaticPriv, publicKey: respStaticPub)
        let initEphemeral = KeyPair(
            privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
        let respEphemeral = KeyPair(
            privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))
        
        let initiator = try NoiseSession(
            protocolName: "NoisePSK_XX_25519_ChaChaPoly_SHA256", role: .initiator,
            staticKeyPair: initStatic, prologue: prologue,
            localEphemeral: initEphemeral, psks: [psk])
        let responder = try NoiseSession(
            protocolName: "NoisePSK_XX_25519_ChaChaPoly_SHA256", role: .responder,
            staticKeyPair: respStatic, prologue: prologue,
            localEphemeral: respEphemeral, psks: [psk])
        
        let msg0 = try initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        XCTAssertEqual(toHex(msg0),
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79449f8ddea3e713f8813c3ba5765fa26b90688fa9055bffed80f696dd59a7173551")
        try responder.readMessage(msg0)
        
        let msg1 = try responder.writeMessage(hex("4d757272617920526f746862617264"))
        XCTAssertEqual(toHex(msg1),
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088433863d49e43f6eb913421be46743e68ec5a939305ea758606b59811eb2c3ba441cf28102e3516dc7ad18f43fac2889463a01bb28f155272d020edfa3bd149a6ab9dcc60a5c6c9cdf3f9b5085211ed58")
        try initiator.readMessage(msg1)
        
        let msg2 = try initiator.writeMessage(hex("462e20412e20486179656b"))
        XCTAssertEqual(toHex(msg2),
            "aa98156e541a2308e05b1610fa23be4c22b7cfbd617ba68542a6afc7b224c6681feae2eb47cb028ada168466ea4d424404359106638a1c5060a8a4750b2a1b0bee93c00a2d437ed6a850a7")
        try responder.readMessage(msg2)
        
        let respTransport = try responder.split()
        let t1 = try respTransport.sender.encryptWithAd(Data(), plaintext: hex("4361726c204d656e676572"))
        XCTAssertEqual(toHex(t1), "4fda7e55ea65eb577840f187102e80035f5b1fbb0a621204f23e26")
    }
    
    func testNoisePSK_without_PSK_throws() throws {
        XCTAssertThrowsError(
            try NoiseSession(protocolName: "NoisePSK_NN_25519_ChaChaPoly_SHA256",
                           role: .initiator, psks: [])
        ) { error in
            guard case NoiseError.invalidKey = error else {
                XCTFail("Expected invalidKey error"); return
            }
        }
    }

    func testNoise_NNpsk0_modern_format() throws {
        let prologue = hex("4a6f686e2047616c74")
        let psk = hex("54686973206973206d7920417573747269616e20706572737065637469766521")

        let initEphemeral = KeyPair(
            privateKey: hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"),
            publicKey: hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"))
        let respEphemeral = KeyPair(
            privateKey: hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"),
            publicKey: hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"))

        let initiator = try NoiseSession(
            protocolName: "Noise_NNpsk0_25519_ChaChaPoly_SHA256", role: .initiator,
            prologue: prologue, localEphemeral: initEphemeral, psks: [psk])
        let responder = try NoiseSession(
            protocolName: "Noise_NNpsk0_25519_ChaChaPoly_SHA256", role: .responder,
            prologue: prologue, localEphemeral: respEphemeral, psks: [psk])

        let msg0 = try initiator.writeMessage(hex("4c756477696720766f6e204d69736573"))
        XCTAssertEqual(toHex(msg0),
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54")
        try responder.readMessage(msg0)

        let msg1 = try responder.writeMessage(hex("4d757272617920526f746862617264"))
        XCTAssertEqual(toHex(msg1),
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d6062704d5a9c422a8e834423f8c1feada7e8d0d910a1a2cd030fb584221e3")
        try initiator.readMessage(msg1)

        let initTransport = try initiator.split()
        let respTransport = try responder.split()

        let t1 = try initTransport.sender.encryptWithAd(Data(), plaintext: hex("462e20412e20486179656b"))
        XCTAssertEqual(toHex(t1), "e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f")

        let t2 = try respTransport.sender.encryptWithAd(Data(), plaintext: hex("4361726c204d656e676572"))
        XCTAssertEqual(toHex(t2), "64c6bee32ea91c8474bb4c21d7a700109ad45af77b29764ba5eb1e")
    }
}
