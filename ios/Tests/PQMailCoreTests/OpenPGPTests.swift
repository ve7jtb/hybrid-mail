import XCTest
@testable import PQMailCore

final class OpenPGPTests:XCTestCase {
    private func fixture(_ name:String)throws->Data {
        let path=URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/"+name)
        return try Data(contentsOf:path)
    }
    private func hex(_ s:String)->Data {
        var d=Data(),i=s.startIndex
        while i<s.endIndex {let j=s.index(i,offsetBy:2);d.append(UInt8(s[i..<j],radix:16)!);i=j};return d
    }
    func testPublishedDraftVectors() throws {
        let pub=try PGP.PublicIdentity(fixture("nist-p384-public.asc"))
        XCTAssertEqual(try pub.fingerprint.hex.uppercased(),"44F8AEA123A5BB7B747C714A3749876A84ECC7EFCAC6CB5ACCD1A152F6351DE6")
        let sig=try PGP.packets(PGP.unarmor(fixture("nist-p384-signature.asc"),"SIGNATURE"))
        _ = try PGP.verifySignature(sig[0].body,data:Data("Testing\n".utf8),type:0,key:pub.primary)
        let encrypted=try PGP.unarmor(fixture("nist-p384-message.asc"),"MESSAGE")
        let envelope=try PGP.Envelope(encrypted,recipient:pub)
        let kek=try PGP.combine(
            hex("6FC2B62C8A99B3ACE887055CEF120E763820D8742373FB9FBED1AE140056F34D"),
            hex("849DB1550BC587A213684D607C4B2A888FAADBEAC9B86F4D940CEDFF7CC6F2C6FEA19640135D2676E3309F3B496B114C"),
            Data(envelope.ciphertext.prefix(97)),PGP.raw(pub.encryption.ec!))
        XCTAssertEqual(kek.hex.uppercased(),"E32208735F54262A792303915B26BD37BE621FC278617CE81EE62FB41C60F3FD")
        // Independent draft fixture exercises AES-256-OCB; outgoing messages also support GCM.
        let session=try NativeCrypto.wrap(false,kek,envelope.wrapped)
        XCTAssertEqual(session.hex.uppercased(),"3DDC8DBB5E523105E906E05EF47157103DD6342E58D91271F496A4699075D265")
        let plain=try envelope.open(kek)
        XCTAssertEqual(try PGP.openSigned(plain,signer:pub),Data("Testing\n".utf8))
    }
    func testMailRoundTripPersistenceAndTampering() async throws {
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:dir)}
        let service=LocalMailService(storeURL:dir)
        let saved=try await service.create(profile:.level3,email:"pgp@example.com",password:"test-password-only")
        _ = try await service.createOpenPGP()
        let publicKey=try await service.exportOpenPGP()
        for encrypted in [false,true] {
            let mail=try await service.compose(profile:.level3,hybrid:true,to:"pgp@example.com",subject:"PGP",text:"OpenPGP test",encrypt:encrypted,recipient:nil,format:.openPGP)
            XCTAssertTrue(OpenPGPMail.isPGP(mail))
            let opened=try await service.open(mail,hybrid:true)
            XCTAssertEqual(opened.text,"OpenPGP test");XCTAssertEqual(opened.encrypted,encrypted)
            let (_,parts,_)=try OpenPGPMail.parts(mail)
            if !encrypted {
                var sig=try PGP.unarmor(MIMEPart(parts[1]).decoded(),"SIGNATURE")
                for index in [sig.count-1,sig.count-3310] {
                    sig[index] ^= 1
                    let changed=try OpenPGPMail.wrap(parts[0],Data("Content-Type: application/pgp-signature\r\n\r\n".utf8)+PGP.armor(sig,"SIGNATURE"),encrypted:false,from:"pgp@example.com",to:"pgp@example.com",subject:"PGP")
                    do{_ = try await service.open(changed,hybrid:true);XCTFail("Accepted tampered component")}catch{}
                    sig[index] ^= 1
                }
            } else {
                var packet=try PGP.unarmor(MIMEPart(parts[1]).decoded(),"MESSAGE");packet[packet.count-1] ^= 1
                let changed=try OpenPGPMail.wrap(parts[0],Data("Content-Type: application/octet-stream\r\n\r\n".utf8)+PGP.armor(packet,"MESSAGE"),encrypted:true,from:"pgp@example.com",to:"pgp@example.com",subject:"PGP")
                do{_ = try await service.open(changed,hybrid:true);XCTFail("Accepted tampered AEAD")}catch{}
            }
        }
        await service.lock()
        let other=LocalMailService(storeURL:dir)
        _ = try await other.select(saved.id,password:"test-password-only")
        let restored=try await other.exportOpenPGP();XCTAssertEqual(restored,publicKey)
    }
    func testRejectUnsupportedProfilesAndWrongRecipient() async throws {
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:dir)}
        let service=LocalMailService(storeURL:dir)
        for p in [Profile.level2,.level5] {
            _ = try await service.create(profile:p,email:"pgp@example.com",password:"test-password-only")
            do{_ = try await service.createOpenPGP();XCTFail("Accepted unsupported profile")}catch{}
        }
        for bad in [Data(),Data([0xc6,255,255,255,255,255]),Data([0xc6,224]),Data([0xc6,1,6])] {
            XCTAssertThrowsError(try PGP.PublicIdentity(bad))
        }
    }
    func testRecipientBindingAndPublicKeyTampering() async throws {
        let a=try SoftwareMailIdentity(profile:.level3,email:"a@example.com")
        let b=try SoftwareMailIdentity(profile:.level3,email:"b@example.com")
        let ak=a.signingKeys,bk=b.signingKeys
        let alice=try await PGP.makePublic(signing:ak,encryption:a.encryptionKeys,email:a.email,created:Int(Date().timeIntervalSince1970)){try PGP.signDigest($0,ak)}
        let bob=try await PGP.makePublic(signing:bk,encryption:b.encryptionKeys,email:b.email,created:Int(Date().timeIntervalSince1970)){try PGP.signDigest($0,bk)}
        let signed=try await PGP.signedPackets(Data("test".utf8),identity:alice){try PGP.signDigest($0,ak)}
        let encrypted=try PGP.encrypt(signed,recipient:bob)
        XCTAssertThrowsError(try PGP.Envelope(encrypted,recipient:alice))
        let envelope=try PGP.Envelope(encrypted,recipient:bob)
        XCTAssertThrowsError(try envelope.open(PGP.decapsulate(envelope.ciphertext,a.encryptionKeys)))
        let clear=try envelope.open(PGP.decapsulate(envelope.ciphertext,b.encryptionKeys))
        XCTAssertEqual(try PGP.openSigned(clear,signer:alice),Data("test".utf8))
        XCTAssertThrowsError(try PGP.openSigned(clear,signer:bob))
        var key=alice.encoded;key[key.count-1] ^= 1
        XCTAssertThrowsError(try PGP.PublicIdentity(key))
        var point=Data(repeating:0,count:97);point[0]=4
        XCTAssertThrowsError(try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(Profile.level3.curveOID)]),.bits(point)]).der))
    }
    func testJavaInteroperability() async throws {
        guard let path=ProcessInfo.processInfo.environment["PQ_MAIL_OPENPGP_DIR"] else{throw XCTSkip("Set PQ_MAIL_OPENPGP_DIR for Java/OpenSSL exchange")}
        let dir=URL(fileURLWithPath:path),temp=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:temp)}
        let service=LocalMailService(storeURL:temp)
        _ = try await service.importPKCS12(Data(contentsOf:dir.appendingPathComponent("identity.p12")),password:"interop-password-only")
        _ = try await service.importOwnOpenPGP(Data(contentsOf:dir.appendingPathComponent("public.asc")))
        for encrypted in [false,true] {
            let suffix=encrypted ? "encrypted.eml" : "signed.eml"
            let incoming=try await service.open(Data(contentsOf:dir.appendingPathComponent("java-"+suffix)),hybrid:true)
            XCTAssertEqual(incoming.text,"Java OpenPGP test");XCTAssertEqual(incoming.encrypted,encrypted)
            let outgoing=try await service.compose(profile:.level3,hybrid:true,to:"interop@example.com",subject:"Interop",text:"Swift OpenPGP test",encrypt:encrypted,recipient:nil,format:.openPGP)
            try outgoing.write(to:dir.appendingPathComponent("swift-"+suffix))
        }
    }
    func testChunkingAndTruncation() throws {
        let session=try NativeCrypto.random(32),plain=try NativeCrypto.random(150000)
        for mode:UInt8 in [2,3] {
            let encoded=try PGP.seipd(plain,session,mode:mode),body=try PGP.packets(encoded)[0].body
            XCTAssertEqual(try PGP.decryptSEIPD(body,session),plain)
            XCTAssertThrowsError(try PGP.decryptSEIPD(Data(body.dropLast(16)),session))
            XCTAssertThrowsError(try PGP.decryptSEIPD(body,NativeCrypto.random(32)))
        }
    }
}
