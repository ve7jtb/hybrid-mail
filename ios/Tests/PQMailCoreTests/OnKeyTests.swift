import XCTest
@testable import PQMailCore

private actor MemoryObjects:OnKeyCard {
    var objects:[Int:Data]=[:];var failAt:Int?;var writes=0
    let serial:UInt
    init(_ serial:UInt=123456){self.serial=serial}
    func get(_ tag:Int)throws->Data?{objects[tag]}
    func put(_ tag:Int,_ data:Data)throws{if writes==failAt{throw MailCryptoError.invalid("Interrupted write")};writes+=1;objects[tag]=data}
    func recover(_ bundle:OnKeyBundle)throws->OnKeyBundle{try check(bundle.credentials);return bundle}
    func authenticate(_ management:Data){}
    func check(_ credentials:[YubiKeyCredential])throws{try require(credentials.allSatisfy{$0.serial==serial},"Wrong serial")}
    func fail(_ n:Int?){writes=0;failAt=n}
    func collision(){objects[0x5f5001]=Data("another app".utf8)}
}
final class OnKeyTests:XCTestCase {
    func fixture(_ profile:Profile)async throws->OnKeyBundle {
        let id=try SoftwareMailIdentity(profile:profile,email:"onkey@example.com")
        let cs=try [false,true].map{hybrid in try YubiKeyCredential(serial:123456,signingSlot:0x9c,traditionalSlot:0x83,kemSlot:0x9d,ecdhSlot:0x82,signingDER:id.signingCertificate(hybrid:hybrid),encryptionDER:id.encryptionCertificate(hybrid:hybrid))}
        let signing=id.signingKeys
        let pgp=profile == .level3 ? try await PGP.makePublic(signing:id.signingKeys,encryption:id.encryptionKeys,email:id.email,created:Int(Date().timeIntervalSince1970)-60){try PGP.signDigest($0,signing)}.encoded:Data()
        return try await OnKeyBundle.signed(cs,[Data(),pgp],signer:1){try id.signingKeys.sign($0,Algorithm(profile:profile,hybrid:true,signing:true))}
    }
    func testProfilesStorageInterruptionAndTamper()async throws {
        for p in Profile.allCases {
            let bundle=try await fixture(p),card=MemoryObjects()
            try await OnKeyStorage.save(bundle,card,Data())
            for cut in 0...((bundle.encoded.count+2047)/2048){await card.fail(cut);do{try await OnKeyStorage.save(bundle,card,Data());XCTFail("Expected interrupted write")}catch{};let loaded=try await OnKeyStorage.load(card);XCTAssertEqual(loaded.encoded,bundle.encoded)}
            await card.fail(nil);try await OnKeyStorage.save(bundle,card,Data());let loaded=try await OnKeyStorage.load(card);XCTAssertEqual(loaded.encoded,bundle.encoded)
            var bad=bundle.encoded;bad[bad.count-1]^=1;XCTAssertThrowsError(try OnKeyBundle(bad));XCTAssertThrowsError(try OnKeyBundle(Data(bundle.encoded.dropLast())))
            let collision=MemoryObjects();await collision.collision();do{try await OnKeyStorage.save(bundle,collision,Data());XCTFail("Collision accepted")}catch{}
        }
    }
    func testImportPersistenceAndPgp()async throws {
        let bundle=try await fixture(.level3),directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:directory)}
        let service=LocalMailService(storeURL:directory);try await service.importOnKey(bundle);try await service.importOnKey(bundle)
        let restored=LocalMailService(storeURL:directory),entries=try await restored.savedIdentities();XCTAssertEqual(entries.count,2)
        let hybrid=entries.first{$0.modes.contains(true)}!;_ = try await restored.select(hybrid.id)
        let pgp=try await restored.exportOpenPGP();XCTAssertEqual(try PGP.PublicIdentity(pgp).encoded,bundle.pgp[1]);XCTAssertEqual(hybrid.token?.traditionalSlot,0x83)
    }
    func testJavaInteroperability()async throws {
        guard let path=ProcessInfo.processInfo.environment["PQ_MAIL_ONKEY_INTEROP"]else{throw XCTSkip("Set PQ_MAIL_ONKEY_INTEROP for Java exchange")}
        for p in Profile.allCases {
            let folder=URL(fileURLWithPath:path),java=try OnKeyBundle(Data(contentsOf:folder.appendingPathComponent("level\(p.rawValue).pqkey")))
            XCTAssertEqual(java.credentials.count,2);XCTAssertEqual(java.pgp[1].isEmpty,p != .level3)
            let swift=try await fixture(p);try swift.encoded.write(to:folder.appendingPathComponent("swift-level\(p.rawValue).pqkey"))
        }
    }
}
