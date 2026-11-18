import XCTest
@testable import PQMailCore
final class SMIMETests: XCTestCase {
    func testAllProfilesRoundTripAndTampering() throws {
        for profile in Profile.allCases {
            let id=try SoftwareMailIdentity(profile:profile,email:"ios-test@example.com")
            let wrong=try SoftwareMailIdentity(profile:profile,email:"ios-test@example.com")
            for hybrid in [false,true] {
                for encrypted in [false,true] {
                    let eml=try SMIME.compose(identity:id,hybrid:hybrid,to:id.email,subject:"Interop",text:"Pure and hybrid S/MIME ✓",recipientCertificate:encrypted ? id.encryptionCertificate(hybrid:hybrid) : nil)
                    let opened=try SMIME.open(eml,identity:id,hybrid:hybrid)
                    XCTAssertEqual(opened.text,"Pure and hybrid S/MIME ✓")
                    XCTAssertTrue(opened.fromMatches)
                    XCTAssertEqual(opened.encrypted,encrypted)
                    var cms=try MIMEPart(eml).decoded();cms[cms.count-1] ^= 1
                    XCTAssertThrowsError(try SMIME.open(SMIME.mime(cms,encrypted:encrypted),identity:id,hybrid:hybrid))
                    if encrypted {XCTAssertThrowsError(try SMIME.open(eml,identity:wrong,hybrid:hybrid))}
                }
                let cert=try id.certs(hybrid).0
                let message=Data("test".utf8),signature=try id.signingKeys.sign(message,cert.algorithm)
                try cert.keys.verify(signature,message,cert.algorithm)
                if hybrid {
                    for index in [0,profile.signatureBytes] {
                        var bad=signature;bad[index] ^= 1
                        XCTAssertThrowsError(try cert.keys.verify(bad,message,cert.algorithm))
                    }
                }
            }
        }
    }
    func testKEMComponentsAndOuterHeaderSemantics() throws {
        for p in Profile.allCases {
            let id=try SoftwareMailIdentity(profile:p,email:"ios-test@example.com")
            for h in [false,true] {
                let cert=try id.certs(h).1
                let (ct,ss)=try cert.keys.encapsulate(cert.algorithm)
                XCTAssertEqual(try id.encryptionKeys.decapsulate(ct,cert.algorithm),ss)
                for index in h ? [0,ct.count-1] : [0] {
                    var changed=ct;changed[index] ^= 1
                    do {let recovered=try id.encryptionKeys.decapsulate(changed,cert.algorithm);XCTAssertNotEqual(recovered,ss)} catch {}
                }
                XCTAssertThrowsError(try id.encryptionKeys.decapsulate(Data(ct.dropLast()),cert.algorithm))
            }
        }
        let id=try SoftwareMailIdentity(profile:.level3,email:"ios-test@example.com")
        let message=try SMIME.compose(identity:id,hybrid:true,to:id.email,subject:"test",text:"body")
        let changed=Data(String(data:message,encoding:.utf8)!.replacingOccurrences(of:"From: ios-test@example.com",with:"From: other@example.com").utf8)
        let opened=try SMIME.open(changed)
        XCTAssertEqual(opened.text,"body")
        XCTAssertFalse(opened.fromMatches)
    }
    func testRejectsMalformedMessagesAndHeaderInjection() throws {
        let id=try SoftwareMailIdentity(profile:.level2,email:"ios-test@example.com")
        XCTAssertThrowsError(try SMIME.compose(identity:id,hybrid:false,to:id.email,subject:"hi\r\nBcc: other@example.com",text:"x"))
        XCTAssertThrowsError(try SMIME.compose(identity:id,hybrid:false,to:"other@example.com",subject:"hi",text:"x",recipientCertificate:id.encryptionCertificate(hybrid:false)))
        for data in [Data(),Data([0x30,0x80,0]),Data([0x30,0xff]),Data([0x30,0,0]),Data([4,0x80,0,0])] {XCTAssertThrowsError(try ASN1.parse(data))}
    }
    func testDesktopInteroperability() throws {
        guard let path=ProcessInfo.processInfo.environment["PQ_MAIL_INTEROP_DIR"] else {throw XCTSkip("Set PQ_MAIL_INTEROP_DIR for desktop fixture exchange")}
        let dir=URL(fileURLWithPath:path)
        for p in Profile.allCases {for h in [false,true] {
            let prefix="level\(p.rawValue)-\(h ? "hybrid" : "pure")"
            let input=dir.appendingPathComponent("bc/"+prefix)
            func read(_ name: String) throws -> Data {try Data(contentsOf:input.appendingPathComponent(name))}
            let id=try SoftwareMailIdentity.loadPKCS12(read("desktop.p12"),password:"interop-password-only")
            try id.pkcs12(password:"interop-password-only").write(to:input.appendingPathComponent("ios.p12"))
            for encrypted in [false,true] {
                let file=encrypted ? "encrypted.eml" : "signed.eml"
                let opened=try SMIME.open(read(file),identity:id,hybrid:h)
                XCTAssertEqual(opened.text.trimmingCharacters(in:.whitespacesAndNewlines),"Desktop interoperability test")
                let result=try SMIME.compose(identity:id,hybrid:h,to:id.email,subject:"iOS reply",text:"iOS interoperability test",recipientCertificate:encrypted ? id.encryptionCertificate(hybrid:h) : nil)
                try result.write(to:input.appendingPathComponent("ios-"+file))
            }
        }}
    }
}
