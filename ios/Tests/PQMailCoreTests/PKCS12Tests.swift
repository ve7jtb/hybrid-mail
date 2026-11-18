import XCTest
@testable import PQMailCore
final class PKCS12Tests: XCTestCase {
    func testPasswordProtectedRoundTrip() throws {
        for p in Profile.allCases {
            let original=try SoftwareMailIdentity(profile:p,email:"storage-test@example.com")
            let bytes=try original.pkcs12(password:"Synthetic test password 123!")
            XCTAssertThrowsError(try SoftwareMailIdentity.loadPKCS12(bytes,password:"wrong password"))
            var damaged=bytes;damaged[damaged.count-1] ^= 1
            XCTAssertThrowsError(try SoftwareMailIdentity.loadPKCS12(damaged,password:"Synthetic test password 123!"))
            let restored=try SoftwareMailIdentity.loadPKCS12(bytes,password:"Synthetic test password 123!")
            XCTAssertEqual(restored.availableModes,[false,true])
            for hybrid in [false,true] {
                XCTAssertEqual(try restored.signingCertificate(hybrid:hybrid),try original.signingCertificate(hybrid:hybrid))
                let message=try SMIME.compose(identity:original,hybrid:hybrid,to:original.email,subject:"test",text:"persistent",recipientCertificate:original.encryptionCertificate(hybrid:hybrid))
                XCTAssertEqual(try SMIME.open(message,identity:restored,hybrid:hybrid).text,"persistent")
                let signed=try SMIME.compose(identity:restored,hybrid:hybrid,to:original.email,subject:"test",text:"restored")
                XCTAssertEqual(try SMIME.open(signed).text,"restored")
            }
        }
    }
}
