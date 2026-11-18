import XCTest
@testable import PQMailCore
final class ProfileTests: XCTestCase {
    func testDesktopParity() throws {
        XCTAssertEqual(Profile.allCases.map(\.hybridSigningOID), ["1.3.6.1.5.5.7.6.40", "1.3.6.1.5.5.7.6.46", "1.3.6.1.5.5.7.6.49"])
        XCTAssertEqual(Profile.allCases.map(\.hybridEncryptionOID), ["1.3.6.1.5.5.7.6.59", "1.3.6.1.5.5.7.6.60", "1.3.6.1.5.5.7.6.63"])
        XCTAssertEqual(Profile.level3.mlKEM, "ML-KEM-768")
        XCTAssertEqual(Profile.level3.curve, "P-384")
        XCTAssertThrowsError(try SlotMap(ecdsa: 0x9c))
        XCTAssertThrowsError(try SlotMap(ecdh: 0xff))
    }
    func testChainedResponse() async throws {
        var commands: [Data] = []
        let result = try await CardRead.exchange(Data([0,0xf7,0,0x9c,0])) { command in
            commands.append(command)
            return commands.count == 1 ? Data([1,2,0x61,3]) : Data([3,4,5,0x90,0])
        }
        XCTAssertEqual(result, Data([1,2,3,4,5]))
        XCTAssertEqual(commands.last, Data([0,0xc0,0,0,3]))
    }
    func testRejectsStatusAndTruncation() async {
        for response in [Data([0x6a,0x82]), Data([0x90])] {
            do { _ = try await CardRead.exchange(Data()) { _ in response }; XCTFail("Must reject invalid response") } catch {}
        }
    }
    func testBoundedChaining() async {
        do { _ = try await CardRead.exchange(Data()) { _ in Data([0x61,0]) }; XCTFail("Must bound chaining") } catch {}
    }
}
