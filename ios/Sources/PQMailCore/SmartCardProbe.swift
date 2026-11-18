import Foundation
import YubiKit

public enum ProbeError: Error, LocalizedError {
    case malformedResponse, responseTooLarge, status(UInt16), wrongSerial(expected: UInt, actual: UInt), invalidSlots
    public var errorDescription: String? {
        switch self {
        case .malformedResponse: "Invalid smart-card response."
        case .responseTooLarge: "Smart-card response exceeded the read limit."
        case .status(let sw): String(format: "PIV returned SW=%04X. If 6A82, check that PIV is enabled for this transport.", sw)
        case .wrongSerial(let expected, let actual): "Insert YubiKey \(expected); connected key is \(actual)."
        case .invalidSlots: "Four distinct PIV key slots are required."
        }
    }
}

/// Bounded ISO 7816 response chaining. No PIN or private operations in this preview.
public enum CardRead {
    public static func exchange(_ command: Data, send: (Data) async throws -> Data) async throws -> Data {
        var next = command
        var output = Data()
        for _ in 0..<256 {
            let response = try await send(next)
            guard response.count >= 2 else { throw ProbeError.malformedResponse }
            let bytes = [UInt8](response)
            let sw1 = bytes[bytes.count-2], sw2 = bytes[bytes.count-1]
            output.append(contentsOf: bytes.dropLast(2))
            guard output.count <= 65536 else { throw ProbeError.responseTooLarge }
            if sw1 == 0x90 && sw2 == 0 { return output }
            guard sw1 == 0x61 else { throw ProbeError.status(UInt16(sw1) << 8 | UInt16(sw2)) }
            next = Data([0, 0xc0, 0, 0, sw2])
        }
        throw ProbeError.responseTooLarge
    }
}

public struct ProbeReport: Sendable {
    public let serial: UInt
    public let firmware: String
    public let metadataBytes: [UInt8: Int]
}

public enum YubiKeyProbe {
    /// Reads metadata as bytes because upstream PIV.KeyType rejects ML-DSA/ML-KEM.
    /// Byte counts are diagnostics, not proof of algorithm or private-key possession.
    public static func inspect(_ connection: any SmartCardConnection, expectedSerial: UInt? = nil) async throws -> ProbeReport {
        do {
            let session = try await PIVSession.makeSession(connection: connection)
            let serial = try await session.getSerialNumber()
            if let expectedSerial, serial != expectedSerial { throw ProbeError.wrongSerial(expected: expectedSerial, actual: serial) }
            let version = await session.version
            var sizes: [UInt8: Int] = [:]
            for slot: UInt8 in [0x9c, 0x9a, 0x9d, 0x82] {
                do {
                    let metadata = try await CardRead.exchange(Data([0, 0xf7, 0, slot, 0])) { try await connection.send(data: $0) }
                    sizes[slot] = metadata.count
                } catch ProbeError.status(0x6a88) { sizes[slot] = 0 }
            }
            await connection.close(error: nil)
            return ProbeReport(serial: serial, firmware: String(describing: version), metadataBytes: sizes)
        } catch {
            await connection.close(error: error)
            throw error
        }
    }
}
