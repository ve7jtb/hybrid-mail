import Foundation

/// Matches desktop TokenProfile. Category labels refer to the ML-DSA parameter set.
public enum Profile: Int, CaseIterable, Identifiable, Sendable {
    case level2 = 2, level3 = 3, level5 = 5
    public var id: Int { rawValue }
    public var mlDSA: String { switch self { case .level2: "ML-DSA-44"; case .level3: "ML-DSA-65"; case .level5: "ML-DSA-87" } }
    public var mlKEM: String { self == .level5 ? "ML-KEM-1024" : "ML-KEM-768" }
    public var curve: String { self == .level2 ? "P-256" : "P-384" }
    public var pureSigningOID: String { "2.16.840.1.101.3.4.3." + (self == .level2 ? "17" : self == .level3 ? "18" : "19") }
    public var pureEncryptionOID: String { "2.16.840.1.101.3.4.4." + (self == .level5 ? "3" : "2") }
    public var hybridSigningOID: String { "1.3.6.1.5.5.7.6." + (self == .level2 ? "40" : self == .level3 ? "46" : "49") }
    public var hybridEncryptionOID: String { "1.3.6.1.5.5.7.6." + (self == .level2 ? "59" : self == .level3 ? "60" : "63") }
    public var hybridSigningName: String { mlDSA.replacingOccurrences(of: "-", with: "") + "-ECDSA-" + curve.replacingOccurrences(of: "-", with: "") + (self == .level2 ? "-SHA256" : "-SHA512") }
    public var hybridEncryptionName: String { mlKEM.replacingOccurrences(of: "-", with: "") + "-ECDH-" + curve.replacingOccurrences(of: "-", with: "") + "-SHA3-256" }
}

public struct SlotMap: Equatable, Sendable {
    public let mlDSA: UInt8, ecdsa: UInt8, mlKEM: UInt8, ecdh: UInt8
    public init(mlDSA: UInt8 = 0x9c, ecdsa: UInt8 = 0x83, mlKEM: UInt8 = 0x9d, ecdh: UInt8 = 0x82) throws {
        let slots = [mlDSA, ecdsa, mlKEM, ecdh]
        guard Set(slots).count == 4, slots.allSatisfy({ (0x82...0x95).contains($0) || [0x9a,0x9c,0x9d,0x9e].contains($0) }) else { throw ProbeError.invalidSlots }
        self.mlDSA=mlDSA; self.ecdsa=ecdsa; self.mlKEM=mlKEM; self.ecdh=ecdh
    }
}
