import Foundation

extension Profile {
    var signingPublicBytes: Int { self == .level2 ? 1312 : self == .level3 ? 1952 : 2592 }
    var signatureBytes: Int { self == .level2 ? 2420 : self == .level3 ? 3309 : 4627 }
    var kemPublicBytes: Int { self == .level5 ? 1568 : 1184 }
    var ciphertextBytes: Int { self == .level5 ? 1568 : 1088 }
    var pointBytes: Int { self == .level2 ? 65 : 97 }
    var group: String { self == .level2 ? "prime256v1" : "secp384r1" }
    var curveOID: String { self == .level2 ? "1.2.840.10045.3.1.7" : "1.3.132.0.34" }
    var compositeHash: String { self == .level2 ? "SHA256" : "SHA512" }
    var ecHash: String { self == .level2 ? "SHA256" : "SHA384" }
}
struct Algorithm: Equatable, Sendable {
    let profile: Profile
    let hybrid: Bool
    let signing: Bool
    var oid: String { signing ? (hybrid ? profile.hybridSigningOID : profile.pureSigningOID) : (hybrid ? profile.hybridEncryptionOID : profile.pureEncryptionOID) }
    static func identify(_ oid: ASN1, signing: Bool) throws -> Algorithm {
        for p in Profile.allCases { for h in [false,true] { let a=Algorithm(profile:p,hybrid:h,signing:signing);if oid.isOID(a.oid) {return a} } }
        throw MailCryptoError.invalid("Unsupported algorithm profile")
    }
}
struct ComponentKeys: Sendable {
    let pq: NativeKey
    let ec: NativeKey?
    static func publicKeys(_ spki: ASN1, _ algorithm: Algorithm) throws -> ComponentKeys {
        _ = try spki.expect(0x30,count:2)
        let alg=try spki.child(0).expect(0x30,count:1)
        try require(try alg.child(0).isOID(algorithm.oid),"Algorithm mismatch")
        let raw=try spki.child(1).bitBytes()
        if !algorithm.hybrid { return ComponentKeys(pq:try NativeKey(der:spki.der),ec:nil) }
        let p=algorithm.profile, n=algorithm.signing ? p.signingPublicBytes : p.kemPublicBytes
        try require(raw.count==n+p.pointBytes,"Invalid composite public key length")
        let pqOID=algorithm.signing ? p.pureSigningOID : p.pureEncryptionOID
        let pqSPKI=ASN1.seq([.alg(pqOID),.bits(Data(raw.prefix(n)))])
        let ecSPKI=ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(p.curveOID)]),.bits(Data(raw.dropFirst(n)))])
        return ComponentKeys(pq:try NativeKey(der:pqSPKI.der),ec:try NativeKey(der:ecSPKI.der))
    }
    func spki(_ algorithm: Algorithm) throws -> ASN1 {
        let pqSPKI=try ASN1.parse(pq.export())
        if !algorithm.hybrid {return pqSPKI}
        guard let ec else {throw MailCryptoError.invalid("Missing classical key")}
        return try .seq([.alg(algorithm.oid),.bits(pqSPKI.child(1).bitBytes()+ASN1.parse(ec.export()).child(1).bitBytes())])
    }
    func sign(_ message: Data, _ algorithm: Algorithm) throws -> Data {
        if !algorithm.hybrid {return try pq.sign(message)}
        guard let ec else {throw MailCryptoError.invalid("Missing classical signing key")}
        let domain=Data(("COMPSIG-"+algorithm.profile.hybridSigningName).utf8)
        let representative=try Data("CompositeAlgorithmSignatures2025".utf8)+domain+Data([0])+NativeCrypto.digest(algorithm.profile.compositeHash,message)
        return try pq.sign(representative,context:domain)+ec.sign(representative,digest:algorithm.profile.ecHash)
    }
    func verify(_ sig: Data, _ message: Data, _ algorithm: Algorithm) throws {
        if !algorithm.hybrid {try pq.verify(sig,message:message);return}
        guard let ec else {throw MailCryptoError.invalid("Missing classical signing key")}
        let n=algorithm.profile.signatureBytes
        try require(sig.count>n && sig.count<n+150,"Invalid composite signature length")
        let domain=Data(("COMPSIG-"+algorithm.profile.hybridSigningName).utf8)
        let representative=try Data("CompositeAlgorithmSignatures2025".utf8)+domain+Data([0])+NativeCrypto.digest(algorithm.profile.compositeHash,message)
        try pq.verify(Data(sig.prefix(n)),message:representative,context:domain)
        try ec.verify(Data(sig.dropFirst(n)),message:representative,digest:algorithm.profile.ecHash)
    }
    func encapsulate(_ algorithm: Algorithm) throws -> (Data,Data) {
        let (ct,ss)=try pq.encapsulate()
        if !algorithm.hybrid {return (ct,ss)}
        guard let ec else {throw MailCryptoError.invalid("Missing ECDH key")}
        let ephemeral=try NativeKey(algorithm:"EC",group:algorithm.profile.group)
        let point=try ASN1.parse(ephemeral.export()).child(1).bitBytes()
        let publicPoint=try ASN1.parse(ec.export()).child(1).bitBytes()
        let tradSS=try ephemeral.derive(ec)
        let label=algorithm.profile.mlKEM.replacingOccurrences(of:"-",with:"")+"-"+algorithm.profile.curve.replacingOccurrences(of:"-",with:"")
        return try (ct+point,NativeCrypto.digest("SHA3-256",ss+tradSS+point+publicPoint+Data(label.utf8)))
    }
    func decapsulate(_ ciphertext: Data, _ algorithm: Algorithm) throws -> Data {
        let p=algorithm.profile, n=p.ciphertextBytes
        try require(ciphertext.count==n+(algorithm.hybrid ? p.pointBytes : 0),"Invalid KEM ciphertext length")
        let ss=try pq.decapsulate(Data(ciphertext.prefix(n)))
        if !algorithm.hybrid {return ss}
        guard let ec else {throw MailCryptoError.invalid("Missing ECDH private key")}
        let point=Data(ciphertext.dropFirst(n))
        let peer=try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(p.curveOID)]),.bits(point)]).der)
        let tradSS=try ec.derive(peer)
        let publicPoint=try ASN1.parse(ec.export()).child(1).bitBytes()
        let label=p.mlKEM.replacingOccurrences(of:"-",with:"")+"-"+p.curve.replacingOccurrences(of:"-",with:"")
        return try NativeCrypto.digest("SHA3-256",ss+tradSS+point+publicPoint+Data(label.utf8))
    }
}
