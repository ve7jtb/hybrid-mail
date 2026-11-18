import Foundation

struct MailCertificate: Sendable {
    let asn: ASN1
    let algorithm: Algorithm
    let spki: ASN1
    let issuer: ASN1
    let serial: ASN1
    let email: String
    let keys: ComponentKeys
    var der: Data {asn.der}
    var rid: ASN1 {.seq([issuer,serial])}
    init(_ data: Data, signing: Bool) throws {
        asn=try ASN1.parse(data).expect(0x30,count:3)
        let tbs=try asn.child(0).expect(0x30)
        try require(tbs.children.count>=8 && tbs.children[0].tag==0xa0,"Expected X.509 v3 certificate")
        serial=try tbs.child(1).expect(2);issuer=try tbs.child(3).expect(0x30);spki=try tbs.child(6).expect(0x30,count:2)
        algorithm=try Algorithm.identify(spki.child(0).child(0),signing:signing)
        keys=try ComponentKeys.publicKeys(spki,algorithm)
        let validity=try tbs.child(4).expect(0x30,count:2)
        func date(_ a: ASN1) throws -> Date {
            try require(a.tag==23 || a.tag==24,"Invalid certificate time")
            let f=DateFormatter();f.locale=Locale(identifier:"en_US_POSIX");f.timeZone=TimeZone(secondsFromGMT:0);f.dateFormat=a.tag==23 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'";f.isLenient=false
            guard let value=String(data:a.value,encoding:.ascii),let d=f.date(from:value) else {throw MailCryptoError.invalid("Invalid certificate time")};return d
        }
        let now=Date();try require(try date(validity.child(0))<=now && date(validity.child(1))>=now,"Certificate is expired or not yet valid")
        guard let ex=tbs.children.first(where:{$0.tag==0xa3}) else {throw MailCryptoError.invalid("Certificate extensions missing")}
        var addresses:[String]=[];var purpose=false;var eku=false;var seen=Set<Data>()
        for e in try ex.child(0).expect(0x30).children {
            try require(e.tag==0x30 && (e.children.count==2 || e.children.count==3),"Invalid certificate extension")
            let oid=try e.child(0);try require(seen.insert(oid.der).inserted,"Duplicate certificate extension")
            let critical=e.children.count==3 && e.children[1].value==Data([255])
            let content=try ASN1.parse(e.children.last!.octets())
            if oid.isOID("2.5.29.17") { for a in content.children where a.tag==0x81 {if let s=String(data:a.value,encoding:.ascii){addresses.append(s)}} }
            else if oid.isOID("2.5.29.15") { try require(content.tag==3 && content.value.count>=2,"Invalid key usage");purpose=content.value[1] & (signing ? 0x80 : 0x20) != 0 }
            else if oid.isOID("2.5.29.37") {eku=content.children.contains{$0.isOID("1.3.6.1.5.5.7.3.4")}}
            else if oid.isOID("2.5.29.19") {try require(content.children.isEmpty || content.children.first?.value==Data([0]),"CA certificates are not mail identities")}
            else {try require(!critical,"Unsupported critical certificate extension")}
        }
        try require(purpose && eku && !addresses.isEmpty,"Certificate must permit email protection and the requested key use")
        email=addresses[0]
    }
}

/// Software identity. Persistence uses encrypted PKCS#12; unencrypted keys stay in memory.
/// Each instance creates four independent keys; pure and hybrid use the same keys.
public final class SoftwareMailIdentity {
    public let profile: Profile
    public let email: String
    let signingKeys: ComponentKeys
    let encryptionKeys: ComponentKeys
    private var certificates: [Bool:(MailCertificate,MailCertificate)] = [:]
    public init(profile: Profile, email: String) throws {
        try Self.validateEmail(email)
        self.profile=profile;self.email=email
        signingKeys=ComponentKeys(pq:try NativeKey(algorithm:profile.mlDSA),ec:try NativeKey(algorithm:"EC",group:profile.group))
        encryptionKeys=ComponentKeys(pq:try NativeKey(algorithm:profile.mlKEM),ec:try NativeKey(algorithm:"EC",group:profile.group))
        for hybrid in [false,true] { certificates[hybrid]=try makeCertificates(hybrid) }
    }
    init(profile: Profile,email: String, signingKeys: ComponentKeys,encryptionKeys: ComponentKeys,hybrid: Bool,signingCertificate: Data,encryptionCertificate: Data) throws {
        self.profile=profile;self.email=email;self.signingKeys=signingKeys;self.encryptionKeys=encryptionKeys
        certificates[hybrid]=(try MailCertificate(signingCertificate,signing:true),try MailCertificate(encryptionCertificate,signing:false))
    }
    static func validateEmail(_ email: String) throws {
        try require(email.count<=254 && email.utf8.allSatisfy { $0 > 32 && $0 < 127 } && email.range(of:"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",options:.regularExpression) != nil,"Enter a plain ASCII email address")
    }
    func certs(_ hybrid: Bool) throws -> (MailCertificate,MailCertificate) {guard let c=certificates[hybrid] else {throw MailCryptoError.invalid("This identity does not contain that profile")};return c}
    public var availableModes: [Bool] { [false,true].filter{certificates[$0] != nil} }
    func addCertificates(signing: Data,encryption: Data) throws {
        let s=try MailCertificate(signing,signing:true),e=try MailCertificate(encryption,signing:false)
        try require(s.algorithm.profile==profile && s.algorithm.hybrid==e.algorithm.hybrid && s.email==email && e.email==email,"Certificate profile mismatch")
        certificates[s.algorithm.hybrid]=(s,e)
    }
    public func signingCertificate(hybrid: Bool) throws -> Data {try certs(hybrid).0.der}
    public func encryptionCertificate(hybrid: Bool) throws -> Data {try certs(hybrid).1.der}
    private func makeCertificates(_ hybrid: Bool) throws -> (MailCertificate,MailCertificate) {
        let signing=Algorithm(profile:profile,hybrid:hybrid,signing:true)
        let name=ASN1.seq([.set([.seq([.oid("2.5.4.3"),ASN1(12,Data(email.utf8))])])])
        func make(_ isSigning: Bool) throws -> MailCertificate {
            let algorithm=Algorithm(profile:profile,hybrid:hybrid,signing:isSigning)
            let keys=isSigning ? signingKeys : encryptionKeys
            let f=DateFormatter();f.locale=Locale(identifier:"en_US_POSIX");f.timeZone=TimeZone(secondsFromGMT:0);f.dateFormat="yyMMddHHmmss'Z'"
            let validity=ASN1.seq([ASN1(23,Data(f.string(from:Date().addingTimeInterval(-300)).utf8)),ASN1(23,Data(f.string(from:Date().addingTimeInterval(86400*365)).utf8))])
            func ext(_ oid: String,_ value: ASN1, critical: Bool = false) -> ASN1 {.seq([.oid(oid)]+(critical ? [ASN1(1,Data([255]))] : [])+[ASN1(4,value.der)])}
            let extensions=ASN1(0xa3,children:[.seq([
                ext("2.5.29.19",.seq([]),critical:true),
                ext("2.5.29.15",ASN1(3,Data([isSigning ? 7 : 5,isSigning ? 0x80 : 0x20])),critical:true),
                ext("2.5.29.37",.seq([.oid("1.3.6.1.5.5.7.3.4")])),
                ext("2.5.29.17",.seq([ASN1(0x81,Data(email.utf8))]))])])
            let serial=ASN1(2,try Data([1])+NativeCrypto.random(15))
            let tbs=try ASN1.seq([ASN1(0xa0,children:[.int(2)]),serial,.alg(signing.oid),name,validity,name,keys.spki(algorithm),extensions])
            let cert=try ASN1.seq([tbs,.alg(signing.oid),.bits(signingKeys.sign(tbs.der,signing))])
            return try MailCertificate(cert.der,signing:isSigning)
        }
        return try (make(true),make(false))
    }
}
