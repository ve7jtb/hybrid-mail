import Foundation

public struct YubiKeyCredential: Codable, Sendable {
    public let serial: UInt
    public let signingSlot: UInt8, traditionalSlot: UInt8, kemSlot: UInt8, ecdhSlot: UInt8
    public let signingDER: Data, encryptionDER: Data
    public var label: String { get throws {let s=try MailCertificate(signingDER,signing:true);return "\(s.email) · \(s.algorithm.hybrid ? s.algorithm.profile.hybridSigningName : s.algorithm.profile.mlDSA) · YubiKey \(serial)"} }
    func validated() throws -> (MailCertificate,MailCertificate) {
        try require(serial>0 && serial<=UInt(UInt32.max),"Invalid YubiKey serial")
        _ = try SlotMap(mlDSA:signingSlot,ecdsa:traditionalSlot,mlKEM:kemSlot,ecdh:ecdhSlot)
        let s=try MailCertificate(signingDER,signing:true),e=try MailCertificate(encryptionDER,signing:false)
        try require(s.email==e.email && s.algorithm.hybrid==e.algorithm.hybrid && e.algorithm.oid==Algorithm(profile:s.algorithm.profile,hybrid:s.algorithm.hybrid,signing:false).oid,"Token certificate profiles do not match")
        return (s,e)
    }
    public static func importBundle(_ data: Data) throws -> [YubiKeyCredential] {
        try require(data.count<=512*1024,"Certificate bundle exceeds 512 KiB")
        guard let text=String(data:data,encoding:.utf8) else {throw MailCryptoError.invalid("Invalid certificate bundle")}
        var fields:[String:String]=[:]
        for raw in text.components(separatedBy:.newlines) {
            let line=raw.trimmingCharacters(in:.whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") {continue}
            guard let eq=line.firstIndex(of:"=") else {throw MailCryptoError.invalid("Malformed certificate bundle field")}
            let key=String(line[..<eq]), value=String(line[line.index(after:eq)...])
            try require(fields[key]==nil,"Duplicate certificate bundle field")
            // Properties.store escapes '=' and ':' in base64 values.
            fields[key]=value.replacingOccurrences(of:"\\=",with:"=").replacingOccurrences(of:"\\:",with:":").replacingOccurrences(of:"\\\\",with:"\\")
        }
        try require(fields["format"]=="pq-mail-certificates" && fields["version"]=="1" && fields["purpose",default:"device"]=="device","Import your own YubiKey setup bundle, not a contact-only bundle")
        guard let count=Int(fields["count"] ?? ""), (1...16).contains(count) else {throw MailCryptoError.invalid("Invalid bundle profile count")}
        try require(fields.count==3+(fields["purpose"]==nil ? 0 : 1)+count*7,"Unexpected certificate bundle fields")
        var result:[YubiKeyCredential]=[]
        for i in 0..<count {
            let p="profile.\(i)."
            func slot(_ name:String) throws -> UInt8 {guard let s=fields[p+name],let v=UInt8(s,radix:16) else {throw MailCryptoError.invalid("Invalid slot mapping")};return v}
            guard let serial=UInt(fields[p+"serial"] ?? ""),let s=Data(base64Encoded:fields[p+"signingCertificate"] ?? ""),let e=Data(base64Encoded:fields[p+"encryptionCertificate"] ?? "") else {throw MailCryptoError.invalid("Invalid token bundle")}
            let c=try YubiKeyCredential(serial:serial,signingSlot:slot("signingSlot"),traditionalSlot:slot("traditionalSlot"),kemSlot:slot("kemSlot"),ecdhSlot:slot("ecdhSlot"),signingDER:s,encryptionDER:e)
            _ = try c.validated();try require(!result.contains{$0.signingDER==s && $0.encryptionDER==e},"Duplicate token certificate profile");result.append(c)
        };return result
    }
    public var review: String {get throws {
        let (s,e)=try validated()
        return "\(try label)\nSlots: ML-DSA \(String(signingSlot,radix:16)), ECDSA \(String(traditionalSlot,radix:16)), ML-KEM \(String(kemSlot,radix:16)), ECDH \(String(ecdhSlot,radix:16))\nSigning SHA-256: \(try NativeCrypto.digest("SHA256",s.der).hex)\nEncryption SHA-256: \(try NativeCrypto.digest("SHA256",e.der).hex)\nPublic certificates only. Serial and public keys will be checked before PIN submission. Import does not grant trust to incoming mail."
    }}
}
