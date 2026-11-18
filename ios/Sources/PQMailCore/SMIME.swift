import Foundation

private let dataOID="1.2.840.113549.1.7.1"
private let signedOID="1.2.840.113549.1.7.2"
private let authEnvelopeOID="1.2.840.113549.1.9.16.1.23"
private let kemRecipientOID="1.2.840.113549.1.9.16.13.3"
private let hkdfOID="1.2.840.113549.1.9.16.3.28"
private let wrapOID="2.16.840.1.101.3.4.1.45"
private let gcmOID="2.16.840.1.101.3.4.1.46"

public struct OpenedMail: Sendable {
    public let text: String
    public let encrypted: Bool
    public let algorithm: String
    public let signerEmail: String
    public let fingerprint: String
    public let fromMatches: Bool
}
struct MIMEPart {
    let headers: [String:String]
    let body: Data
    init(_ input: Data) throws {
        try require(input.count<=20*1024*1024,"Message exceeds 20 MiB")
        guard let split=input.range(of:Data("\r\n\r\n".utf8)) ?? input.range(of:Data("\n\n".utf8)), split.lowerBound<65536,
              let h=String(data:input[..<split.lowerBound],encoding:.utf8) else {throw MailCryptoError.invalid("Invalid MIME headers")}
        var lines:[String]=[]
        for line in h.replacingOccurrences(of:"\r\n",with:"\n").components(separatedBy:"\n") {
            if line.first==" " || line.first=="\t" {try require(!lines.isEmpty,"Invalid MIME folding");lines[lines.count-1]+=" "+line.trimmingCharacters(in:.whitespaces)} else {lines.append(line)}
        }
        var result:[String:String]=[:]
        for line in lines {
            guard let colon=line.firstIndex(of:":") else {throw MailCryptoError.invalid("Malformed MIME header")}
            let key=String(line[..<colon]).lowercased(), val=String(line[line.index(after:colon)...]).trimmingCharacters(in:.whitespaces)
            if ["content-type","content-transfer-encoding","from"].contains(key) {try require(result[key]==nil,"Ambiguous MIME header")}
            result[key]=val
        }
        headers=result;body=Data(input[split.upperBound...])
    }
    func decoded() throws -> Data {
        switch headers["content-transfer-encoding",default:"7bit"].lowercased() {
        case "base64":
            let bytes=body.filter{![9,10,13,32].contains($0)}
            guard let data=Data(base64Encoded:bytes) else {throw MailCryptoError.invalid("Invalid MIME base64")};return data
        case "7bit","8bit","binary":return body
        case "quoted-printable":
            let b=[UInt8](body);var out=Data(),i=0
            while i<b.count {
                if b[i]==61 {
                    if i+2<b.count && b[i+1]==13 && b[i+2]==10 {i+=3;continue}
                    if i+1<b.count && b[i+1]==10 {i+=2;continue}
                    try require(i+2<b.count,"Invalid quoted-printable")
                    guard let n=UInt8(String(bytes:b[(i+1)...(i+2)],encoding:.ascii) ?? "",radix:16) else {throw MailCryptoError.invalid("Invalid quoted-printable")};out.append(n);i+=3
                } else {out.append(b[i]);i+=1}
            };return out
        default:throw MailCryptoError.invalid("Unsupported MIME transfer encoding")
        }
    }
}
public enum SMIME {
    private static func digest(_ a: Algorithm) -> (String,String) {
        a.hybrid && a.profile == .level2 ? ("SHA256","2.16.840.1.101.3.4.2.1") : ("SHA512","2.16.840.1.101.3.4.2.3")
    }
    static func signingAttributes(_ content: Data, _ algorithm: Algorithm) throws -> ASN1 {
        let (hash,_)=digest(algorithm)
        return try ASN1.set([
            .seq([.oid("1.2.840.113549.1.9.3"),.set([.oid(dataOID)])]),
            .seq([.oid("1.2.840.113549.1.9.4"),.set([ASN1(4,NativeCrypto.digest(hash,content))])])])
    }
    static func signCMS(_ content: Data, identity: SoftwareMailIdentity, hybrid: Bool) throws -> Data {
        let cert=try identity.certs(hybrid).0
        return try signCMS(content,certificate:cert) {try identity.signingKeys.sign($0,cert.algorithm)}
    }
    static func signCMS(_ content: Data, certificate cert: MailCertificate, signer: (Data) throws -> Data) throws -> Data {
        let (_,hashOID)=digest(cert.algorithm),attrs=try signingAttributes(content,cert.algorithm)
        let signature=try signer(attrs.der)
        try cert.keys.verify(signature,attrs.der,cert.algorithm)
        let si=ASN1.seq([.int(1),cert.rid,.alg(hashOID),ASN1(0xa0,children:attrs.children),.alg(cert.algorithm.oid),ASN1(4,signature)])
        let sd=ASN1.seq([.int(1),.set([.alg(hashOID)]),.seq([.oid(dataOID),ASN1(0xa0,children:[ASN1(4,content)])]),ASN1(0xa0,children:[cert.asn]),.set([si])])
        return ASN1.seq([.oid(signedOID),ASN1(0xa0,children:[sd])]).der
    }
    static func verifyCMS(_ cms: Data) throws -> (Data,MailCertificate) {
        let ci=try ASN1.parse(cms).expect(0x30,count:2)
        try require(try ci.child(0).isOID(signedOID),"Expected CMS SignedData")
        let sd=try ci.child(1).child(0).expect(0x30,count:5)
        try require(try sd.child(0).number()==1,"Unsupported SignedData version")
        let eci=try sd.child(2).expect(0x30,count:2)
        try require(try eci.child(0).isOID(dataOID),"Unsupported signed content type")
        let content=try eci.child(1).child(0).octets()
        let certs=try sd.child(3).expect(0xa0,count:1)
        let cert=try MailCertificate(certs.child(0).der,signing:true)
        let signers=try sd.child(4).expect(0x31,count:1)
        let si=try signers.child(0).expect(0x30)
        try require(si.children.count==6 || si.children.count==7,"Invalid SignerInfo")
        try require(try si.child(0).number()==1 && si.child(1).der==cert.rid.der,"Signer certificate identifier mismatch")
        let (hash,hashOID)=digest(cert.algorithm)
        let digAlg=try si.child(2).expect(0x30)
        try require(try digAlg.child(0).isOID(hashOID),"Unexpected CMS digest algorithm")
        let digestSet=try sd.child(1).expect(0x31,count:1)
        try require(try digestSet.child(0).der==digAlg.der,"Digest algorithm set mismatch")
        try require(try si.child(4).der==ASN1.alg(cert.algorithm.oid).der,"Signature algorithm mismatch")
        let attrs=try si.child(3).expect(0xa0)
        var seen=Set<Data>();var md:Data?,ct:ASN1?
        for attr in attrs.children {
            _ = try attr.expect(0x30,count:2)
            let oid=try attr.child(0)
            try require(seen.insert(oid.der).inserted,"Duplicate signed attribute")
            if oid.isOID("1.2.840.113549.1.9.3") {ct=try attr.child(1).expect(0x31,count:1).child(0)}
            if oid.isOID("1.2.840.113549.1.9.4") {md=try attr.child(1).expect(0x31,count:1).child(0).octets()}
            if oid.isOID("1.2.840.113549.1.9.52") {
                let protection=try attr.child(1).expect(0x31,count:1).child(0).expect(0x30,count:2)
                try require(try protection.child(0).der==digAlg.der && ASN1(0x30,children:protection.child(1).children).der==ASN1.alg(cert.algorithm.oid).der,"CMS algorithm protection mismatch")
            }
        }
        try require(ct?.isOID(dataOID)==true && md == (try NativeCrypto.digest(hash,content)),"Signed content digest mismatch")
        try cert.keys.verify(si.child(5).octets(),ASN1.set(attrs.children).der,cert.algorithm)
        return (content,cert)
    }
    static func encryptCMS(_ content: Data, recipient: MailCertificate) throws -> Data {
        let (ct,secret)=try recipient.keys.encapsulate(recipient.algorithm)
        let otherInfo=ASN1.seq([.alg(wrapOID),.int(32)])
        let kek=try NativeCrypto.hkdf(secret,otherInfo.der)
        let cek=try NativeCrypto.random(32),nonce=try NativeCrypto.random(12)
        let wrapped=try NativeCrypto.wrap(true,kek,cek)
        let kri=ASN1.seq([.int(0),recipient.rid,.alg(recipient.algorithm.oid),ASN1(4,ct),.alg(hkdfOID),.int(32),.alg(wrapOID),ASN1(4,wrapped)])
        let recipientInfo=ASN1(0xa4,children:[.oid(kemRecipientOID),kri])
        let sealed=try NativeCrypto.gcm(true,cek,nonce,content)
        let eci=ASN1.seq([.oid(dataOID),.seq([.oid(gcmOID),.seq([ASN1(4,nonce),.int(16)])]),ASN1(0x80,Data(sealed.dropLast(16)))])
        let env=ASN1.seq([.int(0),.set([recipientInfo]),eci,ASN1(4,Data(sealed.suffix(16)))])
        return ASN1.seq([.oid(authEnvelopeOID),ASN1(0xa0,children:[env])]).der
    }
    static func decryptCMS(_ cms: Data, identity: SoftwareMailIdentity, hybrid: Bool) throws -> Data {
        let cert=try identity.certs(hybrid).1
        return try decryptCMS(cms,certificate:cert) {try identity.encryptionKeys.decapsulate($0,cert.algorithm)}
    }
    static func decryptCMS(_ cms: Data, certificate cert: MailCertificate, recover: (Data) throws -> Data) throws -> Data {
        let ci=try ASN1.parse(cms).expect(0x30,count:2)
        try require(try ci.child(0).isOID(authEnvelopeOID),"Expected CMS AuthEnvelopedData")
        let env=try ci.child(1).child(0).expect(0x30)
        try require(env.children.count==4 || env.children.count==5,"Unsupported envelope fields")
        try require(try env.child(0).number()==0,"Invalid envelope version")
        let ri=try env.child(1).expect(0x31,count:1).child(0).expect(0xa4,count:2)
        try require(try ri.child(0).isOID(kemRecipientOID),"Unsupported recipient type")
        let kri=try ri.child(1).expect(0x30)
        try require(kri.children.count==8 || kri.children.count==9,"Invalid KEM recipient info")
        try require(try kri.child(0).number()==0 && kri.child(1).der==cert.rid.der,"Identity is not the recipient")
        try require(try kri.child(2).der==ASN1.alg(cert.algorithm.oid).der && kri.child(4).der==ASN1.alg(hkdfOID).der && kri.child(5).number()==32,"Unsupported KEM/KDF parameters")
        let hasUKM=kri.children.count==9;let wrapIndex=hasUKM ? 7 : 6
        try require(try kri.child(wrapIndex).der==ASN1.alg(wrapOID).der,"Unsupported key wrapping")
        let ukm: [ASN1]
        if hasUKM { let u=try kri.child(6).expect(0xa0,count:1);_ = try u.child(0).expect(4);ukm=[u] } else { ukm=[] }
        let otherInfo=ASN1.seq([.alg(wrapOID),.int(32)]+ukm)
        let eci=try env.child(2).expect(0x30,count:3)
        try require(try eci.child(0).isOID(dataOID),"Unsupported encrypted content type")
        let alg=try eci.child(1).expect(0x30,count:2)
        try require(try alg.child(0).isOID(gcmOID),"Expected AES-256-GCM")
        let params=try alg.child(1).expect(0x30,count:2)
        try require(try params.child(1).number()==16,"Expected 128-bit GCM tag")
        var aad=Data();let macIndex:Int
        if env.children.count==5 {
            let attrs=try env.child(3).expect(0xa1)
            var seen=Set<Data>();var contentType=false
            for attr in attrs.children {
                _ = try attr.expect(0x30,count:2)
                let oid=try attr.child(0);try require(seen.insert(oid.der).inserted,"Duplicate authenticated attribute")
                if oid.isOID("1.2.840.113549.1.9.3") {
                    contentType=try attr.child(1).expect(0x31,count:1).child(0).isOID(dataOID)
                }
            }
            try require(contentType,"Authenticated content type missing or mismatched")
            aad=ASN1.set(attrs.children).der;macIndex=4
        } else {macIndex=3}
        let mac=try env.child(macIndex).octets();try require(mac.count==16,"Invalid GCM tag")
        let nonce=try params.child(0).octets(),ciphertext=try eci.child(2).octets()
        try require(nonce.count==12,"Invalid GCM nonce")
        let encapsulation=try kri.child(3).octets(),wrapped=try kri.child(wrapIndex+1).octets()
        try require(wrapped.count==40,"Invalid wrapped content-key length")
        let secret=try recover(encapsulation)
        let kek=try NativeCrypto.hkdf(secret,otherInfo.der)
        let cek=try NativeCrypto.wrap(false,kek,wrapped)
        return try NativeCrypto.gcm(false,cek,nonce,ciphertext+mac,aad:aad)
    }
    static func mime(_ cms: Data, encrypted: Bool) -> Data {
        let headers="MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=\(encrypted ? "authEnveloped-data" : "signed-data"); name=smime.p7m\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=smime.p7m\r\n\r\n"
        return Data((headers+cms.base64EncodedString(options:[.lineLength64Characters,.endLineWithCarriageReturn,.endLineWithLineFeed])+"\r\n").utf8)
    }
    public static func compose(identity: SoftwareMailIdentity, hybrid: Bool, to: String, subject: String, text: String, recipientCertificate: Data? = nil) throws -> Data {
        let cert=try identity.certs(hybrid).0
        return try compose(certificate:cert,to:to,subject:subject,text:text,recipientCertificate:recipientCertificate) {try identity.signingKeys.sign($0,cert.algorithm)}
    }
    static func plain(_ text: String) throws -> Data {
        try require(text.utf8.count<=5*1024*1024,"Body exceeds 5 MiB")
        return Data(("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"+Data(text.utf8).base64EncodedString(options:[.lineLength64Characters,.endLineWithCarriageReturn,.endLineWithLineFeed])+"\r\n").utf8)
    }
    static func compose(certificate: MailCertificate, to: String, subject: String, text: String, recipientCertificate: Data?, signer: (Data) throws -> Data) throws -> Data {
        try SoftwareMailIdentity.validateEmail(to)
        try require(!subject.utf8.contains(13) && !subject.utf8.contains(10) && subject.count<=500,"Invalid subject")
        try require(text.utf8.count<=5*1024*1024,"Body exceeds 5 MiB")
        let content=try plain(text)
        var part=mime(try signCMS(content,certificate:certificate,signer:signer),encrypted:false)
        if let recipientCertificate {
            let recipient=try MailCertificate(recipientCertificate,signing:false)
            try require(recipient.email.caseInsensitiveCompare(to) == .orderedSame,"Recipient email does not match certificate")
            part=mime(try encryptCMS(part,recipient:recipient),encrypted:true)
        }
        let encodedSubject="=?UTF-8?B?"+Data(subject.utf8).base64EncodedString()+"?="
        let outer=Data("From: \(certificate.email)\r\nTo: \(to)\r\nSubject: \(encodedSubject)\r\n".utf8)+part
        try require(outer.count<=20*1024*1024,"Message exceeds 20 MiB");return outer
    }
    public static func open(_ eml: Data, identity: SoftwareMailIdentity? = nil, hybrid: Bool = false) throws -> OpenedMail {
        try open(eml) {cms in
            guard let identity else {throw MailCryptoError.invalid("Load the matching identity to decrypt")}
            return try decryptCMS(cms,identity:identity,hybrid:hybrid)
        }
    }
    static func open(_ eml: Data, decrypt: (Data) throws -> Data) throws -> OpenedMail {
        let outer=try MIMEPart(eml);var part=outer
        var cms=try part.decoded();let ci=try ASN1.parse(cms).expect(0x30,count:2)
        let encrypted=try ci.child(0).isOID(authEnvelopeOID)
        if encrypted {
            part=try MIMEPart(decrypt(cms));cms=try part.decoded()
        }
        let (signedContent,cert)=try verifyCMS(cms)
        let plain=try MIMEPart(signedContent)
        try require(plain.headers["content-type",default:"text/plain"].lowercased().hasPrefix("text/plain"),"This iOS preview opens signed plain-text bodies only")
        guard let text=String(data:try plain.decoded(),encoding:.utf8) else {throw MailCryptoError.invalid("Invalid UTF-8 message")}
        return OpenedMail(text:text,encrypted:encrypted,algorithm:cert.algorithm.hybrid ? cert.algorithm.profile.hybridSigningName : cert.algorithm.profile.mlDSA,signerEmail:cert.email,fingerprint:try NativeCrypto.digest("SHA256",cert.der).hex,fromMatches:outer.headers["from"]?.caseInsensitiveCompare(cert.email) == .orderedSame)
    }
}
