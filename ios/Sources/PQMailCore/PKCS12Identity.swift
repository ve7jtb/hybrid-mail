import Foundation
import CNative

extension ComponentKeys {
    func privateDER(_ a: Algorithm) throws -> Data {
        if !a.hybrid {return try pq.export(privateKey:true)}
        guard let ec else {throw MailCryptoError.invalid("Missing EC private key")}
        var seed=try take(pq_key_seed(pq.handle));defer {seed.resetBytes(in:0..<seed.count)}
        try require(seed.count==(a.signing ? 32 : 64),"Unexpected PQ seed size")
        let ecPrivate=try ASN1.parse(ec.export(privateKey:true)).child(2).octets()
        let sec1=try ASN1.parse(ecPrivate).expect(0x30)
        let inner=ASN1.seq(sec1.children.filter{$0.tag != 0xa1})
        return ASN1.seq([.int(0),.alg(a.oid),ASN1(4,seed+inner.der)]).der
    }
    static func privateKeys(_ der: Data,_ a: Algorithm) throws -> ComponentKeys {
        let p8=try ASN1.parse(der).expect(0x30)
        try require(try p8.child(1).child(0).isOID(a.oid),"Private key profile mismatch")
        if !a.hybrid {return ComponentKeys(pq:try NativeKey(der:der,privateKey:true),ec:nil)}
        let payload=try p8.child(2).octets(),n=a.signing ? 32 : 64
        try require(payload.count>n,"Invalid composite private key")
        let pureOID=a.signing ? a.profile.pureSigningOID : a.profile.pureEncryptionOID
        let pure=ASN1.seq([.int(0),.alg(pureOID),ASN1(4,ASN1(0x80,Data(payload.prefix(n))).der)])
        let ec=ASN1.seq([.int(0),.seq([.oid("1.2.840.10045.2.1"),.oid(a.profile.curveOID)]),ASN1(4,Data(payload.dropFirst(n)))])
        return ComponentKeys(pq:try NativeKey(der:pure.der,privateKey:true),ec:try NativeKey(der:ec.der,privateKey:true))
    }
}
struct P12Bag {
    let type: UInt8
    let name: String
    let data: Data
    static func encode(_ bags: [P12Bag]) throws -> Data {
        var out=Data()
        for b in bags {
            let name=Data(b.name.utf8),n=b.data.count
            try require(name.count<=255 && n<=131072,"Identity bag too large")
            out.append(contentsOf:[b.type,0,UInt8(name.count),UInt8((n>>24)&255),UInt8((n>>16)&255),UInt8((n>>8)&255),UInt8(n&255)])
            out.append(name);out.append(b.data)
        };return out
    }
    static func decode(_ data: Data) throws -> [P12Bag] {
        let b=[UInt8](data);var i=0,out:[P12Bag]=[]
        while i<b.count {
            try require(i+7<=b.count && out.count<32,"Invalid identity bags")
            let type=b[i],nn=Int(b[i+1])*256+Int(b[i+2]),dn=(Int(b[i+3])<<24)|(Int(b[i+4])<<16)|(Int(b[i+5])<<8)|Int(b[i+6]);i+=7
            try require(nn>0 && nn<=255 && dn<=131072 && nn+dn<=b.count-i,"Invalid identity bag length")
            guard let name=String(bytes:b[i..<i+nn],encoding:.utf8) else {throw MailCryptoError.invalid("Invalid identity alias")};i+=nn
            try require(!out.contains{$0.type==type && $0.name==name},"Duplicate identity alias")
            out.append(P12Bag(type:type,name:name,data:Data(b[i..<i+dn])));i+=dn
        };return out
    }
}
extension SoftwareMailIdentity {
    public func pkcs12(password: String) throws -> Data {
        try require(password.count>=12 && password.utf8.count<=1024 && !password.utf8.contains(0),"Use a 12–1024 character identity password")
        var bags:[P12Bag]=[]
        for h in availableModes {
            let cert=try certs(h),prefix=h || availableModes.count==1 ? "" : "pure-"
            for (name,c,k) in [("sign",cert.0,signingKeys),("encrypt",cert.1,encryptionKeys)] {
                bags.append(P12Bag(type:1,name:prefix+name,data:try k.privateDER(c.algorithm)))
                bags.append(P12Bag(type:2,name:prefix+name,data:c.der))
            }
        }
        var data=try P12Bag.encode(bags);defer {data.resetBytes(in:0..<data.count)}
        return try data.bytes {p in try password.withCString {try take(pq_p12_pack(p,data.count,$0))}}
    }
    public static func loadPKCS12(_ data: Data,password: String) throws -> SoftwareMailIdentity {
        try require(data.count<=1024*1024 && !password.isEmpty && password.utf8.count<=1024 && !password.utf8.contains(0),"Invalid identity file or password length")
        var raw:Data
        do {raw=try data.bytes {p in try password.withCString {try take(pq_p12_unpack(p,data.count,$0))}}} catch {throw MailCryptoError.invalid("Cannot unlock .p12: wrong password, damaged file, unsupported protection, or missing key/certificate aliases")}
        defer {raw.resetBytes(in:0..<raw.count)}
        let bags=try P12Bag.decode(raw)
        func find(_ name:String,_ type:UInt8) throws -> Data {guard let b=bags.first(where:{$0.name==name && $0.type==type}) else {throw MailCryptoError.invalid("Missing \(name) key/certificate in .p12")};return b.data}
        let s=try MailCertificate(find("sign",2),signing:true),e=try MailCertificate(find("encrypt",2),signing:false)
        let sk=try ComponentKeys.privateKeys(find("sign",1),s.algorithm),ek=try ComponentKeys.privateKeys(find("encrypt",1),e.algorithm)
        let id=try SoftwareMailIdentity(profile:s.algorithm.profile,email:s.email,signingKeys:sk,encryptionKeys:ek,hybrid:s.algorithm.hybrid,signingCertificate:s.der,encryptionCertificate:e.der)
        if bags.contains(where:{$0.name=="pure-sign"}) {
            let sc=try MailCertificate(find("pure-sign",2),signing:true),ec=try MailCertificate(find("pure-encrypt",2),signing:false)
            let pureS=try ComponentKeys.privateKeys(find("pure-sign",1),sc.algorithm),pureE=try ComponentKeys.privateKeys(find("pure-encrypt",1),ec.algorithm)
            try require(try pureS.spki(sc.algorithm).der==sc.spki.der && pureE.spki(ec.algorithm).der==ec.spki.der,"Pure private keys do not match certificates")
            try id.addCertificates(signing:sc.der,encryption:ec.der)
        }
        for h in id.availableModes {
            let (sc,ec)=try id.certs(h)
            try require(sc.email==ec.email && sc.email==id.email && sc.algorithm.hybrid==ec.algorithm.hybrid,"Certificate profile/email mismatch")
            try require(try sk.spki(sc.algorithm).der==sc.spki.der && ek.spki(ec.algorithm).der==ec.spki.der,"Private keys do not match certificates")
        }
        return id
    }
}
