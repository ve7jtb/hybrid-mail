import Foundation

/// Same big-endian, length-delimited public format as the desktop/Android core.
public struct OnKeyBundle: Sendable {
    public private(set) var recoveredMigration=false
    public private(set) var credentials:[YubiKeyCredential]
    let pgp:[Data]
    let signer:Int
    let encoded:Data
    public var review:String {get throws {(recoveredMigration ? "Recovered migration: signed bundle says 9a; matching key is now in 83. Import updates the mapping; save the bundle again.\n":"") + (try credentials.map{try $0.review}.joined(separator:"\n\n")+"\nVerified bundle signature; no automatic trust. OpenPGP identities: \(pgp.filter{!$0.isEmpty}.count)")}}
    static func number(_ n:Int,_ width:Int=4)->Data {Data((0..<width).reversed().map{UInt8((UInt64(n)>>($0*8))&255)})}
    static func blob(_ d:Data)->Data {number(d.count)+d}
    struct Reader {
        let data:Data;var offset=0
        mutating func take(_ n:Int)throws->Data {try require(n>=0 && n<=data.count-offset,"Invalid on-key field length");defer{offset+=n};return data.subdata(in:offset..<offset+n)}
        mutating func number(_ n:Int=4)throws->Int {let d=try take(n);var v:UInt64=0;for b in d{v=(v<<8)|UInt64(b)};try require(v<=UInt64(Int.max),"On-key integer overflow");return Int(v)}
        mutating func blob()throws->Data {let n=try number();try require(n<=65536,"On-key field too large");return try take(n)}
        mutating func magic(_ s:String)throws{try require(try take(8)==Data(s.utf8),"Unsupported on-key format")}
        var done:Bool{offset==data.count}
    }
    static func validatePGP(_ data:Data,_ c:YubiKeyCredential)throws {
        if data.isEmpty{return}
        let own=try PGP.PublicIdentity(data),(s,e)=try c.validated()
        try require(s.algorithm.profile == .level3 && s.algorithm.hybrid,"Unsupported OpenPGP profile")
        try require(try own.email==s.email && PGP.raw(own.signing.pq)==PGP.raw(s.keys.pq) && PGP.raw(own.signing.ec!)==PGP.raw(s.keys.ec!) && PGP.raw(own.encryption.pq)==PGP.raw(e.keys.pq) && PGP.raw(own.encryption.ec!)==PGP.raw(e.keys.ec!),"OpenPGP keys do not match certificates")
    }
    static func payload(_ credentials:[YubiKeyCredential],_ pgp:[Data])throws->Data {
        try require((1...16).contains(credentials.count) && credentials.count==pgp.count,"Invalid profile count")
        let first=try credentials[0].validated()
        try require(credentials.contains{(try? $0.validated().0.algorithm.hybrid)==true} && credentials.contains{(try? $0.validated().0.algorithm.hybrid)==false},"Save both pure and hybrid profiles")
        for c in credentials{let (s,e)=try c.validated();try require(try s.keys.pq.export()==first.0.keys.pq.export() && e.keys.pq.export()==first.1.keys.pq.export() && c.signingSlot==credentials[0].signingSlot && c.traditionalSlot==credentials[0].traditionalSlot && c.kemSlot==credentials[0].kemSlot && c.ecdhSlot==credentials[0].ecdhSlot,"Inconsistent profile keys/slots")}
        var out=Data("PQMAILB1".utf8)+number(credentials.count),seen=Set<Data>()
        for (i,c) in credentials.enumerated(){_ = try c.validated();try require(c.serial==credentials[0].serial,"Mixed YubiKey serials");try require(seen.insert(c.signingDER+c.encryptionDER).inserted,"Duplicate profile");try validatePGP(pgp[i],c)
            out += number(Int(c.serial))+Data([c.signingSlot,c.traditionalSlot,c.kemSlot,c.ecdhSlot])+blob(c.signingDER)+blob(c.encryptionDER)+blob(pgp[i])
        };try require(out.count<65536,"On-key bundle too large");return out
    }
    public init(_ data:Data)throws {
        try require(data.count<=65536,"On-key bundle exceeds 64 KiB");var r=Reader(data:data);try r.magic("PQMAILS1");let body=try r.blob(),signer=try r.number(),signature=try r.blob();try require(r.done,"Trailing bundle bytes")
        var p=Reader(data:body);try p.magic("PQMAILB1");let count=try p.number();try require((1...16).contains(count) && (0..<count).contains(signer),"Invalid profile count/signer")
        var cs:[YubiKeyCredential]=[],pgps:[Data]=[]
        for _ in 0..<count {let serial=try p.number(),slots=[UInt8](try p.take(4));cs.append(try YubiKeyCredential(serial:UInt(serial),signingSlot:slots[0],traditionalSlot:slots[1],kemSlot:slots[2],ecdhSlot:slots[3],signingDER:p.blob(),encryptionDER:p.blob()));pgps.append(try p.blob())}
        try require(p.done,"Trailing profile bytes");_ = try Self.payload(cs,pgps)
        let cert=try cs[signer].validated().0;try cert.keys.verify(signature,body,cert.algorithm)
        credentials=cs;pgp=pgps;self.signer=signer;encoded=data
    }
    func recovered()->OnKeyBundle{var copy=self;copy.credentials=credentials.map{$0.migrated()};copy.recoveredMigration=true;return copy}
    static func signed(_ credentials:[YubiKeyCredential],_ pgp:[Data],signer:Int,sign:(Data) async throws->Data)async throws->OnKeyBundle {
        try require(credentials.indices.contains(signer),"Invalid signer");let payload=try payload(credentials,pgp),signature=try await sign(payload)
        return try OnKeyBundle(Data("PQMAILS1".utf8)+blob(payload)+number(signer)+blob(signature))
    }
}

protocol OnKeyCard:Sendable {
    func get(_ tag:Int)async throws->Data?
    func put(_ tag:Int,_ data:Data)async throws
    func check(_ credentials:[YubiKeyCredential])async throws
    func recover(_ bundle:OnKeyBundle)async throws->OnKeyBundle
    func authenticate(_ management:Data)async throws
}
enum OnKeyStorage {
    static let banks=[0x5f5000,0x5f5100],chunk=2048,count=32
    struct Saved {let bank:Int,generation:Int,bytes:Data}
    static func read(_ card:any OnKeyCard,_ bank:Int)async throws->Saved? {
        guard let data=try await card.get(banks[bank]) else{return nil}
        var r=OnKeyBundle.Reader(data:data);try r.magic("PQMIDX01");let generation=try r.number(8),size=try r.number(),hash=try r.take(32)
        try require(generation>0 && (1...65536).contains(size) && r.done,"Invalid on-key manifest");var out=Data()
        for i in 0..<((size+chunk-1)/chunk){guard let c=try await card.get(banks[bank]+1+i)else{return nil};var p=OnKeyBundle.Reader(data:c);try p.magic("PQMCHK01");guard try p.number(8)==generation && p.number()==i else{return nil};let d=try p.take(c.count-p.offset);guard d.count==min(chunk,size-i*chunk)else{return nil};out+=d}
        guard try NativeCrypto.digest("SHA256",out)==hash else{return nil};_ = try OnKeyBundle(out);return Saved(bank:bank,generation:generation,bytes:out)
    }
    static func recoverableRead(_ card:any OnKeyCard,_ bank:Int)async throws->Saved? {
        do{return try await read(card,bank)}catch MailCryptoError.invalid{return nil}
    }
    static func latest(_ card:any OnKeyCard)async throws->Saved? {
        let a=try await recoverableRead(card,0),b=try await recoverableRead(card,1)
        if let a,let b{return a.generation>=b.generation ? a:b};return a ?? b
    }
    static func load(_ card:any OnKeyCard)async throws->OnKeyBundle {
        guard let saved=try await latest(card)else{throw MailCryptoError.invalid("No complete PQ Mail bundle on this YubiKey")};let bundle=try OnKeyBundle(saved.bytes);return try await card.recover(bundle)
    }
    static func save(_ bundle:OnKeyBundle,_ card:any OnKeyCard,_ management:Data)async throws {
        try await card.check(bundle.credentials);let old=try await latest(card),bank=old==nil ? 0:1-old!.bank,generation=(old?.generation ?? 0)+1
        for i in 0...count{if let d=try await card.get(banks[bank]+i){var r=OnKeyBundle.Reader(data:d);try r.magic(i==0 ? "PQMIDX01":"PQMCHK01")}}
        try await card.authenticate(management)
        let bytes=bundle.encoded
        for i in 0..<((bytes.count+chunk-1)/chunk){let d=Data("PQMCHK01".utf8)+OnKeyBundle.number(generation,8)+OnKeyBundle.number(i)+bytes.subdata(in:i*chunk..<min(bytes.count,(i+1)*chunk));try await card.put(banks[bank]+1+i,d);try require(try await card.get(banks[bank]+1+i)==d,"On-key read-back failed; previous bank retained")}
        let manifest=try Data("PQMIDX01".utf8)+OnKeyBundle.number(generation,8)+OnKeyBundle.number(bytes.count)+NativeCrypto.digest("SHA256",bytes)
        try await card.put(banks[bank],manifest);let saved=try await read(card,bank);try require(saved?.bytes==bytes,"Commit verification failed; reconnect to inspect recovery state")
    }
}
