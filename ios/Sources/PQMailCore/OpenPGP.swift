import Foundation
import CNative

public enum MailFormat:String,CaseIterable,Sendable {case smime="S/MIME",openPGP="OpenPGP (Level 3 hybrid draft)"}

/// Deliberately restricted to draft-ietf-openpgp-nist-bp-comp-05 IDs 41 and 37.
/// This layer never applies CMS domain separation or CMS KEM labels.
enum PGP {
    static let limit=20*1024*1024
    static func u32(_ n:Int)->Data {Data((0..<4).reversed().map{UInt8((n>>($0*8))&255)})}
    static func u64(_ n:Int)->Data {Data((0..<8).reversed().map{UInt8((UInt64(n)>>($0*8))&255)})}
    static func frame(_ tag:UInt8,_ body:Data)->Data {Data([0xc0|tag,255])+u32(body.count)+body}
    static func length(_ n:Int)->Data {n<192 ? Data([UInt8(n)]) : Data([255])+u32(n)}
    static func sub(_ tag:UInt8,_ body:Data)->Data {length(body.count+1)+Data([tag])+body}
    static func keyHash(_ body:Data)->Data {Data([0x9b])+u32(body.count)+body}
    static func fingerprint(_ body:Data)throws->Data {try NativeCrypto.digest("SHA256",keyHash(body))}
    static func armor(_ data:Data,_ kind:String)->Data {
        let b=data.base64EncodedString(options:[.lineLength64Characters,.endLineWithCarriageReturn,.endLineWithLineFeed])
        return Data(("-----BEGIN PGP "+kind+"-----\r\n\r\n"+b+"\r\n-----END PGP "+kind+"-----\r\n").utf8)
    }
    static func unarmor(_ data:Data,_ kind:String)throws->Data {
        try require(data.count<=limit,"OpenPGP input exceeds 20 MiB")
        if !data.starts(with:Data("-----BEGIN".utf8)){return data}
        guard let s=String(data:data,encoding:.utf8) else {throw MailCryptoError.invalid("Invalid OpenPGP armor")}
        let lines=s.replacingOccurrences(of:"\r\n",with:"\n").components(separatedBy:"\n")
        try require(lines.first=="-----BEGIN PGP "+kind+"-----","Unexpected OpenPGP armor type")
        var body=false,ended=false,encoded=""
        for line in lines.dropFirst() {
            if line=="-----END PGP "+kind+"-----"{ended=true;break}
            if !body {if line.isEmpty{body=true}else{try require(line.contains(":"),"Invalid armor header")};continue}
            if line.hasPrefix("="){continue} // RFC 9580: CRC is advisory, not authentication.
            encoded += line.filter{!$0.isWhitespace}
        }
        guard ended,let bytes=Data(base64Encoded:encoded) else {throw MailCryptoError.invalid("Invalid OpenPGP armor")}
        return bytes
    }
    struct Reader {
        let data:Data
        var offset=0
        init(_ data:Data){self.data=Data(data)}
        var remaining:Int {data.count-offset}
        mutating func take(_ n:Int)throws->Data {try require(n>=0 && n<=remaining,"Truncated OpenPGP data");defer{offset+=n};return data.subdata(in:offset..<offset+n)}
        mutating func byte()throws->UInt8 {try take(1)[0]}
        mutating func number(_ n:Int)throws->Int {try take(n).reduce(0){($0<<8)|Int($1)}}
        mutating func size()throws->(Int,Bool) {
            let b=try byte()
            if b<192{return(Int(b),false)}
            if b<224{return((Int(b)-192)*256+(try Int(byte()))+192,false)}
            if b==255{return(try number(4),false)}
            return(1<<Int(b&31),true)
        }
    }
    struct Packet {let tag:UInt8;let body:Data}
    static func packets(_ data:Data)throws->[Packet] {
        try require(data.count<=limit,"OpenPGP data exceeds limit")
        var r=Reader(data),out:[Packet]=[]
        while r.remaining>0 {
            try require(out.count<64,"Too many OpenPGP packets")
            let header=try r.byte();try require(header&0xc0==0xc0,"Only modern OpenPGP packet headers are supported")
            let tag=header&63
            var body=Data(),partial:Bool
            repeat {
                let size=try r.size();partial=size.1
                try require(size.0<=limit-body.count && (!partial || [8,9,11,18].contains(tag)),"Invalid OpenPGP partial length")
                body += try r.take(size.0)
            }while partial
            if tag==21{continue}
            if tag==10{try require(body==Data("PGP".utf8),"Invalid marker");continue}
            out.append(Packet(tag:tag,body:body))
        };return out
    }
    static func raw(_ key:NativeKey)throws->Data {try ASN1.parse(key.export()).child(1).bitBytes()}
    static func keyBody(_ keys:ComponentKeys,signing:Bool,created:Int)throws->Data {
        guard let ec=keys.ec else{throw MailCryptoError.invalid("OpenPGP requires Level 3 hybrid keys")}
        let material=try raw(ec)+raw(keys.pq)
        try require(material.count==(signing ? 2049 : 1281),"OpenPGP requires ML-DSA-65/ML-KEM-768 with P-384")
        return Data([6])+u32(created)+Data([signing ? 41 : 37])+u32(material.count)+material
    }
    static func parseKey(_ body:Data,signing:Bool)throws->ComponentKeys {
        var r=Reader(body)
        try require(try r.byte()==6,"OpenPGP v6 key required")
        let created=try r.number(4);try require(created<=Int(Date().timeIntervalSince1970)+300,"OpenPGP key is from the future")
        try require(try r.byte()==(signing ? 41 : 37),"Unsupported OpenPGP hybrid profile (requires draft IDs 41/37)")
        let n=try r.number(4);try require(n==(signing ? 2049 : 1281) && n==r.remaining,"Invalid OpenPGP key size")
        let point=try r.take(97),pq=try r.take(r.remaining)
        let a=Algorithm(profile:.level3,hybrid:false,signing:signing)
        return ComponentKeys(pq:try NativeKey(der:ASN1.seq([.alg(a.oid),.bits(pq)]).der),ec:try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(Profile.level3.curveOID)]),.bits(point)]).der))
    }
    static func fixedECDSA(_ der:Data)throws->Data {
        let seq=try ASN1.parse(der).expect(0x30,count:2)
        return try seq.children.reduce(into:Data()){out,item in
            try require(item.tag==2 && !item.value.isEmpty && item.value[0]&128==0,"Invalid ECDSA integer")
            let bytes=Data(item.value.drop(while:{$0==0}));try require(!bytes.isEmpty && bytes.count<=48,"Invalid ECDSA scalar")
            out += Data(repeating:0,count:48-bytes.count)+bytes
        }
    }
    static func derECDSA(_ fixed:Data)throws->Data {
        try require(fixed.count==96,"Invalid OpenPGP ECDSA length")
        func integer(_ bytes:Data)throws->ASN1 {
            var b=Data(bytes.drop(while:{$0==0}));try require(!b.isEmpty,"Zero ECDSA scalar")
            if b[0]&128 != 0{b.insert(0,at:0)};return ASN1(2,b)
        }
        return try ASN1.seq([integer(Data(fixed.prefix(48))),integer(Data(fixed.suffix(48)))]).der
    }
    static func signDigest(_ digest:Data,_ keys:ComponentKeys)throws->Data {
        guard let ec=keys.ec else{throw MailCryptoError.invalid("Missing OpenPGP ECDSA key")}
        let der=try digest.bytes{try take(pq_ec_sign_digest(ec.handle,$0,digest.count))}
        return try fixedECDSA(der)+keys.pq.sign(digest)
    }
    static func verifyDigest(_ sig:Data,_ digest:Data,_ keys:ComponentKeys)throws {
        try require(sig.count==96+3309 && [32,48,64].contains(digest.count),"Invalid OpenPGP hybrid signature")
        guard let ec=keys.ec else{throw MailCryptoError.invalid("Missing OpenPGP ECDSA public key")}
        let der=try derECDSA(Data(sig.prefix(96)))
        let ok=digest.bytes {d in der.bytes{pq_ec_verify_digest(ec.handle,d,digest.count,$0,der.count)}}
        try require(ok==1,"Invalid OpenPGP ECDSA signature")
        try keys.pq.verify(Data(sig.dropFirst(96)),message:digest)
    }
    struct Signature {
        let header:Data,salt:Data,digest:Data
        let type:UInt8
        init(data:Data,type:UInt8,fingerprint:Data,extra:Data=Data())throws {
            self.type=type;salt=try NativeCrypto.random(24)
            let subs=PGP.sub(2,PGP.u32(Int(Date().timeIntervalSince1970)))+PGP.sub(33,Data([6])+fingerprint)+extra
            header=Data([6,type,41,9])+PGP.u32(subs.count)+subs
            digest=try NativeCrypto.digest("SHA384",salt+data+header+Data([6,255])+PGP.u32(header.count))
        }
        func finish(_ signature:Data)throws->Data {
            try require(signature.count==3405,"Incorrect hybrid signature size")
            return header+PGP.u32(0)+digest.prefix(2)+Data([24])+salt+signature
        }
    }
    struct VerifiedSignature {let subpackets:[UInt8:Data];let salt:Data}
    static func verifySignature(_ body:Data,data:Data,type:UInt8,key:Data)throws->VerifiedSignature {
        var r=Reader(body)
        try require(try r.take(3)==Data([6,type,41]),"Unsupported OpenPGP signature (requires v6, ML-DSA-65+P-384)")
        let hashID=try r.byte()
        guard let hash=[8:("SHA256",16),9:("SHA384",24),10:("SHA512",32),12:("SHA3-256",16),14:("SHA3-512",32)][Int(hashID)] else {throw MailCryptoError.invalid("Unsupported OpenPGP signature hash")}
        let n=try r.number(4);try require(n<=8192,"OpenPGP signature metadata exceeds limit")
        let hashed=try r.take(n),header=Data(body.prefix(r.offset))
        let un=try r.number(4);try require(un<=8192,"OpenPGP unhashed metadata exceeds limit");_ = try r.take(un)
        let prefix=try r.take(2);try require(try r.byte()==UInt8(hash.1),"Incorrect OpenPGP signature salt size")
        let salt=try r.take(hash.1),sig=try r.take(r.remaining)
        let digest=try NativeCrypto.digest(hash.0,salt+data+header+Data([6,255])+u32(header.count))
        try require(prefix==digest.prefix(2),"OpenPGP signature digest mismatch")
        var subreader=Reader(hashed),subs:[UInt8:Data]=[:]
        while subreader.remaining>0 {
            let (len,partial)=try subreader.size();try require(!partial && len>0,"Invalid signature subpacket")
            var sr=Reader(try subreader.take(len));let t=try sr.byte(),id=t&127
            try require(t&128==0 || [2,3,9,11,21,22,27,30,33,39].contains(id),"Unsupported critical OpenPGP signature subpacket")
            try require(subs[id]==nil,"Duplicate OpenPGP signature subpacket")
            subs[id]=try sr.take(sr.remaining)
        }
        try require(try subs[33]==Data([6])+fingerprint(key),"OpenPGP issuer fingerprint mismatch")
        guard let time=subs[2],time.count==4 else{throw MailCryptoError.invalid("Missing signature creation time")}
        let created=time.reduce(0){($0<<8)|Int($1)},now=Int(Date().timeIntervalSince1970)
        try require(created<=now+300,"OpenPGP signature is from the future")
        if let expires=subs[3] {try require(expires.count==4,"Invalid signature expiry");let seconds=expires.reduce(0){($0<<8)|Int($1)};try require(seconds==0 || created+seconds>=now,"Expired OpenPGP signature")}
        try verifyDigest(sig,digest,parseKey(key,signing:true))
        return VerifiedSignature(subpackets:subs,salt:salt)
    }
    struct PublicIdentity:Sendable {
        let primary:Data,subkey:Data,email:String,encoded:Data
        let signing:ComponentKeys,encryption:ComponentKeys
        let aead:UInt8?
        var fingerprint:Data {get throws{try PGP.fingerprint(primary)}}
        var encryptionFingerprint:Data {get throws{try PGP.fingerprint(subkey)}}
        init(_ encoded:Data)throws {
            let bytes=try PGP.unarmor(encoded,"PUBLIC KEY BLOCK"),packets=try PGP.packets(bytes)
            try require(packets.map{$0.tag}==[6,2,13,2,14,2],"Supported OpenPGP certificate needs one primary key, direct signature, email user ID and bound encryption subkey; extra/revoked keys are rejected")
            primary=packets[0].body;subkey=packets[4].body;self.encoded=bytes
            signing=try PGP.parseKey(primary,signing:true);encryption=try PGP.parseKey(subkey,signing:false)
            guard let uid=String(data:packets[2].body,encoding:.utf8) else{throw MailCryptoError.invalid("Invalid OpenPGP user ID")}
            let address:String
            if let l=uid.lastIndex(of:"<"),uid.hasSuffix(">"){address=String(uid[uid.index(after:l)..<uid.index(before:uid.endIndex)])}else{address=uid}
            try SoftwareMailIdentity.validateEmail(address);email=address
            let direct=try PGP.verifySignature(packets[1].body,data:PGP.keyHash(primary),type:0x1f,key:primary)
            let prefs=direct.subpackets[39] ?? Data()
            try require(prefs.count%2==0,"Invalid AEAD preferences")
            let modes=stride(from:0,to:prefs.count,by:2).compactMap {prefs[$0]==9 ? prefs[$0+1] : nil}
            aead=modes.contains(3) ? 3 : modes.contains(2) ? 2 : nil
            _ = try PGP.verifySignature(packets[3].body,data:PGP.keyHash(primary)+Data([0xb4])+PGP.u32(packets[2].body.count)+packets[2].body,type:0x13,key:primary)
            let binding=try PGP.verifySignature(packets[5].body,data:PGP.keyHash(primary)+PGP.keyHash(subkey),type:0x18,key:primary)
            try require((direct.subpackets[27]?.first ?? 0)&3==3 && (binding.subpackets[27]?.first ?? 0)&12 != 0,"OpenPGP key flags do not permit signing/encryption")
            for (key,metadata) in [(primary,direct),(subkey,binding)] {
                if let expiry=metadata.subpackets[9] {
                    try require(expiry.count==4,"Invalid OpenPGP key expiry")
                    let seconds=expiry.reduce(0){($0<<8)|Int($1)},created=key.subdata(in:1..<5).reduce(0){($0<<8)|Int($1)}
                    try require(seconds==0 || created+seconds>=Int(Date().timeIntervalSince1970),"Expired OpenPGP key")
                }
            }
        }
    }
    static func makePublic(signing:ComponentKeys,encryption:ComponentKeys,email:String,created:Int,signer:@Sendable (Data)async throws->Data)async throws->PublicIdentity {
        try SoftwareMailIdentity.validateEmail(email)
        let primary=try keyBody(signing,signing:true,created:created),subkey=try keyBody(encryption,signing:false,created:created),fp=try fingerprint(primary),uid=Data(email.utf8)
        let preferences=sub(27,Data([3]))+sub(11,Data([9]))+sub(21,Data([9]))+sub(22,Data([0]))+sub(30,Data([8]))+sub(39,Data([9,3,9,2]))
        let inputs:[(UInt8,Data,Data)]=[(0x1f,keyHash(primary),preferences),(0x13,keyHash(primary)+Data([0xb4])+u32(uid.count)+uid,Data()),(0x18,keyHash(primary)+keyHash(subkey),sub(27,Data([12])))]
        var signatures:[Data]=[]
        for (type,input,extra) in inputs {
            let request=try Signature(data:input,type:type,fingerprint:fp,extra:extra)
            let sig=try await signer(request.digest);try verifyDigest(sig,request.digest,signing)
            signatures.append(try frame(2,try request.finish(sig)))
        }
        return try PublicIdentity(frame(6,primary)+signatures[0]+frame(13,uid)+signatures[1]+frame(14,subkey)+signatures[2])
    }
    static func combine(_ pq:Data,_ ec:Data,_ point:Data,_ recipient:Data)throws->Data {
        try require(pq.count==32 && ec.count==48 && point.count==97 && recipient.count==97,"Invalid OpenPGP KEM components")
        return try NativeCrypto.digest("SHA3-256",pq+ec+point+recipient+Data([37])+Data("OpenPGPCompositeKDFv1".utf8)+Data([21]))
    }
    static func encapsulate(_ recipient:PublicIdentity)throws->(Data,Data) {
        let (ct,ss)=try recipient.encryption.pq.encapsulate()
        let ephemeral=try NativeKey(algorithm:"EC",group:Profile.level3.group),ec=recipient.encryption.ec!
        let point=try raw(ephemeral),share=try ephemeral.derive(ec)
        return try (point+ct,combine(ss,share,point,raw(ec)))
    }
    static func decapsulate(_ ct:Data,_ keys:ComponentKeys)throws->Data {
        try require(ct.count==1185,"Invalid OpenPGP KEM ciphertext")
        let point=Data(ct.prefix(97))
        let peer=try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(Profile.level3.curveOID)]),.bits(point)]).der)
        guard let ec=keys.ec else{throw MailCryptoError.invalid("Missing ECDH key")}
        return try combine(keys.pq.decapsulate(Data(ct.dropFirst(97))),ec.derive(peer),point,raw(ec))
    }
    static func seipd(_ plain:Data,_ session:Data,mode:UInt8=3)throws->Data {
        try require(mode==2 || mode==3,"Unsupported AEAD mode")
        let salt=try NativeCrypto.random(32),info=Data([0xd2,2,9,mode,10])
        let derived=try derive(session,salt,info,mode==2 ? 39 : 36),key=Data(derived.prefix(32)),iv=Data(derived.dropFirst(32))
        var out=Data([2,9,mode,10])+salt,index=0,offset=0
        repeat {
            let n=min(65536,plain.count-offset)
            out += try aead(true,mode,key,iv+u64(index),plain.subdata(in:offset..<offset+n),aad:info)
            offset+=n;index+=1
        }while offset<plain.count
        out += try aead(true,mode,key,iv+u64(index),Data(),aad:info+u64(plain.count))
        return frame(18,out)
    }
    static func aead(_ encrypt:Bool,_ mode:UInt8,_ key:Data,_ nonce:Data,_ input:Data,aad:Data)throws->Data {
        if mode==3{return try NativeCrypto.gcm(encrypt,key,nonce,input,aad:aad)}
        try require(mode==2 && key.count==32 && nonce.count==15,"Invalid OCB parameters")
        return try key.bytes{k in try nonce.bytes{iv in try aad.bytes{a in try input.bytes{try take(pq_ocb(encrypt ? 1 : 0,k,iv,a,aad.count,$0,input.count))}}}}
    }
    static func derive(_ session:Data,_ salt:Data,_ info:Data,_ n:Int)throws->Data {
        try session.bytes{s in try salt.bytes{t in try info.bytes{try take(pq_hkdf_salt(s,session.count,t,salt.count,$0,info.count,n))}}}
    }
    static func decryptSEIPD(_ body:Data,_ session:Data)throws->Data {
        var r=Reader(body);try require(try r.take(2)==Data([2,9]),"Only v2 SEIPD with AES-256 is supported")
        let mode=try r.byte();try require(mode==2 || mode==3,"Unsupported OpenPGP AEAD mode")
        let c=try r.byte();try require(c<=16,"Invalid OpenPGP chunk size")
        let salt=try r.take(32),info=Data([0xd2,2,9,mode,c]),derived=try derive(session,salt,info,mode==2 ? 39 : 36),key=Data(derived.prefix(32)),iv=Data(derived.dropFirst(32))
        var out=Data(),index=0
        let chunk=1<<(Int(c)+6)
        try require(r.remaining>=32,"Truncated OpenPGP encrypted message")
        while r.remaining>16 {
            let n=min(chunk+16,r.remaining-16);try require(n>=16,"Invalid OpenPGP encrypted chunk")
            out += try aead(false,mode,key,iv+u64(index),r.take(n),aad:info);index+=1
        }
        _ = try aead(false,mode,key,iv+u64(index),r.take(16),aad:info+u64(out.count))
        return out
    }
    static func encrypt(_ signed:Data,recipient:PublicIdentity)throws->Data {
        guard let mode=recipient.aead else{throw MailCryptoError.invalid("Recipient must advertise AES-256 with OCB or GCM")}
        let session=try NativeCrypto.random(32),(ct,kek)=try encapsulate(recipient),wrapped=try NativeCrypto.wrap(true,kek,session)
        let pkesk=try Data([6,33,6])+recipient.encryptionFingerprint+Data([37])+ct+Data([UInt8(wrapped.count)])+wrapped
        return try frame(1,pkesk)+seipd(signed,session,mode:mode)
    }
    struct Envelope {
        let ciphertext:Data,wrapped:Data,encrypted:Data
        init(_ bytes:Data,recipient:PublicIdentity)throws {
            let p=try PGP.packets(bytes);try require(p.map{$0.tag}==[1,18],"Expected one OpenPGP recipient and authenticated payload")
            var r=Reader(p[0].body)
            try require(try r.take(3)==Data([6,33,6]),"Unsupported OpenPGP recipient")
            try require(try r.take(32)==recipient.encryptionFingerprint && r.byte()==37,"OpenPGP recipient does not match selected identity")
            ciphertext=try r.take(1185)
            try require(try r.byte()==40 && r.remaining==40,"Invalid wrapped OpenPGP session key")
            wrapped=try r.take(40);encrypted=p[1].body
            // Validate public EC input and payload algorithm before prompting for PIN.
            _ = try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(Profile.level3.curveOID)]),.bits(Data(ciphertext.prefix(97)))]).der)
            try require(encrypted.count>=68 && encrypted.prefix(2)==Data([2,9]) && [2,3].contains(encrypted[2]) && encrypted[3]<=16,"Unsupported encrypted OpenPGP payload")
        }
        func open(_ kek:Data)throws->Data {
            let session=try NativeCrypto.wrap(false,kek,wrapped);try require(session.count==32,"Invalid OpenPGP session key")
            return try PGP.decryptSEIPD(encrypted,session)
        }
    }
    static func signedPackets(_ plain:Data,identity:PublicIdentity,signer:@Sendable (Data)async throws->Data)async throws->Data {
        let request=try Signature(data:plain,type:0,fingerprint:identity.fingerprint),sig=try await signer(request.digest)
        try verifyDigest(sig,request.digest,identity.signing)
        let ops=try Data([6,0,9,41,24])+request.salt+identity.fingerprint+Data([1])
        return frame(4,ops)+frame(11,Data([0x62,0])+u32(0)+plain)+frame(2,try request.finish(sig))
    }
    static func openSigned(_ data:Data,signer:PublicIdentity)throws->Data {
        let p=try packets(data);try require(p.map{$0.tag}==[4,11,2],"Unsupported OpenPGP signed message; compression is not supported")
        var literal=Reader(p[1].body);let format=try literal.byte();try require([0x62,0x75,0x74].contains(format),"Invalid literal data")
        let filename=try literal.number(1);_ = try literal.take(filename+4);let plain=try literal.take(literal.remaining)
        let checked=try verifySignature(p[2].body,data:plain,type:0,key:signer.primary)
        let expected=try Data([6,0,p[2].body[3],41,UInt8(checked.salt.count)])+checked.salt+signer.fingerprint+Data([1])
        try require(p[0].body==expected,"OpenPGP one-pass signature mismatch")
        return plain
    }
}
