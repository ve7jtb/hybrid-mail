import XCTest
import CNative
@testable import PQMailCore

private actor MockPIV:PIVConnection {
    let signingKeys:ComponentKeys
    let encryptionKeys:ComponentKeys
    let profile:Profile
    let hybrid:Bool
    let message:Data
    var serial:UInt=41088008
    var wrongKey=false
    var pgp=false
    var failPIN=false
    var verifies=0
    var closed=false
    var chained=Data()
    var response=Data()
    var chainCount=0
    init(_ signingKeys:ComponentKeys,_ encryptionKeys:ComponentKeys,_ profile:Profile,_ hybrid:Bool,_ message:Data){self.signingKeys=signingKeys;self.encryptionKeys=encryptionKeys;self.profile=profile;self.hybrid=hybrid;self.message=message}
    func configure(serial:UInt=41088008,wrongKey:Bool=false,failPIN:Bool=false,pgp:Bool=false){self.pgp=pgp;self.serial=serial;self.wrongKey=wrongKey;self.failPIN=failPIN}
    func counts()->(Int,Bool,Int){(verifies,closed,chainCount)}
    func close() async {closed=true}
    func send(_ command:Data) async throws -> Data {
        let b=[UInt8](command),ins=b[1],slot=b[3],p=profile
        if ins==0xc0 {return chunk()}
        let data=b.count>5 ? Data(b[5..<5+Int(b[4])]) : Data()
        if b[0]==0x10 {chainCount+=1;chained+=data;return Data([0x90,0])}
        let payload=chained+data;chained=Data()
        var result=Data()
        switch ins {
        case 0xa4:XCTAssertEqual(payload,Data([0xa0,0,0,3,8]))
        case 0xf8:result=Data([UInt8((serial>>24)&255),UInt8((serial>>16)&255),UInt8((serial>>8)&255),UInt8(serial&255)])
        case 0xf7:
            let key:NativeKey,alg:UInt8,tag:UInt8
            switch slot {
            case 0x9c:key=signingKeys.pq;alg=p == .level2 ? 0xe2 : p == .level3 ? 0xe3 : 0xe4;tag=0x87
            case 0x9d:key=encryptionKeys.pq;alg=p == .level5 ? 0xe7 : 0xe6;tag=0x88
            case 0x9a:key=signingKeys.ec!;alg=p == .level2 ? 0x11 : 0x14;tag=0x86
            default:key=encryptionKeys.ec!;alg=p == .level2 ? 0x11 : 0x14;tag=0x86
            }
            var raw=try ASN1.parse(key.export()).child(1).bitBytes()
            if wrongKey {raw[0] ^= 1}
            result=PIVTLV.encode(1,Data([alg]))+PIVTLV.encode(4,PIVTLV.encode(tag,raw))
        case 0x20:
            verifies+=1
            XCTAssertEqual(payload,Data("123456".utf8)+Data([255,255]))
            if failPIN{return Data([0x63,0xc2])}
        case 0x87:
            let values=try PIVTLV.decode(PIVTLV.decode(payload)[0x7c]!)
            let context=hybrid ? Data(("COMPSIG-"+p.hybridSigningName).utf8) : Data()
            let representative=try hybrid ? Data("CompositeAlgorithmSignatures2025".utf8)+context+Data([0])+NativeCrypto.digest(p.compositeHash,message) : message
            var output=Data()
            switch slot {
            case 0x9c:
                let raw=try ASN1.parse(signingKeys.pq.export()).child(1).bitBytes()
                let tr=try raw.bytes{try take(pq_shake256($0,raw.count,64))}
                let input=tr+Data([0,UInt8(context.count)])+context+representative
                let expected=try input.bytes{try take(pq_shake256($0,input.count,64))}
                if !pgp {XCTAssertEqual(values[0x88],expected)}
                let mu=values[0x88]!
                output=try mu.bytes{try take(pq_sign_mu(signingKeys.pq.handle,$0,mu.count))}
            case 0x9a:
                if !pgp {XCTAssertEqual(values[0x81],try NativeCrypto.digest(p.ecHash,representative))}
                let digest=values[0x81]!
                output=try digest.bytes{try take(pq_ec_sign_digest(signingKeys.ec!.handle,$0,digest.count))}
            case 0x9d:output=try encryptionKeys.pq.decapsulate(values[0x86]!)
            default:
                let peer=try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(p.curveOID)]),.bits(values[0x85]!)]).der)
                output=try encryptionKeys.ec!.derive(peer)
            }
            result=PIVTLV.encode(0x7c,PIVTLV.encode(0x82,output))
        default:throw MailCryptoError.invalid("Unexpected APDU")
        }
        response=result;return chunk()
    }
    private func chunk()->Data {
        let part=Data(response.prefix(180));response=Data(response.dropFirst(part.count))
        return part+(response.isEmpty ? Data([0x90,0]) : Data([0x61,0]))
    }
}
final class YubiKeyTests:XCTestCase {
    private func credential(_ id:SoftwareMailIdentity,_ h:Bool)throws->YubiKeyCredential {
        try YubiKeyCredential(serial:41088008,signingSlot:0x9c,traditionalSlot:0x9a,kemSlot:0x9d,ecdhSlot:0x82,signingDER:id.signingCertificate(hybrid:h),encryptionDER:id.encryptionCertificate(hybrid:h))
    }
    func testSixProfilesWithChainedAPDUs() async throws {
        for p in Profile.allCases {
            let id=try SoftwareMailIdentity(profile:p,email:"test@example.com")
            for h in [false,true] {
                let message=Data("CMS signed attributes".utf8),c=try credential(id,h)
                let card=MockPIV(id.signingKeys,id.encryptionKeys,id.profile,h,message),op=try PIVOperation(connection:card,pin:Array("123456".utf8))
                let sig=try await op.sign(message,credential:c)
                try id.signingKeys.verify(sig,message,Algorithm(profile:p,hybrid:h,signing:true))
                let (ct,ss)=try id.encryptionKeys.encapsulate(Algorithm(profile:p,hybrid:h,signing:false))
                let recovered=try await op.decapsulate(ct,credential:c)
                XCTAssertEqual(recovered,ss)
                await op.finish()
                let counts=await card.counts()
                XCTAssertEqual(counts.0,h ? 4 : 2);XCTAssertTrue(counts.1);XCTAssertGreaterThan(counts.2,0)
            }
        }
    }
    func testBindingBeforePINAndNoRetry() async throws {
        let id=try SoftwareMailIdentity(profile:.level3,email:"test@example.com"),c=try credential(id,true)
        for mode in 0...2 {
            let card=MockPIV(id.signingKeys,id.encryptionKeys,id.profile,true,Data()),op=try PIVOperation(connection:card,pin:Array("123456".utf8))
            await card.configure(serial:mode==0 ? 999 : 41088008,wrongKey:mode==1,failPIN:mode==2)
            do {_ = try await op.sign(Data(),credential:c);XCTFail("Accepted invalid binding/PIN")} catch {}
            await op.finish()
            let counts=await card.counts();XCTAssertEqual(counts.0,mode==2 ? 1 : 0);XCTAssertTrue(counts.1)
        }
    }
    func testOpenPGPWithHardwareAdapter() async throws {
        let id=try SoftwareMailIdentity(profile:.level3,email:"test@example.com"),c=try credential(id,true)
        let card=MockPIV(id.signingKeys,id.encryptionKeys,id.profile,true,Data()),op=try PIVOperation(connection:card,pin:Array("123456".utf8))
        await card.configure(pgp:true)
        let pub=try await PGP.makePublic(signing:id.signingKeys,encryption:id.encryptionKeys,email:id.email,created:Int(Date().timeIntervalSince1970)) {try await op.signOpenPGP($0,credential:c)}
        let mail=try await OpenPGPMail.compose(identity:pub,recipient:pub,to:id.email,subject:"Token protocol",text:"hardware adapter") {try await op.signOpenPGP($0,credential:c)}
        let envelope=try OpenPGPMail.envelope(mail,recipient:pub)!
        let kek=try await op.decapsulateOpenPGP(envelope.ciphertext,credential:c)
        let opened=try OpenPGPMail.open(mail,signer:pub,recipient:pub){_ in kek}
        XCTAssertEqual(opened.text,"hardware adapter")
        await op.finish()
        let counts=await card.counts();XCTAssertEqual(counts.0,10);XCTAssertTrue(counts.1)
    }
    func testPersistenceAcrossServiceInstances() async throws {
        let dir=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:dir)}
        let first=LocalMailService(storeURL:dir)
        let entry=try await first.create(profile:.level3,email:"test@example.com",password:"test-password-only")
        await first.lock()
        let reopened=LocalMailService(storeURL:dir)
        let entries=try await reopened.savedIdentities();XCTAssertEqual(entries.count,1)
        do {_ = try await reopened.select(entry.id,password:"wrong");XCTFail("Wrong password accepted")} catch {}
        _ = try await reopened.select(entry.id,password:"test-password-only")
        for h in [false,true] {
            let eml=try await reopened.compose(profile:.level3,hybrid:h,to:"test@example.com",subject:"Persist",text:"persistent",encrypt:true,recipient:nil)
            let opened=try await reopened.open(eml,hybrid:h);XCTAssertEqual(opened.text,"persistent")
        }
    }
}
