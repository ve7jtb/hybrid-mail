import Foundation
import CNative
import YubiKit

public enum YubiKeyTransport: String, CaseIterable, Sendable {case nfc="NFC",usb="USB-C"}
protocol PIVConnection: Sendable {
    func send(_ command: Data) async throws -> Data
    func close() async
}
struct YubiKitConnection: PIVConnection {
    let connection: any SmartCardConnection
    func send(_ command: Data) async throws -> Data {try await connection.send(data:command)}
    func close() async {await connection.close(error:nil)}
    static func open(_ transport: YubiKeyTransport) async throws -> YubiKitConnection {
        #if os(iOS)
        if transport == .nfc {return try await YubiKitConnection(connection:NFCSmartCardConnection(alertMessage:"Keep your YubiKey in place until PQ Mail says you can remove it."))}
        #endif
        if transport == .usb {return try await YubiKitConnection(connection:USBSmartCardConnection())}
        throw MailCryptoError.invalid("NFC requires a physical iPhone")
    }
}
/// Minimal definite-length PIV TLVs; these are not ASN.1 constructed values.
enum PIVTLV {
    static func encode(_ tag: UInt8,_ data: Data) -> Data {
        var len:Data
        if data.count<128 {len=Data([UInt8(data.count)])}
        else if data.count<256 {len=Data([0x81,UInt8(data.count)])}
        else {len=Data([0x82,UInt8(data.count>>8),UInt8(data.count&255)])}
        return Data([tag])+len+data
    }
    static func decode(_ data:Data) throws -> [UInt8:Data] {
        let b=[UInt8](data);var i=0,out:[UInt8:Data]=[:]
        while i<b.count {
            try require(i+2<=b.count && out.count<16,"Invalid PIV TLV")
            let tag=b[i],first=b[i+1];i+=2;var n=Int(first)
            if first&128 != 0 {let c=Int(first&127);try require(c>0 && c<=2 && i+c<=b.count,"Invalid PIV TLV length");n=0;for _ in 0..<c {n=n*256+Int(b[i]);i+=1}}
            try require(n<=b.count-i && out[tag]==nil,"Invalid or duplicate PIV TLV")
            out[tag]=Data(b[i..<i+n]);i+=n
        };return out
    }
}
actor PIVOperation {
    private let connection: any PIVConnection
    private var pin: [UInt8]
    private var checked=false
    init(connection: any PIVConnection,pin: [UInt8]) throws {
        try Self.validatePIN(pin);self.connection=connection;self.pin=pin
    }
    init(readOnly connection:any PIVConnection){self.connection=connection;self.pin=[]}
    static func validatePIN(_ pin:[UInt8]) throws {try require((6...8).contains(pin.count) && pin.allSatisfy{(32...126).contains($0)},"Use a 6–8 character ASCII YubiKey PIN")}
    func finish() async {_ = pin.withUnsafeMutableBytes{$0.initializeMemory(as:UInt8.self,repeating:0)};pin.removeAll();await connection.close()}
    func command(_ ins:UInt8,_ p1:UInt8,_ p2:UInt8,_ data:Data=Data()) async throws -> Data {
        try Task.checkCancellation()
        try require(data.count<=8192,"PIV command exceeds limit")
        var offset=0
        while data.count-offset>255 {
            let packet=Data([0x10,ins,p1,p2,255])+data.subdata(in:offset..<offset+255)
            let reply=try await connection.send(packet)
            try require(reply==Data([0x90,0]),"PIV command chaining failed")
            offset+=255
        }
        let last=Data(data.dropFirst(offset))
        let packet=last.isEmpty ? Data([0,ins,p1,p2,0]) : Data([0,ins,p1,p2,UInt8(last.count)])+last+Data([0])
        return try await CardRead.exchange(packet) { [connection] in try await connection.send($0) }
    }
    func check(_ credential:YubiKeyCredential) async throws {
        let (s,e)=try credential.validated()
        _ = try await command(0xa4,4,0,Data([0xa0,0,0,3,8]))
        let serial=try await command(0xf8,0,0)
        try require(serial.count==4,"Invalid YubiKey serial response")
        let actual=serial.reduce(UInt(0)){($0<<8)|UInt($1)}
        guard actual==credential.serial else {throw ProbeError.wrongSerial(expected:credential.serial,actual:actual)}
        let p=s.algorithm.profile
        var bindings:[(UInt8,UInt8,UInt8,NativeKey)] = [(credential.signingSlot,p == .level2 ? 0xe2 : p == .level3 ? 0xe3 : 0xe4,0x87,s.keys.pq),(credential.kemSlot,p == .level5 ? 0xe7 : 0xe6,0x88,e.keys.pq)]
        if s.algorithm.hybrid {
            guard let sk=s.keys.ec,let ek=e.keys.ec else {throw MailCryptoError.invalid("Missing hybrid public keys")}
            bindings += [(credential.traditionalSlot,p == .level2 ? 0x11 : 0x14,0x86,sk),(credential.ecdhSlot,p == .level2 ? 0x11 : 0x14,0x86,ek)]
        }
        for (slot,algorithm,tag,key) in bindings {
            let metadata=try PIVTLV.decode(await command(0xf7,0,slot))
            try require(metadata[1]==Data([algorithm]),"Wrong key algorithm in slot \(String(slot,radix:16)); PIN not submitted")
            guard let publicTLV=metadata[4],let raw=try PIVTLV.decode(publicTLV)[tag] else {throw MailCryptoError.invalid("Missing slot public key; PIN not submitted")}
            try require(try raw==ASN1.parse(key.export()).child(1).bitBytes(),"YubiKey slot public key does not match selected credential; PIN not submitted")
        }
        checked=true
    }
    private func authorize() async throws {
        try require(checked && !pin.isEmpty,"YubiKey binding has not been checked")
        var padded=Data(pin)+Data(repeating:0xff,count:8-pin.count);defer {padded.resetBytes(in:0..<padded.count)}
        do {_ = try await command(0x20,0,0x80,padded)} catch ProbeError.status(let sw) {
            if sw&0xfff0==0x63c0 {throw MailCryptoError.invalid("Incorrect YubiKey PIN. \(sw&15) attempts remain. No retry was made.")}
            if sw==0x6983 {throw MailCryptoError.invalid("YubiKey PIN is blocked. No retry was made.")}
            throw ProbeError.status(sw)
        }
    }
    private func use(_ slot:UInt8,_ algorithm:UInt8,_ operand:UInt8,_ data:Data) async throws -> Data {
        try await authorize() // PIN_ALWAYS: verify before each component, using one operation PIN.
        let payload=PIVTLV.encode(0x7c,PIVTLV.encode(0x82,Data())+PIVTLV.encode(operand,data))
        let outer=try PIVTLV.decode(await command(0x87,algorithm,slot,payload))
        guard let inner=outer[0x7c],let response=try PIVTLV.decode(inner)[0x82] else {throw MailCryptoError.invalid("Malformed PIV operation response")};return response
    }
    func sign(_ message:Data,credential:YubiKeyCredential) async throws -> Data {
        try await check(credential)
        let cert=try credential.validated().0,p=cert.algorithm.profile
        let context=cert.algorithm.hybrid ? Data(("COMPSIG-"+p.hybridSigningName).utf8) : Data()
        let representative=try cert.algorithm.hybrid ? Data("CompositeAlgorithmSignatures2025".utf8)+context+Data([0])+NativeCrypto.digest(p.compositeHash,message) : message
        let raw=try ASN1.parse(cert.keys.pq.export()).child(1).bitBytes()
        let tr=try raw.bytes {try take(pq_shake256($0,raw.count,64))}
        let muInput=tr+Data([0,UInt8(context.count)])+context+representative
        let mu=try muInput.bytes {try take(pq_shake256($0,muInput.count,64))}
        var signature=try await use(credential.signingSlot,p == .level2 ? 0xe2 : p == .level3 ? 0xe3 : 0xe4,0x88,mu)
        try require(signature.count==p.signatureBytes,"Incorrect ML-DSA signature length")
        if cert.algorithm.hybrid {signature += try await use(credential.traditionalSlot,p == .level2 ? 0x11 : 0x14,0x81,NativeCrypto.digest(p.ecHash,representative))}
        try cert.keys.verify(signature,message,cert.algorithm) // Never emit an unverified token signature.
        return signature
    }
    func decapsulate(_ ct:Data,credential:YubiKeyCredential) async throws -> Data {
        let cert=try credential.validated().1,p=cert.algorithm.profile,n=p.ciphertextBytes
        try require(ct.count==n+(cert.algorithm.hybrid ? p.pointBytes : 0),"Invalid KEM ciphertext length")
        let point=Data(ct.dropFirst(n))
        if cert.algorithm.hybrid { // Reject malformed/off-curve peer points before any PIN submission.
            _ = try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(p.curveOID)]),.bits(point)]).der)
        }
        try await check(credential)
        let ss=try await use(credential.kemSlot,p == .level5 ? 0xe7 : 0xe6,0x86,Data(ct.prefix(n)))
        try require(ss.count==32,"Invalid ML-KEM shared-secret length")
        if !cert.algorithm.hybrid {return ss}
        let traditional=try await use(credential.ecdhSlot,p == .level2 ? 0x11 : 0x14,0x85,point)
        try require(traditional.count==(p == .level2 ? 32 : 48),"Invalid ECDH shared-secret length")
        let pub=try ASN1.parse(cert.keys.ec!.export()).child(1).bitBytes()
        let label=p.mlKEM.replacingOccurrences(of:"-",with:"")+"-"+p.curve.replacingOccurrences(of:"-",with:"")
        return try NativeCrypto.digest("SHA3-256",ss+traditional+point+pub+Data(label.utf8))
    }
    func signOpenPGP(_ digest:Data,credential:YubiKeyCredential) async throws -> Data {
        let cert=try credential.validated().0
        try require(cert.algorithm.profile == .level3 && cert.algorithm.hybrid && [32,48,64].contains(digest.count),"OpenPGP needs the Level 3 hybrid credential")
        try await check(credential)
        let raw=try PGP.raw(cert.keys.pq)
        let tr=try raw.bytes {try take(pq_shake256($0,raw.count,64))}
        let input=tr+Data([0,0])+digest // Pure ML-DSA over OpenPGP's digest, empty context.
        let mu=try input.bytes {try take(pq_shake256($0,input.count,64))}
        let pq=try await use(credential.signingSlot,0xe3,0x88,mu)
        let ec=try await use(credential.traditionalSlot,0x14,0x81,digest)
        let sig=try PGP.fixedECDSA(ec)+pq
        try PGP.verifyDigest(sig,digest,cert.keys)
        return sig
    }
    func decapsulateOpenPGP(_ ciphertext:Data,credential:YubiKeyCredential) async throws -> Data {
        let cert=try credential.validated().1
        try require(cert.algorithm.profile == .level3 && cert.algorithm.hybrid && ciphertext.count==1185,"OpenPGP needs the Level 3 hybrid credential")
        let point=Data(ciphertext.prefix(97))
        _ = try NativeKey(der:ASN1.seq([.seq([.oid("1.2.840.10045.2.1"),.oid(Profile.level3.curveOID)]),.bits(point)]).der)
        try await check(credential)
        let pq=try await use(credential.kemSlot,0xe6,0x86,Data(ciphertext.dropFirst(97)))
        let ec=try await use(credential.ecdhSlot,0x14,0x85,point)
        return try PGP.combine(pq,ec,point,PGP.raw(cert.keys.ec!))
    }

}
