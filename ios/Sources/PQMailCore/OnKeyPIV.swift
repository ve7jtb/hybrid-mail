import Foundation
import YubiKit

actor OnKeyPIV:OnKeyCard {
    let connection:YubiKitConnection
    let operation:PIVOperation
    init(_ connection:YubiKitConnection){self.connection=connection;operation=PIVOperation(readOnly:connection)}
    static func open(_ transport:YubiKeyTransport)async throws->OnKeyPIV {
        let connection=try await YubiKitConnection.open(transport),card=OnKeyPIV(connection)
        do{_ = try await card.operation.command(0xa4,4,0,Data([0xa0,0,0,3,8]));return card}catch{await connection.close();throw error}
    }
    func close()async{await operation.finish()}
    func check(_ credentials:[YubiKeyCredential])async throws{for c in credentials{try await operation.check(c)}}
    func recover(_ bundle:OnKeyBundle)async throws->OnKeyBundle {
        if bundle.credentials.allSatisfy({$0.traditionalSlot==0x9a}){do{_ = try await operation.command(0xf7,0,0x9a)}catch ProbeError.status(0x6a88){let updated=bundle.recovered();try await check(updated.credentials);return updated}}
        try await check(bundle.credentials);return bundle
    }
    func get(_ tag:Int)async throws->Data? {
        let selector=PIVTLV.encode(0x5c,OnKeyBundle.number(tag,3))
        do{let data=try await operation.command(0xcb,0x3f,0xff,selector);guard let value=try PIVTLV.decode(data)[0x53]else{throw MailCryptoError.invalid("Malformed PIV object")};return value}
        catch ProbeError.status(0x6a82){return nil}
    }
    func put(_ tag:Int,_ data:Data)async throws{
        try require(data.count<=2068,"PIV object too large")
        _ = try await operation.command(0xdb,0x3f,0xff,PIVTLV.encode(0x5c,OnKeyBundle.number(tag,3))+PIVTLV.encode(0x53,data))
    }
    func authenticate(_ management:Data)async throws{
        // Resolve Beta0's 0.0.1 placeholder from this same device before the SDK
        // chooses the management-key algorithm. Do not assume legacy TDES.
        let managementSession=try await Management.Session.makeSession(connection:connection.connection)
        _ = try await managementSession.getDeviceInfo()
        let session=try await PIVSession.makeSession(connection:connection.connection)
        try require(await session.version >= Version("5.3.0")!,"Cannot establish management-key metadata support")
        try await session.authenticate(with:management)
    }
    func migrate(_ credentials:[YubiKeyCredential],_ management:Data)async throws {
        try require(credentials.allSatisfy{$0.traditionalSlot==0x9a} && credentials.contains{(try? $0.validated().0.algorithm.hybrid)==true},"Migration needs the existing pure/hybrid profiles mapped to 9a")
        do{_ = try await operation.command(0xf7,0,0x9a)}catch ProbeError.status(0x6a88){try await check(credentials.map{$0.migrated()});return}
        try await check(credentials)
        do{_ = try await operation.command(0xf7,0,0x83);throw MailCryptoError.invalid("Slot 83 already has a key")}catch ProbeError.status(0x6a88){}
        try require(try await get(0x5fc10e)==nil,"Slot 83 already has a certificate")
        let before=try PIVTLV.decode(await operation.command(0xf7,0,0x9a))
        try require(before[1]==Data([0x11]) || before[1]==Data([0x14]),"Only ECDSA P-256/P-384 migration is supported")
        let cert=try await get(0x5fc105)
        try await authenticate(management)
        _ = try await operation.command(0xf6,0x83,0x9a)
        let after=try PIVTLV.decode(await operation.command(0xf7,0,0x83))
        try require(before[1]==after[1] && before[2]==after[2] && before[4]==after[4],"Key moved; destination metadata differs")
        try await check(credentials.map{$0.migrated()})
        if let cert{try await put(0x5fc10e,cert);try require(try await get(0x5fc10e)==cert,"Key moved; certificate copy verification failed");try await put(0x5fc105,Data())}
    }
}
extension YubiKeyCredential {
    func migrated()->YubiKeyCredential {YubiKeyCredential(serial:serial,signingSlot:signingSlot,traditionalSlot:traditionalSlot==0x9a ? 0x83:traditionalSlot,kemSlot:kemSlot,ecdhSlot:ecdhSlot,signingDER:signingDER,encryptionDER:encryptionDER)}
}
