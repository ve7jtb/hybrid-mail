import Foundation

/// Owns unlocked keys; passwords and PINs are never written to the identity store.
public actor LocalMailService {
    private var identity: SoftwareMailIdentity?
    private var selected: SavedIdentity?
    private let store: IdentityStore
    public init(storeURL: URL? = nil) { store=IdentityStore(directory:storeURL) }

    public func readOnKey(transport:YubiKeyTransport)async throws->OnKeyBundle {
        let card=try await OnKeyPIV.open(transport)
        do{let bundle=try await OnKeyStorage.load(card);await card.close();return bundle}catch{await card.close();throw error}
    }
    public func importOnKey(_ bundle:OnKeyBundle)throws {
        for c in bundle.credentials where c.traditionalSlot==0x83{for old in try store.list(){if let token=old.token,token.serial==c.serial && token.signingDER==c.signingDER && token.encryptionDER==c.encryptionDER && token.traditionalSlot==0x9a{try store.save(SavedIdentity(id:old.id,label:old.label,profile:old.profile,modes:old.modes,token:c))}}}
        let entries=try importTokenCredentials(bundle.credentials)
        for (i,e) in entries.enumerated() where !bundle.pgp[i].isEmpty {
            let url=store.directory.appendingPathComponent(e.id+".pgp")
            if FileManager.default.fileExists(atPath:url.path){let old=try PGP.PublicIdentity(Data(contentsOf:url)),new=try PGP.PublicIdentity(bundle.pgp[i]);try require(try old.fingerprint==new.fingerprint && old.encryptionFingerprint==new.encryptionFingerprint,"Conflicting existing OpenPGP identity")}
            try bundle.pgp[i].write(to:url,options:.atomic)
        }
    }
    private func tokenProfiles()throws->[SavedIdentity] {
        guard let token=selected?.token else{throw MailCryptoError.invalid("Select a YubiKey identity")}
        let (sign,enc)=try token.validated()
        return try store.list().filter {entry in
            guard let c=entry.token,c.serial==token.serial else{return false};let (s,e)=try c.validated()
            return try s.keys.pq.export()==sign.keys.pq.export() && e.keys.pq.export()==enc.keys.pq.export()
        }
    }
    public func prepareOnKey(pin:String,transport:YubiKeyTransport)async throws->OnKeyBundle {
        let entries=try tokenProfiles(),credentials=entries.compactMap(\.token)
        let pgp=try entries.map {e->Data in let url=store.directory.appendingPathComponent(e.id+".pgp");return FileManager.default.fileExists(atPath:url.path) ? try Data(contentsOf:url):Data()}
        let signer=credentials.firstIndex{(try? $0.validated().0.algorithm.hybrid)==true} ?? 0
        return try await hardware(pin,transport){op in try await OnKeyBundle.signed(credentials,pgp,signer:signer){try await op.sign($0,credential:credentials[signer])}}
    }
    public func writeOnKey(_ bundle:OnKeyBundle,management:String,transport:YubiKeyTransport)async throws {
        var key=try Self.managementBytes(management);defer{key.resetBytes(in:0..<key.count)}
        let card=try await OnKeyPIV.open(transport)
        do{try await OnKeyStorage.save(bundle,card,key);await card.close()}catch{await card.close();throw error}
    }
    private static func managementBytes(_ text:String)throws->Data {
        let b=Array(text.utf8);try require([32,48,64].contains(b.count),"Management key needs 32, 48 or 64 hex characters")
        var data=Data();for i in stride(from:0,to:b.count,by:2){guard let value=UInt8(String(decoding:b[i..<i+2],as:UTF8.self),radix:16)else{throw MailCryptoError.invalid("Invalid management key")};data.append(value)};return data
    }
    public func migrateOnKey(management:String,transport:YubiKeyTransport)async throws {
        let entries=try tokenProfiles(),credentials=entries.compactMap(\.token)
        var key=try Self.managementBytes(management);defer{key.resetBytes(in:0..<key.count)}
        let backup=try JSONEncoder().encode(entries)
        try backup.write(to:store.directory.appendingPathComponent("migration-\(UUID().uuidString).backup"),options:.atomic)
        let card=try await OnKeyPIV.open(transport)
        do{try await card.migrate(credentials,key);await card.close()}catch{await card.close();throw error}
        for e in entries{let updated=SavedIdentity(id:e.id,label:e.label,profile:e.profile,modes:e.modes,token:e.token!.migrated());try store.save(updated);if selected?.id==e.id{selected=updated}}
    }

    public func savedIdentities() throws -> [SavedIdentity] {try store.list()}
    public func lock() {identity=nil;selected=nil}
    public func create(profile: Profile,email: String,password: String) throws -> SavedIdentity {
        let fresh=try SoftwareMailIdentity(profile:profile,email:email)
        let encrypted=try fresh.pkcs12(password:password)
        let entry=SavedIdentity(id:UUID().uuidString,label:"\(email) · Level \(profile.rawValue) · Software .p12",profile:profile.rawValue,modes:fresh.availableModes,token:nil)
        try store.save(entry,encrypted:encrypted);identity=fresh;selected=entry;return entry
    }
    public func importPKCS12(_ data:Data,password:String) throws -> SavedIdentity {
        let fresh=try SoftwareMailIdentity.loadPKCS12(data,password:password)
        let entry=SavedIdentity(id:UUID().uuidString,label:"\(fresh.email) · Level \(fresh.profile.rawValue) · Software .p12",profile:fresh.profile.rawValue,modes:fresh.availableModes,token:nil)
        try store.save(entry,encrypted:fresh.pkcs12(password:password));identity=fresh;selected=entry;return entry
    }
    public func select(_ id:String,password:String = "") throws -> SavedIdentity {
        let entry=try store.entry(id)
        if let token=entry.token {_ = try token.validated();identity=nil;selected=entry}
        else {
            let fresh=try SoftwareMailIdentity.loadPKCS12(store.encryptedFile(entry),password:password)
            try require(fresh.profile.rawValue==entry.profile && fresh.availableModes==entry.modes,"Saved metadata does not match identity")
            identity=fresh;selected=entry
        }
        return entry
    }
    public func exportPKCS12() throws -> Data {
        guard let entry=selected,!entry.isYubiKey else {throw MailCryptoError.invalid("Select a software .p12 identity")}
        return try store.encryptedFile(entry)
    }
    public func importTokenCredentials(_ credentials:[YubiKeyCredential]) throws -> [SavedIdentity] {
        try require(!credentials.isEmpty && credentials.count<=16,"Invalid token credential count")
        // Validate the complete set before any writes.
        let pending=try credentials.map {c -> SavedIdentity in
            let (s,_)=try c.validated()
            return SavedIdentity(id:UUID().uuidString,label:try c.label,profile:s.algorithm.profile.rawValue,modes:[s.algorithm.hybrid],token:c)
        }
        let existing=try store.list();var entries:[SavedIdentity]=[]
        for e in pending {
            if let duplicate=existing.first(where:{$0.token?.signingDER==e.token?.signingDER && $0.token?.encryptionDER==e.token?.encryptionDER && $0.token?.serial==e.token?.serial && $0.token?.signingSlot==e.token?.signingSlot && $0.token?.traditionalSlot==e.token?.traditionalSlot && $0.token?.kemSlot==e.token?.kemSlot && $0.token?.ecdhSlot==e.token?.ecdhSlot}) {entries.append(duplicate)}
            else {try store.save(e);entries.append(e)}
        };return entries
    }
    private func hardware<T:Sendable>(_ pin:String?,_ transport:YubiKeyTransport,_ action:@Sendable (PIVOperation) async throws -> T) async throws -> T {
        guard let pin else {throw MailCryptoError.invalid("Enter the YubiKey PIN before connecting")}
        var bytes=Array(pin.utf8);defer{_ = bytes.withUnsafeMutableBytes{$0.initializeMemory(as:UInt8.self,repeating:0)}}
        try PIVOperation.validatePIN(bytes)
        let connection=try await YubiKitConnection.open(transport)
        let operation=try PIVOperation(connection:connection,pin:bytes)
        return try await withTaskCancellationHandler {
            do {let result=try await action(operation);await operation.finish();return result}
            catch {await operation.finish();throw error}
        } onCancel: {Task {await connection.close()}}
    }
    public func compose(profile: Profile,hybrid: Bool,to: String,subject: String,text: String,encrypt: Bool,recipient: Data?,pin:String?=nil,transport:YubiKeyTransport = .nfc,format:MailFormat = .smime) async throws -> Data {
        if format == .openPGP {try require(profile == .level3 && hybrid,"OpenPGP requires the Level 3 hybrid profile");return try await composeOpenPGP(to:to,subject:subject,text:text,encrypt:encrypt,recipient:recipient,pin:pin,transport:transport)}
        guard let selected else {throw MailCryptoError.invalid("Select and unlock an identity first")}
        try require(selected.profile==profile.rawValue && selected.modes.contains(hybrid),"Select a credential matching the outgoing profile")
        if let token=selected.token {
            let (sc,ec)=try token.validated()
            let recipientDER=try encrypt ? (recipient.map{try Self.certificateDER($0)} ?? ec.der) : nil
            let attrs=try SMIME.signingAttributes(SMIME.plain(text),sc.algorithm).der
            // Validate message/recipient fields before opening a hardware session.
            try SoftwareMailIdentity.validateEmail(to)
            try require(!subject.utf8.contains(10) && !subject.utf8.contains(13) && subject.count<=500,"Invalid subject")
            if let recipientDER {let c=try MailCertificate(recipientDER,signing:false);try require(c.email.caseInsensitiveCompare(to) == .orderedSame,"Recipient address does not match certificate")}
            let signature=try await hardware(pin,transport) {try await $0.sign(attrs,credential:token)}
            return try SMIME.compose(certificate:sc,to:to,subject:subject,text:text,recipientCertificate:recipientDER) {input in
                try require(input==attrs,"Signing input changed");return signature
            }
        }
        guard let id=identity else {throw MailCryptoError.invalid("Unlock the software identity")}
        let cert=try encrypt ? (recipient.map{try Self.certificateDER($0)} ?? id.encryptionCertificate(hybrid:hybrid)) : nil
        return try SMIME.compose(identity:id,hybrid:hybrid,to:to,subject:subject,text:text,recipientCertificate:cert)
    }
    public func open(_ eml:Data,hybrid:Bool,pin:String?=nil,transport:YubiKeyTransport = .nfc,pgpSigner:Data?=nil) async throws -> OpenedMail {
        if OpenPGPMail.isPGP(eml) {return try await openOpenPGP(eml,signer:pgpSigner,pin:pin,transport:transport)}
        guard let token=selected?.token else {return try SMIME.open(eml,identity:identity,hybrid:hybrid)}
        let cert=try token.validated().1
        // Parse and validate all envelope fields before submitting the PIN.
        struct NeedSecret: Error {let ciphertext:Data}
        do {return try SMIME.open(eml) {cms in try SMIME.decryptCMS(cms,certificate:cert) {throw NeedSecret(ciphertext:$0)}}}
        catch let request as NeedSecret {
            let secret=try await hardware(pin,transport) {try await $0.decapsulate(request.ciphertext,credential:token)}
            return try SMIME.open(eml) {cms in try SMIME.decryptCMS(cms,certificate:cert) {ct in
                try require(ct==request.ciphertext,"Ciphertext changed");return secret
            }}
        }
    }
    public func messageFormat(_ eml:Data) -> MailFormat {OpenPGPMail.isPGP(eml) ? .openPGP : .smime}
    public func needsTokenPIN(_ eml:Data) throws -> Bool {
        guard let token=selected?.token else {return false}
        if OpenPGPMail.isPGP(eml) {if try !OpenPGPMail.parts(eml).2{return false};return try OpenPGPMail.envelope(eml,recipient:ownPGP()) != nil}
        let certificate=try token.validated().1
        struct Needed:Error {}
        do {_ = try SMIME.open(eml) {cms in try SMIME.decryptCMS(cms,certificate:certificate) {_ in throw Needed()}};return false}
        catch is Needed {return true}
    }
    public func certificate(hybrid: Bool,signing: Bool) throws -> Data {
        if let token=selected?.token {return signing ? token.signingDER : token.encryptionDER}
        guard let id=identity else {throw MailCryptoError.invalid("Unlock a software identity or select a YubiKey credential")}
        return try signing ? id.signingCertificate(hybrid:hybrid) : id.encryptionCertificate(hybrid:hybrid)
    }

    private func pgpKeys() throws -> (ComponentKeys,ComponentKeys,String) {
        guard let selected,selected.profile==3,selected.modes.contains(true) else {throw MailCryptoError.invalid("OpenPGP requires a Level 3 hybrid identity. Level 2 and Level 5 P-384 profiles remain S/MIME-only.")}
        if let token=selected.token {let (s,e)=try token.validated();return(s.keys,e.keys,s.email)}
        guard let identity else{throw MailCryptoError.invalid("Unlock the software identity")}
        return(identity.signingKeys,identity.encryptionKeys,identity.email)
    }
    private func pgpURL() throws -> URL {
        guard let selected,UUID(uuidString:selected.id) != nil else{throw MailCryptoError.invalid("Select an identity")}
        return store.directory.appendingPathComponent(selected.id+".pgp")
    }
    private func ownPGP() throws -> PGP.PublicIdentity {
        let (s,e,email)=try pgpKeys(),url=try pgpURL()
        guard FileManager.default.fileExists(atPath:url.path) else{throw MailCryptoError.invalid("Create the OpenPGP public identity first, then share its public key with your recipient.")}
        try require((try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? Int.max)<=128*1024,"OpenPGP identity too large")
        let own=try PGP.PublicIdentity(Data(contentsOf:url))
        try require(try own.email==email && PGP.raw(own.signing.pq)==PGP.raw(s.pq) && PGP.raw(own.signing.ec!)==PGP.raw(s.ec!) && PGP.raw(own.encryption.pq)==PGP.raw(e.pq) && PGP.raw(own.encryption.ec!)==PGP.raw(e.ec!),"Saved OpenPGP identity does not match selected keys")
        return own
    }
    public func importOwnOpenPGP(_ data:Data) throws -> String {
        let own=try PGP.PublicIdentity(data),(s,e,email)=try pgpKeys(),url=try pgpURL()
        try require(try own.email==email && PGP.raw(own.signing.pq)==PGP.raw(s.pq) && PGP.raw(own.signing.ec!)==PGP.raw(s.ec!) && PGP.raw(own.encryption.pq)==PGP.raw(e.pq) && PGP.raw(own.encryption.ec!)==PGP.raw(e.ec!),"OpenPGP public identity does not match selected keys/email")
        if FileManager.default.fileExists(atPath:url.path) {
            let existing=try ownPGP()
            try require(try existing.fingerprint==own.fingerprint && existing.encryptionFingerprint==own.encryptionFingerprint,"A different OpenPGP identity is already saved for these keys")
        }
        #if os(iOS)
        try own.encoded.write(to:url,options:[.atomic,.completeFileProtection])
        #else
        try own.encoded.write(to:url,options:.atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
        return try openPGPDescription(data)
    }
    public func exportOpenPGP() throws -> Data {try PGP.armor(ownPGP().encoded,"PUBLIC KEY BLOCK")}
    public func createOpenPGP(pin:String?=nil,transport:YubiKeyTransport = .nfc) async throws -> String {
        let (s,e,email)=try pgpKeys(),url=try pgpURL()
        if FileManager.default.fileExists(atPath:url.path) {return try openPGPDescription(exportOpenPGP())}
        let created=Int(Date().timeIntervalSince1970),own:PGP.PublicIdentity
        if let token=selected?.token {
            own=try await hardware(pin,transport) {op in
                try await PGP.makePublic(signing:s,encryption:e,email:email,created:created) {try await op.signOpenPGP($0,credential:token)}
            }
        }else{
            own=try await PGP.makePublic(signing:s,encryption:e,email:email,created:created) {try PGP.signDigest($0,s)}
        }
        #if os(iOS)
        try own.encoded.write(to:url,options:[.atomic,.completeFileProtection])
        #else
        try own.encoded.write(to:url,options:.atomic)
        #endif
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
        return try openPGPDescription(PGP.armor(own.encoded,"PUBLIC KEY BLOCK"))
    }
    public func openPGPDescription(_ data:Data) throws -> String {
        let own=try PGP.PublicIdentity(data)
        return try own.email+" · OpenPGP Level 3 hybrid (draft-05)\nFingerprint: "+own.fingerprint.hex+"\nSelf-signatures and encryption subkey binding verified. Trust is not established; confirm this fingerprint independently."
    }
    private func composeOpenPGP(to:String,subject:String,text:String,encrypt:Bool,recipient:Data?,pin:String?,transport:YubiKeyTransport) async throws -> Data {
        let own=try ownPGP(),keys=try pgpKeys().0
        let rec=try encrypt ? (recipient.map{try PGP.PublicIdentity($0)} ?? own) : nil
        try SoftwareMailIdentity.validateEmail(to)
        try require(!subject.utf8.contains(10) && !subject.utf8.contains(13) && subject.count<=500,"Invalid subject")
        if let rec {try require(rec.email.caseInsensitiveCompare(to) == .orderedSame,"OpenPGP recipient address mismatch")}
        if let token=selected?.token {
            return try await hardware(pin,transport) {op in
                try await OpenPGPMail.compose(identity:own,recipient:rec,to:to,subject:subject,text:text) {try await op.signOpenPGP($0,credential:token)}
            }
        }
        return try await OpenPGPMail.compose(identity:own,recipient:rec,to:to,subject:subject,text:text) {try PGP.signDigest($0,keys)}
    }
    private func openOpenPGP(_ eml:Data,signer:Data?,pin:String?,transport:YubiKeyTransport) async throws -> OpenedMail {
        let (_,_,encrypted)=try OpenPGPMail.parts(eml)
        let own=encrypted || signer==nil ? try ownPGP() : nil
        let verification=try signer.map{try PGP.PublicIdentity($0)} ?? own!
        if let token=selected?.token,encrypted {
            guard let envelope=try OpenPGPMail.envelope(eml,recipient:own!) else{throw MailCryptoError.invalid("Missing encrypted message")}
            let kek=try await hardware(pin,transport) {try await $0.decapsulateOpenPGP(envelope.ciphertext,credential:token)}
            return try OpenPGPMail.open(eml,signer:verification,recipient:own) {ct in try require(ct==envelope.ciphertext,"Ciphertext changed");return kek}
        }
        let keys=encrypted ? try pgpKeys().1 : nil
        return try OpenPGPMail.open(eml,signer:verification,recipient:own) {ct in
            guard let keys else{throw MailCryptoError.invalid("Select a decryption identity")}
            return try PGP.decapsulate(ct,keys)
        }
    }
    public func recipientDescription(_ data: Data) throws -> String {
        let c=try MailCertificate(Self.certificateDER(data),signing:false)
        return "\(c.email) · \(c.algorithm.hybrid ? c.algorithm.profile.hybridEncryptionName : c.algorithm.profile.mlKEM)\nSHA-256: \(try NativeCrypto.digest("SHA256",c.der).hex)\nConfirm this fingerprint with the recipient. Import does not establish trust."
    }
    static func certificateDER(_ data: Data) throws -> Data {
        try require(data.count<=128*1024,"Certificate too large")
        if let s=String(data:data,encoding:.utf8),s.hasPrefix("-----BEGIN CERTIFICATE-----") {
            let stripped=s.replacingOccurrences(of:"-----BEGIN CERTIFICATE-----",with:"").replacingOccurrences(of:"-----END CERTIFICATE-----",with:"").filter{!$0.isWhitespace}
            guard let decoded=Data(base64Encoded:stripped) else {throw MailCryptoError.invalid("Invalid PEM certificate")};return decoded
        }
        return data
    }
    #if DEBUG
    public func openPGPSelfTest() async throws -> String {
        let directory=FileManager.default.temporaryDirectory.appendingPathComponent("PQMail-PGP-test-"+UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:directory)}
        let test=LocalMailService(storeURL:directory)
        let entry=try await test.create(profile:.level3,email:"ios-test@example.com",password:"synthetic-test-password")
        _ = try await test.createOpenPGP()
        let publicKey=try await test.exportOpenPGP()
        await test.lock()
        let restored=LocalMailService(storeURL:directory)
        _ = try await restored.select(entry.id,password:"synthetic-test-password")
        try require(try await restored.exportOpenPGP()==publicKey,"OpenPGP persistence failed")
        var lines=["PASS encrypted .p12 and OpenPGP public identity restored"]
        for encrypted in [false,true] {
            let eml=try await restored.compose(profile:.level3,hybrid:true,to:"ios-test@example.com",subject:"Synthetic OpenPGP",text:"OpenPGP simulator test",encrypt:encrypted,recipient:nil,format:.openPGP)
            let opened=try await restored.open(eml,hybrid:true)
            try require(opened.text=="OpenPGP simulator test" && opened.encrypted==encrypted,"OpenPGP round trip failed")
            lines.append("PASS OpenPGP Level 3 hybrid: "+(encrypted ? "sign/encrypt/decrypt/verify" : "sign/verify"))
        }
        return lines.joined(separator:"\n")+"\nNo email sent; no YubiKey operations."
    }
    public func selfTest(outputDirectory: URL? = nil) throws -> String {try CryptoSelfTest.run(outputDirectory:outputDirectory)}
    #endif
}

#if DEBUG
/// Uses only newly generated synthetic identities. Optional fixture export is for
/// simulator/desktop interoperability tests, never the user's session identity.
enum CryptoSelfTest {
    static func run(outputDirectory: URL?) throws -> String {
        var lines=[NativeCrypto.version]
        for p in Profile.allCases {
            let id=try SoftwareMailIdentity(profile:p,email:"ios-test@example.com")
            let wrong=try SoftwareMailIdentity(profile:p,email:"ios-test@example.com")
            for h in [false,true] {
                let name="level\(p.rawValue)-\(h ? "hybrid" : "pure")"
                let dir=outputDirectory?.appendingPathComponent(name)
                if let dir {
                    try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
                    func write(_ data: Data,_ file: String) throws {try data.write(to:dir.appendingPathComponent(file),options:.atomic);try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:dir.appendingPathComponent(file).path)}
                    try write(id.signingCertificate(hybrid:h),"sign.cer");try write(id.encryptionCertificate(hybrid:h),"kem.cer")
                    try write(id.signingKeys.pq.export(privateKey:true),"sign-pq.pk8");try write(id.encryptionKeys.pq.export(privateKey:true),"kem-pq.pk8")
                    if h {try write(id.signingKeys.ec!.export(privateKey:true),"sign-ec.pk8");try write(id.encryptionKeys.ec!.export(privateKey:true),"kem-ec.pk8")}
                }
                for encrypted in [false,true] {
                    let eml=try SMIME.compose(identity:id,hybrid:h,to:id.email,subject:"Synthetic test",text:"iOS interoperability test",recipientCertificate:encrypted ? id.encryptionCertificate(hybrid:h) : nil)
                    let opened=try SMIME.open(eml,identity:id,hybrid:h)
                    try require(opened.text=="iOS interoperability test" && opened.encrypted==encrypted && opened.fromMatches,"Round trip failed")
                    var cms=try MIMEPart(eml).decoded();cms[cms.count-1] ^= 1
                    do {_ = try SMIME.open(SMIME.mime(cms,encrypted:encrypted),identity:id,hybrid:h);throw MailCryptoError.invalid("Tampering accepted")} catch MailCryptoError.invalid(let s) {if s=="Tampering accepted" {throw MailCryptoError.invalid(s)}}
                    if encrypted {
                        do {_ = try SMIME.open(eml,identity:wrong,hybrid:h);throw MailCryptoError.invalid("Wrong identity accepted")} catch MailCryptoError.invalid(let s) {if s=="Wrong identity accepted" {throw MailCryptoError.invalid(s)}}
                    }
                    if let dir {try eml.write(to:dir.appendingPathComponent(encrypted ? "ios-encrypted.eml" : "ios-signed.eml"))}
                    lines.append("PASS \(name): \(encrypted ? "sign/encrypt/decrypt/verify" : "sign/verify"); tampering rejected")
                }
            }
        }
        lines.append("SUCCESS: six profiles, twelve round trips; no email sent; no YubiKey operations")
        return lines.joined(separator:"\n")
    }
}
#endif
