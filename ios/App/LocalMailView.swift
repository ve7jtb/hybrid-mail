import SwiftUI
import UniformTypeIdentifiers
import PQMailCore

struct MailFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var data: Data
    init(_ data: Data) {self.data=data}
    init(configuration: ReadConfiguration) throws {data=configuration.file.regularFileContents ?? Data()}
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {FileWrapper(regularFileWithContents:data)}
}

struct LocalMailView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var service=LocalMailService()
    @State private var saved:[SavedIdentity]=[]
    @State private var selected:SavedIdentity?
    @State private var profile=Profile.level3
    @State private var hybrid=true
    @State private var format=MailFormat.smime
    @State private var pgpRecipient:Data?
    @State private var pgpSigner:Data?
    @State private var pgpRecipientInfo="Encryption uses my OpenPGP public identity."
    @State private var pgpSignerInfo="Verification uses my OpenPGP public identity."
    private var pgpSupported:Bool {selected?.profile==3 && selected?.modes.contains(true)==true}
    @State private var email="ios-test@example.com"
    @State private var to="ios-test@example.com"
    @State private var subject="PQ Mail iOS test"
    @State private var bodyText="A signed message from PQ Mail for iOS."
    @State private var encrypt=false
    @State private var recipient:Data?
    @State private var recipientInfo="Encryption uses the selected identity's certificate."
    @State private var status=""
    @State private var busy=false
    @State private var job:Task<Void,Never>?
    #if USB_ONLY
    @State private var transport=YubiKeyTransport.usb
    #else
    @State private var transport=YubiKeyTransport.nfc
    #endif
    @State private var importing=false
    @State private var importKind="message"
    @State private var exporting=false
    @State private var exportFile=MailFile(Data())
    @State private var exportName="PQ-Mail.eml"
    @State private var exportType=UTType.data
    @State private var secretSheet=false
    @State private var secret=""
    @State private var confirmation=""
    @State private var secretAction="create"
    @State private var pendingID=""
    @State private var pendingData=Data()
    @State private var pendingPGP=false
    @State private var onKeyReview:OnKeyBundle?
    @State private var pendingOnKey:OnKeyBundle?
    @State private var review:[YubiKeyCredential]=[]
    @State private var reviewText=""
    @State private var reviewSheet=false
    private var availableIdentities:[SavedIdentity] {
        #if SOFTWARE_ONLY
        return saved.filter { !$0.isYubiKey }
        #else
        return saved
        #endif
    }
    private var managementAction:Bool {secretAction=="onkey-write" || secretAction=="onkey-migrate"}
    private var token:Bool {selected?.isYubiKey == true}
    private var pinAction:Bool {secretAction=="sign" || secretAction=="decrypt" || secretAction=="pgp-create" || secretAction=="onkey-sign"}
    var body:some View {
        NavigationStack {
            Form {
                section0
                section1
                section2
                #if !SOFTWARE_ONLY
                section3
                #endif
                pgpSection
                section4
                section5
                #if DEBUG
                Section("Software tests") {
                    Button("Test all six S/MIME profiles — no email") {perform {status=try await service.selfTest()}}
                    Button("Test OpenPGP — no email") {perform {status=try await service.openPGPSelfTest()}}
                }
                #endif
                Section {Text(NativeCrypto.version).font(.caption)}
            }
            .disabled(busy)
            .overlay {if busy {VStack {ProgressView(token ? "Keep the YubiKey connected…" : "Working…");Button("Cancel") {job?.cancel()}}.padding().background(.regularMaterial).clipShape(RoundedRectangle(cornerRadius:12))}}
            .navigationTitle("PQ Mail")
            .sheet(isPresented:$secretSheet,onDismiss:{secret="";confirmation=""}) {secretView}
            .sheet(isPresented:$reviewSheet) {
                NavigationStack {ScrollView {Text(reviewText).padding().textSelection(.enabled)}
                    .navigationTitle("Review YubiKey certificates")
                    .toolbar {
                        ToolbarItem(placement:.cancellationAction) {Button("Cancel"){reviewSheet=false;review=[]}}
                        ToolbarItem(placement:.confirmationAction) {Button("Import"){let items=review;reviewSheet=false;perform {if let bundle=onKeyReview{try await service.importOnKey(bundle);onKeyReview=nil}else{_ = try await service.importTokenCredentials(items)};saved=try await service.savedIdentities();status="Public credentials saved. Select a pure or hybrid entry to use it."}}}
                    }}
            }
            .fileImporter(isPresented:$importing,allowedContentTypes:[.data]) {result in
                perform {
                    let url=try result.get();let access=url.startAccessingSecurityScopedResource();defer{if access{url.stopAccessingSecurityScopedResource()}}
                    let size=try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? Int.max
                    guard size<=20*1024*1024 else {throw MailCryptoError.invalid("File exceeds 20 MiB")}
                    let data=try Data(contentsOf:url)
                    switch importKind {
                    case "certificate":recipientInfo=try await service.recipientDescription(data);recipient=data
                    case "pgp-own":status=try await service.importOwnOpenPGP(data)
                    case "pgp-recipient":pgpRecipientInfo=try await service.openPGPDescription(data);pgpRecipient=data
                    case "pgp-signer":pgpSignerInfo=try await service.openPGPDescription(data);pgpSigner=data
                    case "p12":pendingData=data;ask("import")
                    case "bundle":onKeyReview=nil;review=try YubiKeyCredential.importBundle(data);reviewText=try review.map{try $0.review}.joined(separator:"\n\n");reviewSheet=true
                    default:
                        pendingData=data
                        pendingPGP=await service.messageFormat(data) == .openPGP
                        let needsPIN=try await service.needsTokenPIN(data)
                        if token && needsPIN {ask("decrypt")}
                        else {try await openMessage(data,nil)}
                    }
                }
            }
            .fileExporter(isPresented:$exporting,document:exportFile,contentType:exportType,defaultFilename:exportName) {result in if case .failure(let e)=result{status=e.localizedDescription}}
            .task {
                do {saved=try await service.savedIdentities()} catch {status=error.localizedDescription}
                #if DEBUG && targetEnvironment(simulator)
                if ProcessInfo.processInfo.arguments.contains("--crypto-self-test") {perform {
                    let docs=FileManager.default.urls(for:.documentDirectory,in:.userDomainMask)[0]
                    do {status=try await service.selfTest(outputDirectory:docs.appendingPathComponent("CryptoSelfTest"))}
                    catch {status="FAIL: "+error.localizedDescription}
                    try status.write(to:docs.appendingPathComponent("crypto-results.txt"),atomically:true,encoding:.utf8)
                }}
                if ProcessInfo.processInfo.arguments.contains("--openpgp-self-test") {perform {
                    let docs=FileManager.default.urls(for:.documentDirectory,in:.userDomainMask)[0]
                    do {status=try await service.openPGPSelfTest()}
                    catch {status="FAIL: "+error.localizedDescription}
                    try status.write(to:docs.appendingPathComponent("openpgp-results.txt"),atomically:true,encoding:.utf8)
                }}
                #endif
            }
            .onChange(of:format) {value in if value == .openPGP {hybrid=true}}
            .onChange(of:scenePhase) {phase in
                if phase == .background && !busy {secret="";confirmation="";Task {await service.lock();selected=nil;format = .smime}}
            }
        }
    }
    private var section0:some View {
Section("Local encrypted mail") {
                    #if SOFTWARE_ONLY
                    Text("Software-only preview. YubiKey NFC and USB-C are unavailable in this build.").font(.headline)
                    #endif
                    Text("Sign, encrypt and open .eml files. No mail account or sending. Software private keys are saved in password-protected .p12 files; YubiKey credentials contain public certificates and slot mappings only.").font(.footnote)
                }
    }
    private var section1:some View {
Section("Saved identities") {
                    ForEach(availableIdentities) {entry in
                        Button((selected?.id==entry.id ? "✓ " : "")+entry.label) {
                            if entry.isYubiKey {perform {activate(try await service.select(entry.id))}}
                            else {pendingID=entry.id;ask("unlock")}
                        }
                    }
                    Text(selected?.label ?? "Select an identity; software identities require their .p12 password.").font(.caption)
                    if selected != nil {
                        if selected!.modes.count>1 && format == .smime {Toggle("Use hybrid profile",isOn:$hybrid)}
                        Text(hybrid ? profile.hybridSigningName+"\n"+profile.hybridEncryptionName : profile.mlDSA+"\n"+profile.mlKEM).font(.caption)
                        Button("Export signing certificate") {exportCertificate(true)}
                        Button("Export encryption certificate") {exportCertificate(false)}
                        Button("Lock / deselect") {perform {await service.lock();selected=nil;format = .smime}}
                    }
                }
    }
    private var section2:some View {
Section("Software .p12 identities") {
                    TextField("Certificate email",text:$email).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("New identity level",selection:$profile) {ForEach(Profile.allCases){Text("Level \($0.rawValue)").tag($0)}}
                        .disabled(selected != nil)
                    Button("Create four software keys") {ask("create")}
                    Button("Import password-protected .p12") {startImport("p12")}
                    if selected != nil && !token {Button("Export encrypted .p12") {perform {save(try await service.exportPKCS12(),"PQ-Mail-identity.p12")}}}
                }
    }
    private var section3:some View {
Section("YubiKey credentials") {
                    Button("Import certificates from YubiKey — no PIN") {perform {let bundle=try await service.readOnKey(transport:transport);onKeyReview=bundle;review=bundle.credentials;reviewText=try bundle.review;reviewSheet=true;status="Read complete — remove your key."}}
                    if token {
                        Button("Save certificates on YubiKey…") {ask("onkey-sign")}
                        Button("Migrate signing key 9a → 83…") {ask("onkey-migrate")}
                        Text("On-key certificates, OpenPGP public identities and slot mappings are public. Saving requires a signing PIN, then management-key authorization. Migration moves the existing ECDSA key only into empty 83; it does not generate keys. Save the bundle again after migration.").font(.footnote)
                    }
                    Button("Import device certificate bundle (.pqcert)") {startImport("bundle")}
                    Text("Use Share certificates → move to another device on desktop or Android. Review the public certificates, serial and four slots before import. No token keys are generated or replaced.").font(.footnote)
                    #if USB_ONLY
                    Text("Connection: USB-C. NFC is disabled in this build.")
                    #else
                    Picker("Connection",selection:$transport) {ForEach(YubiKeyTransport.allCases,id:\.self){Text($0.rawValue).tag($0)}}
                    #endif
                    if let c=selected?.token {Text("Required YubiKey: \(c.serial)").font(.caption)}
                }
    }
    private var section4:some View {
Section("Compose") {
                    Picker("Message format",selection:$format) {
                        Text("S/MIME").tag(MailFormat.smime)
                        if pgpSupported {Text("OpenPGP (Level 3 hybrid draft)").tag(MailFormat.openPGP)}
                    }
                    TextField("To",text:$to).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Subject",text:$subject)
                    TextEditor(text:$bodyText).frame(minHeight:90)
                    Toggle("Also encrypt",isOn:$encrypt)
                    if encrypt && format == .openPGP {
                        Button("Import recipient OpenPGP public key") {startImport("pgp-recipient")}
                        Text(pgpRecipientInfo).font(.caption).textSelection(.enabled)
                        if pgpRecipient != nil {Button("Use my OpenPGP public key"){pgpRecipient=nil;pgpRecipientInfo="Encryption uses my OpenPGP public identity."}}
                    }
                    if encrypt && format == .smime {
                        Button("Import recipient encryption certificate") {startImport("certificate")}
                        Text(recipientInfo).font(.caption).textSelection(.enabled)
                        if recipient != nil {Button("Use my certificate") {recipient=nil;recipientInfo="Encryption uses the selected identity's certificate."}}
                    }
                    Button("Sign and save .eml") {if token {ask("sign")} else {compose(nil)}}
                        .disabled(selected==nil)
                }
    }
    private var section5:some View {
Section("Open and verify") {
                    Button("Open S/MIME .eml") {startImport("message")}
                    Text("Select the matching credential and pure/hybrid mode for decryption. A valid signature does not automatically establish signer trust.").font(.footnote)
                    Text(status).textSelection(.enabled)
                }
    }
    private var pgpSection:some View {
        Section("OpenPGP public identities") {
            Text("Draft-05 Level 3 hybrid only. Existing software/YubiKey keys are reused; OpenPGP fingerprints and self-signatures are separate from X.509 certificates. No changes are made to the YubiKey.").font(.footnote)
            if pgpSupported {
                Button("Create OpenPGP public identity") {
                    if token {ask("pgp-create")}
                    else {perform {status=try await service.createOpenPGP()}}
                }
                Button("Import my existing OpenPGP public identity"){startImport("pgp-own")}
                Button("Export OpenPGP public key (.asc)") {perform {save(try await service.exportOpenPGP(),"PQ-Mail-public.asc")}}
            }
            Button("Import sender OpenPGP public key") {startImport("pgp-signer")}
            Text(pgpSignerInfo).font(.caption).textSelection(.enabled)
            if pgpSigner != nil {Button("Verify with my OpenPGP public key"){pgpSigner=nil;pgpSignerInfo="Verification uses my OpenPGP public identity."}}
        }
    }
    private var operationAlgorithms:String {
        if secretAction=="pgp-create" {return "OpenPGP ML-DSA-65 + ECDSA P-384: three public identity binding signatures"}
        if secretAction=="sign" {
            return format == .openPGP ? "OpenPGP ML-DSA-65 + ECDSA P-384 · SHA-384" : (hybrid ? profile.hybridSigningName : profile.mlDSA)
        }
        return pendingPGP ? "OpenPGP ML-KEM-768 + ECDH P-384" : (hybrid ? profile.hybridEncryptionName : profile.mlKEM)
    }
    private var secretView:some View {
        NavigationStack {Form {
            if managementAction {Text(secretAction=="onkey-migrate" ? "Move the existing ECDSA key from 9a to empty 83 and update local mappings. No key generation. If interrupted, inspect before retrying.":"Write the signed public identity bundle. Anyone holding the YubiKey can read it. The previous bank is retained until commit.");Text("Enter the management key in hex, not your PIN. Keep the key connected until completion.")} else if pinAction {
                Text("YubiKey \(selected?.token?.serial ?? 0) · \(transport.rawValue)")
                Text(operationAlgorithms)
                Text("Enter the PIN before connecting. Keep the key in place until the operation finishes. One PIN entry is reused for the hybrid components during this operation, then cleared.")
            } else {Text("The .p12 password protects software private keys. It is not the YubiKey PIN and is not saved. New and imported identities require at least 12 characters.")}
            SecureField(managementAction ? "Management key (hex)" : pinAction ? "YubiKey PIN" : ".p12 password",text:$secret).textInputAutocapitalization(.never).autocorrectionDisabled()
            if secretAction=="create" {SecureField("Confirm password",text:$confirmation)}
        }.navigationTitle(managementAction ? "Authorize YubiKey change" : pinAction ? "YubiKey operation" : "Software identity")
            .toolbar {
                ToolbarItem(placement:.cancellationAction) {Button("Cancel"){secretSheet=false;secret="";confirmation="";pendingData=Data()}}
                ToolbarItem(placement:.confirmationAction) {Button("Continue"){submitSecret()}.disabled(secret.isEmpty || (secretAction=="create" && (secret.count<12 || secret != confirmation)) || (pinAction && (!(6...8).contains(secret.utf8.count) || !secret.utf8.allSatisfy{(32...126).contains($0)})))}
            }}
    }
    private func ask(_ action:String) {secretAction=action;secret="";confirmation="";secretSheet=true}
    private func activate(_ entry:SavedIdentity) {selected=entry;profile=Profile(rawValue:entry.profile) ?? .level3;hybrid=entry.modes.contains(true);if !pgpSupported{format = .smime};status="Selected "+entry.label}
    private func submitSecret() {
        let value=secret,action=secretAction,data=pendingData;secret="";confirmation="";secretSheet=false;pendingData=Data()
        if action=="sign" {compose(value);return}
        perform {
            switch action {
            case "onkey-sign":pendingOnKey=try await service.prepareOnKey(pin:value,transport:transport);status="Bundle signed — remove your key, then authorize storage.";ask("onkey-write")
            case "onkey-write":guard let bundle=pendingOnKey else{throw MailCryptoError.invalid("Sign the bundle first")};try await service.writeOnKey(bundle,management:value,transport:transport);pendingOnKey=nil;status="Bundle saved and verified — remove your key."
            case "onkey-migrate":try await service.migrateOnKey(management:value,transport:transport);if let id=selected?.id{activate(try await service.select(id))};status="Migration complete — remove your key. Save the on-key bundle again to update its mapping."
            case "create":activate(try await service.create(profile:profile,email:email,password:value))
            case "unlock":activate(try await service.select(pendingID,password:value))
            case "import":activate(try await service.importPKCS12(data,password:value))
            case "decrypt":try await openMessage(data,value)
            case "pgp-create":status=try await service.createOpenPGP(pin:value,transport:transport)+"\nYou can remove your YubiKey now."
            default:break
            }
            saved=try await service.savedIdentities()
        }
    }
    private func startImport(_ kind:String){importKind=kind;importing=true}
    private func save(_ data:Data,_ name:String) {exportFile=MailFile(data);exportName=name;exportType=UTType(filenameExtension:(name as NSString).pathExtension) ?? .data;exporting=true}
    private func compose(_ pin:String?) {perform {
        let data=try await service.compose(profile:profile,hybrid:hybrid,to:to,subject:subject,text:bodyText,encrypt:encrypt,recipient:format == .openPGP ? pgpRecipient : recipient,pin:pin,transport:transport,format:format)
        status="Message created. Nothing sent."+(token ? " You can remove your YubiKey now." : "")
        save(data,encrypt ? "PQ-Mail-encrypted.eml" : "PQ-Mail-signed.eml")
    }}
    private func openMessage(_ data:Data,_ pin:String?) async throws {
        let opened=try await service.open(data,hybrid:hybrid,pin:pin,transport:transport,pgpSigner:pgpSigner)
        status=(token && opened.encrypted ? "You can remove your YubiKey now.\n" : "")+"Signature valid (trust not established)\n\(opened.algorithm)\nSigner: \(opened.signerEmail)\nFrom matches: \(opened.fromMatches)\nEncrypted: \(opened.encrypted)\nSHA-256: \(opened.fingerprint)\n\n\(opened.text)"
    }
    private func exportCertificate(_ signing:Bool) {perform {save(try await service.certificate(hybrid:hybrid,signing:signing),signing ? "PQ-Mail-signing.cer" : "PQ-Mail-encryption.cer")}}
    @MainActor private func perform(_ work:@escaping @MainActor () async throws -> Void) {
        guard !busy else{return};busy=true
        job=Task {do{try await work()}catch{status=error.localizedDescription+(token ? "\nOperation ended; you can remove your YubiKey." : "")};busy=false;job=nil}
    }
}
