import Foundation

public struct SavedIdentity: Codable, Identifiable, Sendable {
    public let id: String
    public let label: String
    public let profile: Int
    public let modes: [Bool]
    public let token: YubiKeyCredential?
    public var isYubiKey: Bool {token != nil}
}
struct IdentityStore {
    let directory: URL
    init(directory: URL? = nil) {
        self.directory=directory ?? FileManager.default.urls(for:.applicationSupportDirectory,in:.userDomainMask)[0].appendingPathComponent("PQMail/Identities",isDirectory:true)
    }
    func list() throws -> [SavedIdentity] {
        guard FileManager.default.fileExists(atPath:directory.path) else {return []}
        let files=try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil).filter{$0.pathExtension=="json"}
        try require(files.count<=100,"Too many saved identities")
        return try files.map {url in
            let data=try Data(contentsOf:url);try require(data.count<=512*1024,"Invalid identity metadata size")
            let entry=try JSONDecoder().decode(SavedIdentity.self,from:data)
            try require(UUID(uuidString:entry.id) != nil && url.deletingPathExtension().lastPathComponent==entry.id,"Invalid identity record")
            return entry
        }.sorted{$0.label<$1.label}
    }
    func entry(_ id:String) throws -> SavedIdentity {guard let e=try list().first(where:{$0.id==id}) else {throw MailCryptoError.invalid("Select a saved identity")};return e}
    func encryptedFile(_ entry:SavedIdentity) throws -> Data {
        try require(UUID(uuidString:entry.id) != nil && !entry.isYubiKey,"Not a software identity")
        let url=directory.appendingPathComponent(entry.id+".p12")
        try require((try url.resourceValues(forKeys:[.fileSizeKey]).fileSize ?? Int.max)<=1024*1024,"Identity file too large")
        return try Data(contentsOf:url)
    }
    func save(_ entry:SavedIdentity,encrypted:Data?=nil) throws {
        try require(UUID(uuidString:entry.id) != nil,"Invalid identity ID")
        try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        func write(_ data:Data,_ ext:String) throws {
            let url=directory.appendingPathComponent(entry.id+ext)
            #if os(iOS)
            try data.write(to:url,options:[.atomic,.completeFileProtection])
            #else
            try data.write(to:url,options:.atomic)
            #endif
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
        }
        if let encrypted {try write(encrypted,".p12")}
        try write(JSONEncoder().encode(entry),".json")
    }
}
