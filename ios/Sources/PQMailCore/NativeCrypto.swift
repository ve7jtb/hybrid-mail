import Foundation
import CNative

public enum MailCryptoError: Error, LocalizedError {
    case invalid(String)
    public var errorDescription: String? { if case .invalid(let s) = self { return s }; return nil }
}
func require(_ condition: Bool, _ message: String) throws { if !condition { throw MailCryptoError.invalid(message) } }
extension Data {
    func bytes<T>(_ body: (UnsafePointer<UInt8>?) throws -> T) rethrows -> T { try withUnsafeBytes { try body($0.bindMemory(to: UInt8.self).baseAddress) } }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
func take(_ b: PQBuffer) throws -> Data { defer { pq_buffer_free(b) }; guard let p = b.data else { throw MailCryptoError.invalid("OpenSSL operation failed") }; return Data(bytes: p, count: b.count) }
public enum NativeCrypto {
    public static var version: String { String(cString: pq_version()) }
    static func random(_ n: Int) throws -> Data { try take(pq_random(n)) }
    static func digest(_ name: String, _ input: Data) throws -> Data { try input.bytes { try take(pq_digest(name,$0,input.count)) } }
    static func hkdf(_ secret: Data, _ info: Data) throws -> Data { try secret.bytes { s in try info.bytes { try take(pq_hkdf(s,secret.count,$0,info.count)) } } }
    static func wrap(_ encrypt: Bool, _ key: Data, _ input: Data) throws -> Data {
        try require(key.count == 32, "Invalid AES wrapping key")
        return try key.bytes { k in try input.bytes { try take(pq_wrap(encrypt ? 1 : 0,k,$0,input.count)) } }
    }
    static func gcm(_ encrypt: Bool, _ key: Data, _ nonce: Data, _ input: Data, aad: Data = Data()) throws -> Data {
        try require(key.count == 32 && nonce.count == 12, "Invalid AES-GCM key or nonce")
        return try key.bytes { k in try nonce.bytes { iv in try aad.bytes { a in try input.bytes { try take(pq_gcm(encrypt ? 1 : 0,k,iv,a,aad.count,$0,input.count)) } } } }
    }
}
final class NativeKey: @unchecked Sendable {
    let handle: UnsafeMutableRawPointer
    init(algorithm: String, group: String = "") throws { guard let h = pq_key_generate(algorithm,group) else { throw MailCryptoError.invalid("Cannot generate \(algorithm)") }; handle=h }
    init(der: Data, privateKey: Bool = false) throws { guard let h = der.bytes({ pq_key_read($0,der.count,privateKey ? 1 : 0) }) else { throw MailCryptoError.invalid("Invalid or unsupported key encoding") };handle=h }
    deinit { pq_key_free(handle) }
    func export(privateKey: Bool = false) throws -> Data { try take(pq_key_export(handle,privateKey ? 1 : 0)) }
    func sign(_ message: Data, digest: String = "", context: Data = Data()) throws -> Data { try context.bytes { c in try message.bytes { try take(pq_sign(handle,digest,c,context.count,$0,message.count)) } } }
    func verify(_ signature: Data, message: Data, digest: String = "", context: Data = Data()) throws {
        let ok = context.bytes { c in message.bytes { m in signature.bytes { pq_verify(handle,digest,c,context.count,m,message.count,$0,signature.count) } } }
        try require(ok == 1, "Invalid signature")
    }
    func encapsulate() throws -> (Data,Data) {
        var ct=PQBuffer(), ss=PQBuffer()
        try require(pq_encapsulate(handle,&ct,&ss)==1,"KEM encapsulation failed")
        defer { pq_buffer_free(ct);pq_buffer_free(ss) }
        return (Data(bytes:ct.data!,count:ct.count),Data(bytes:ss.data!,count:ss.count))
    }
    func decapsulate(_ ct: Data) throws -> Data { try ct.bytes { try take(pq_decapsulate(handle,$0,ct.count)) } }
    func derive(_ peer: NativeKey) throws -> Data { try take(pq_ecdh(handle,peer.handle)) }
}
