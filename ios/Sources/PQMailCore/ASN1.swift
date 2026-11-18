import Foundation

/// Bounded BER reader for CMS; output is canonical DER. Supports constructed
/// indefinite lengths used by streaming CMS, but no high-tag-number encodings.
struct ASN1: Sendable {
    let tag: UInt8
    let value: Data
    let children: [ASN1]
    init(_ tag: UInt8, _ value: Data) { self.tag=tag;self.value=value;children=[] }
    init(_ tag: UInt8, children: [ASN1]) { self.tag=tag;self.children=children;value=Data() }
    var content: Data { children.isEmpty ? value : children.reduce(into: Data()) { $0.append($1.der) } }
    var der: Data {
        let data=content; var length=Data()
        if data.count < 128 { length.append(UInt8(data.count)) }
        else { var n=data.count;while n>0 { length.insert(UInt8(n&255),at:0);n >>= 8 };length.insert(0x80|UInt8(length.count),at:0) }
        return Data([tag])+length+data
    }
    func expect(_ t: UInt8, count: Int? = nil) throws -> ASN1 { try require(tag==t && (count == nil || children.count==count!),"Unexpected ASN.1 structure");return self }
    func child(_ i: Int) throws -> ASN1 { try require(i>=0 && i<children.count,"Missing ASN.1 field");return children[i] }
    func number() throws -> Int { try require(tag==2 && !value.isEmpty && value.count<=4 && value[0]&128==0,"Invalid ASN.1 integer");return value.reduce(0){($0<<8)|Int($1)} }
    func octets() throws -> Data {
        if tag==4 || tag==0x80 { return value }
        try require(tag==0x24 || tag==0xa0,"Expected octets")
        return try children.reduce(into:Data()) { $0.append(try $1.octets()) }
    }
    static func parse(_ data: Data) throws -> ASN1 {
        try require(data.count<=20*1024*1024,"Message exceeds 20 MiB")
        let b=[UInt8](data);var offset=0;var nodes=0
        func read(_ end: Int,_ depth: Int) throws -> ASN1 {
            nodes+=1;try require(depth<32 && nodes<10000 && offset+2<=end,"Invalid ASN.1 bounds")
            let tag=b[offset];let first=b[offset+1];offset+=2
            try require(tag != 0 && tag&31 != 31,"Unsupported ASN.1 tag")
            var n=Int(first)
            if first==0x80 {
                try require(tag&0x20 != 0,"Indefinite primitive")
                var ch:[ASN1]=[]
                while true { try require(offset+2<=end,"Truncated BER");if b[offset]==0 && b[offset+1]==0 {offset+=2;break};ch.append(try read(end,depth+1)) }
                return ASN1(tag,children:ch)
            }
            if first&128 != 0 {
                let c=Int(first&127);try require(c>0 && c<=4 && offset+c<=end,"Invalid ASN.1 length");n=0
                for _ in 0..<c {n=(n<<8)|Int(b[offset]);offset+=1}
            }
            try require(n<=end-offset,"Truncated ASN.1")
            let stop=offset+n
            if tag&0x20 != 0 { var ch:[ASN1]=[];while offset<stop { ch.append(try read(stop,depth+1)) };return ASN1(tag,children:ch) }
            let v=Data(b[offset..<stop]);offset=stop;return ASN1(tag,v)
        }
        let result=try read(b.count,0);try require(offset==b.count,"Trailing ASN.1 data");return result
    }
    static func seq(_ a: [ASN1]) -> ASN1 { ASN1(0x30,children:a) }
    static func set(_ a: [ASN1]) -> ASN1 { ASN1(0x31,children:a.sorted{$0.der.lexicographicallyPrecedes($1.der)}) }
    static func int(_ n: Int) -> ASN1 { var v=n;var bytes=Data();repeat {bytes.insert(UInt8(v&255),at:0);v >>= 8}while v>0;if bytes[0]&128 != 0 {bytes.insert(0,at:0)};return ASN1(2,bytes) }
    static func oid(_ string: String) -> ASN1 {
        let a=string.split(separator:".").map{UInt64($0)!};var bytes=Data()
        for var n in [a[0]*40+a[1]]+a.dropFirst(2) { var b=[UInt8(n&127)];n >>= 7;while n>0 {b.insert(UInt8(n&127)|128,at:0);n >>= 7};bytes.append(contentsOf:b) }
        return ASN1(6,bytes)
    }
    func isOID(_ s: String) -> Bool { tag==6 && value==ASN1.oid(s).value }
    static func alg(_ oid: String) -> ASN1 { .seq([.oid(oid)]) }
    static func bits(_ data: Data) -> ASN1 { ASN1(3,Data([0])+data) }
    func bitBytes() throws -> Data { try require(tag==3 && value.first==0,"Expected byte-aligned bit string");return Data(value.dropFirst()) }
}
