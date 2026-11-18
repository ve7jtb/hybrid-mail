import Foundation

enum OpenPGPMail {
    static func isPGP(_ data:Data)->Bool {
        guard let p=try? MIMEPart(data) else{return false}
        let ct=p.headers["content-type",default:""].lowercased()
        return ct.contains("application/pgp-encrypted") || ct.contains("application/pgp-signature")
    }
    static func parts(_ eml:Data)throws->(MIMEPart,[Data],Bool) {
        let root=try MIMEPart(eml),ct=root.headers["content-type",default:""]
        let encrypted=ct.lowercased().contains("application/pgp-encrypted")
        try require(ct.lowercased().hasPrefix(encrypted ? "multipart/encrypted;" : "multipart/signed;") && (encrypted || ct.lowercased().contains("application/pgp-signature")),"Unsupported PGP/MIME content type")
        let parameters=ct.components(separatedBy:";").dropFirst().map{$0.trimmingCharacters(in:.whitespaces)}
        let bounds=parameters.filter{$0.lowercased().hasPrefix("boundary=")}
        try require(bounds.count==1,"Ambiguous MIME boundary")
        var boundary=String(bounds[0].dropFirst(9))
        if boundary.hasPrefix("\"") && boundary.hasSuffix("\""){boundary=String(boundary.dropFirst().dropLast())}
        try require(!boundary.isEmpty && boundary.count<=70 && boundary.utf8.allSatisfy{(33...126).contains($0)},"Invalid MIME boundary")
        guard let text=String(data:root.body,encoding:.utf8) else{throw MailCryptoError.invalid("Invalid PGP/MIME body")}
        let delimiter="--"+boundary
        let chunks=text.components(separatedBy:delimiter)
        try require(chunks.count==4 && chunks[3].hasPrefix("--"),"Expected two PGP/MIME parts")
        let bodies=try chunks[1...2].map {part -> Data in
            try require(part.hasPrefix("\r\n") && part.hasSuffix("\r\n"),"Invalid PGP/MIME delimiter")
            return Data(Data(part.utf8).dropFirst(2).dropLast(2))
        }
        if encrypted {
            let control=try MIMEPart(bodies[0])
            try require(control.headers["content-type"]?.lowercased()=="application/pgp-encrypted" && String(data:try control.decoded(),encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines)=="Version: 1","Invalid PGP/MIME version")
            let payload=try MIMEPart(bodies[1]);try require(payload.headers["content-type"]?.lowercased().hasPrefix("application/octet-stream")==true,"Invalid PGP/MIME encrypted part")
        }else{
            let signature=try MIMEPart(bodies[1]);try require(signature.headers["content-type"]?.lowercased().hasPrefix("application/pgp-signature")==true,"Invalid PGP/MIME signature part")
        }
        return(root,bodies,encrypted)
    }
    static func wrap(_ first:Data,_ second:Data,encrypted:Bool,from:String,to:String,subject:String)throws->Data {
        try SoftwareMailIdentity.validateEmail(from);try SoftwareMailIdentity.validateEmail(to)
        try require(subject.count<=500 && !subject.utf8.contains(10) && !subject.utf8.contains(13),"Invalid mail subject")
        let boundary="pqmail-"+UUID().uuidString
        let protocolType=encrypted ? "application/pgp-encrypted" : "application/pgp-signature"
        let type=encrypted ? "encrypted" : "signed"
        let header="From: "+from+"\r\nTo: "+to+"\r\nSubject: "+subject+"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/"+type+"; protocol=\""+protocolType+"\"; "+(encrypted ? "" : "micalg=pgp-sha384; ")+"boundary=\""+boundary+"\"\r\n\r\n"
        return Data((header+"--"+boundary+"\r\n").utf8)+first+Data(("\r\n--"+boundary+"\r\n").utf8)+second+Data(("\r\n--"+boundary+"--\r\n").utf8)
    }
    static func compose(identity:PGP.PublicIdentity,recipient:PGP.PublicIdentity?,to:String,subject:String,text:String,signer:@Sendable (Data)async throws->Data) async throws -> Data {
        try SoftwareMailIdentity.validateEmail(to)
        try require(subject.count<=500 && !subject.utf8.contains(10) && !subject.utf8.contains(13),"Invalid subject")
        let plain=try SMIME.plain(text)
        if let recipient {
            try require(recipient.email.caseInsensitiveCompare(to) == .orderedSame,"OpenPGP recipient address mismatch")
            let signed=try await PGP.signedPackets(plain,identity:identity,signer:signer)
            let encrypted=try PGP.encrypt(signed,recipient:recipient)
            return try wrap(Data("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n".utf8),Data("Content-Type: application/octet-stream\r\n\r\n".utf8)+PGP.armor(encrypted,"MESSAGE"),encrypted:true,from:identity.email,to:to,subject:subject)
        }
        let request=try PGP.Signature(data:plain,type:0,fingerprint:identity.fingerprint)
        let signature=try await signer(request.digest);try PGP.verifyDigest(signature,request.digest,identity.signing)
        return try wrap(plain,Data("Content-Type: application/pgp-signature\r\n\r\n".utf8)+PGP.armor(PGP.frame(2,request.finish(signature)),"SIGNATURE"),encrypted:false,from:identity.email,to:to,subject:subject)
    }
    static func envelope(_ data:Data,recipient:PGP.PublicIdentity)throws->PGP.Envelope? {
        let (_,parts,encrypted)=try self.parts(data)
        if !encrypted{return nil}
        return try PGP.Envelope(PGP.unarmor(MIMEPart(parts[1]).decoded(),"MESSAGE"),recipient:recipient)
    }
    static func open(_ data:Data,signer:PGP.PublicIdentity,recipient:PGP.PublicIdentity?,recover:(Data)throws->Data)throws->OpenedMail {
        let (root,parts,encrypted)=try self.parts(data)
        let plain:Data
        if encrypted {
            guard let recipient else{throw MailCryptoError.invalid("Select the matching OpenPGP decryption identity")}
            let envelope=try PGP.Envelope(PGP.unarmor(MIMEPart(parts[1]).decoded(),"MESSAGE"),recipient:recipient)
            plain=try PGP.openSigned(envelope.open(recover(envelope.ciphertext)),signer:signer)
        }else{
            let signatures=try PGP.packets(PGP.unarmor(MIMEPart(parts[1]).decoded(),"SIGNATURE"))
            try require(signatures.count==1 && signatures[0].tag==2,"Expected one detached OpenPGP signature")
            _ = try PGP.verifySignature(signatures[0].body,data:parts[0],type:0,key:signer.primary)
            plain=parts[0]
        }
        let part=try MIMEPart(plain)
        try require(part.headers["content-type",default:""].lowercased().hasPrefix("text/plain"),"This preview supports plain-text OpenPGP mail")
        guard let text=String(data:try part.decoded(),encoding:.utf8) else{throw MailCryptoError.invalid("Invalid message text")}
        return try OpenedMail(text:text,encrypted:encrypted,algorithm:"OpenPGP ML-DSA-65 + ECDSA P-384 (draft-05)",signerEmail:signer.email,fingerprint:signer.fingerprint.hex,fromMatches:root.headers["from"]?.caseInsensitiveCompare(signer.email) == .orderedSame)
    }
}
