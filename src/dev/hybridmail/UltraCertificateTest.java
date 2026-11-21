package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Real cryptography with synthetic hardware keys; no PC/SC or user data. */
public final class UltraCertificateTest {
    static final class Signing implements ExternalMu.Backend {
        final ExternalMu.Backend delegate;int calls;Signing(KeyPair pair){delegate=Level5CompanionTest.signer(pair);}
        public byte[] sign(PublicKey key,byte[] mu)throws Exception{calls++;return delegate.sign(key,mu);}
    }
    static void reject(Level5CompanionTest.Checked action)throws Exception{Level5CompanionTest.rejected(action);}
    static byte[] replaceTemplate(byte[] encoded,byte[] template,KeyPair certification)throws Exception{
        byte[] unpacked=CompanionEncoding.unpack(encoded);var outer=new DataInputStream(new ByteArrayInputStream(unpacked));byte[] body=Level5Companion.field(outer);var in=new DataInputStream(new ByteArrayInputStream(body));in.skipNBytes(12);for(int i=0;i<4;i++)Level5Companion.field(in);int start=body.length-in.available();Level5Companion.field(in);int end=body.length-in.available();
        var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);out.write(body,0,start);Level5Companion.field(out,template);out.write(body,end,body.length-end);body=bytes.toByteArray();
        var signer=Signature.getInstance("ML-DSA-87","BC");signer.initSign(certification.getPrivate());signer.update(body);bytes=new ByteArrayOutputStream();out=new DataOutputStream(bytes);Level5Companion.field(out,body);Level5Companion.field(out,signer.sign());return CompanionEncoding.pack(bytes.toByteArray());
    }
    static byte[] replacePacket(byte[] template,int index,byte[] body)throws Exception{var packets=packets(template);var out=new OpenPgp.Buffer();for(int i=0;i<packets.size();i++)out.put(frame(packets.get(i).tag(),i==index?body:packets.get(i).body()));return out.toByteArray();}
    static int subOffset(byte[] signature,int tag)throws Exception{var r=new OpenPgp.Reader(signature);r.take(4);int n=(int)r.number(4),end=r.at+n;while(r.at<end){int len=r.length();int found=r.one()&127;if(found==tag)return r.at;r.take(len-1);}throw new AssertionError("Subpacket missing");}
    static byte[] salt(byte[] signature)throws Exception{var r=new OpenPgp.Reader(signature);r.take(4);r.take((int)r.number(4));r.take((int)r.number(4));r.take(2);check(r.one()==32,"Expected salt32");return r.take(32);}
    public static void main(String[] args)throws Exception{
        MailEngine.init();var certification=SoftwareOpenPgp.generate("ML-DSA-87");var signing=SoftwareOpenPgp.generate("ML-DSA-87");var kem=SoftwareOpenPgp.generate("ML-KEM-1024");var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new ECGenParameterSpec("secp384r1"));var wrapping=g.generateKeyPair();
        var hardware=Map.of("86",certification.getPublic(),"9c",signing.getPublic(),"9d",kem.getPublic(),"82",wrapping.getPublic());var certBackend=new Signing(certification);var signBackend=new Signing(signing);var backend=new TokenKemTest.Simulator(kem,wrapping);
        byte[] full,ultra,template,originalSigned,originalEncrypted;PublicIdentity original;byte[] plain=bytes("Synthetic ultra companion interoperability test\n");
        List<String> emails=List.of("ultra@example.test","alias1@example.test");
        try(var initial=Level5Companion.create(123456,hardware,emails,certBackend,signBackend)){
            original=initial.own;full=initial.seal(certBackend);template=UltraCertificate.template(original);originalSigned=initial.sign(plain,signBackend);originalEncrypted=encrypt(originalSigned,original);
        }
        // Conversion starts from a restored identity, proving no original
        // creation-time software-key objects are needed or regenerated.
        try(var unlocked=Level5Companion.restore(full,123456,hardware,backend)){ultra=unlocked.toUltra(certBackend);}
        var inspected=Level5Companion.inspect(ultra,123456,hardware);check(inspected.ultra()&&inspected.own()==null&&Arrays.equals(inspected.template(),template),"Ultra inspect semantics");check(ultra.length<full.length,"Ultra did not shrink");
        check(Level5Companion.inspect(ultra,123456,hardware,original).own()!=null,"Original public certificate was not a valid cache");
        int privateCalls=backend.ecCalls,certCalls=certBackend.calls,signCalls=signBackend.calls;
        reject(()->Level5Companion.restore(ultra,123456,hardware,backend));check(backend.ecCalls==privateCalls,"Missing cache caused a private call");
        var badCache=new PublicIdentity(original.encoded.clone());badCache.encoded[badCache.encoded.length-1]^=1;reject(()->Level5Companion.restore(ultra,123456,hardware,backend,badCache));check(backend.ecCalls==privateCalls,"Bad cache caused a private call");
        PublicIdentity regenerated;
        try(var restored=Level5Companion.reconstruct(ultra,123456,hardware,backend,certBackend,signBackend)){
            regenerated=restored.own;check(backend.ecCalls==privateCalls+1&&certBackend.calls==certCalls+emails.size()+3&&signBackend.calls==signCalls+1,"Unexpected reconstruction private-operation counts");
            check(original.certifiedEmails().equals(regenerated.certifiedEmails()),"Reconstruction lost email metadata");check(Arrays.equals(original.primary,regenerated.primary)&&Arrays.equals(original.signingBody(),regenerated.signingBody())&&Arrays.equals(original.subkey,regenerated.subkey),"Reconstruction changed a key or fingerprint");
            check(Arrays.equals(template,UltraCertificate.template(regenerated)),"Reconstruction changed authenticated metadata");
            var beforePackets=packets(original.encoded);var afterPackets=packets(regenerated.encoded);
            for(int i=0;i<beforePackets.size();i++)if(beforePackets.get(i).tag()==2){byte[] before=beforePackets.get(i).body(),after=afterPackets.get(i).body();check(!Arrays.equals(salt(before),salt(after)),"Reconstruction reused a signature salt");if(i==beforePackets.size()-3){int bo=subOffset(before,32),ao=subOffset(after,32);check(!Arrays.equals(salt(slice(before,bo,before.length)),salt(slice(after,ao,after.length))),"Reconstruction reused the cross-signature salt");}}
            check(Arrays.equals(plain,openSigned(restored.decrypt(originalEncrypted,backend),original)),"Ultra lost original private decryption key");check(Arrays.equals(plain,openSigned(restored.sign(plain,signBackend),original)),"Ultra lost original signing key");
        }
        certCalls=certBackend.calls;signCalls=signBackend.calls;privateCalls=backend.ecCalls;
        try(var cached=Level5Companion.restore(ultra,123456,hardware,backend,regenerated)){check(cached.own.fingerprint().equals(original.fingerprint()),"Cached restore fingerprint changed");}
        check(backend.ecCalls==privateCalls+1&&certBackend.calls==certCalls&&signBackend.calls==signCalls,"Cached restore unexpectedly regenerated signatures");
        // The outer signature is valid for every malformed template below.
        // Thus these tests reach the inner parser and prove it refuses to use
        // ECDH or signing as an oracle for attacker-supplied metadata.
        var badTemplates=new ArrayList<byte[]>();var packets=packets(template);byte[] direct=packets.get(1).body();
        byte[] changed=direct.clone();changed[changed.length-1]=1;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[3]=9;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[changed.length-4741-1]=1;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[subOffset(changed,27)]=3;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();Arrays.fill(changed,subOffset(changed,2),subOffset(changed,2)+4,(byte)0);badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[subOffset(changed,33)+1]^=1;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[subOffset(changed,11)-1]=100;badTemplates.add(replacePacket(template,1,changed));
        changed=direct.clone();changed[subOffset(changed,11)]=99;badTemplates.add(replacePacket(template,1,changed));
        int signingBinding=packets.size()-3;changed=packets.get(signingBinding).body().clone();int cross=subOffset(changed,32);changed[cross+1]=24;badTemplates.add(replacePacket(template,signingBinding,changed));
        changed=packets.get(signingBinding).body().clone();changed[subOffset(changed,32)-1]=(byte)(128|32);badTemplates.add(replacePacket(template,signingBinding,changed));
        badTemplates.add(cat(template,frame(2,b(6,32,31,10))));badTemplates.add(Arrays.copyOf(template,template.length-1));
        for(byte[] bad:badTemplates){int ec=backend.ecCalls,cs=certBackend.calls,ss=signBackend.calls;byte[] tampered=replaceTemplate(ultra,bad,certification);reject(()->Level5Companion.reconstruct(tampered,123456,hardware,backend,certBackend,signBackend));check(backend.ecCalls==ec&&certBackend.calls==cs&&signBackend.calls==ss,"Malformed ultra template caused private calls");}
        // Conversion must not strip packets that the general mail parser can
        // otherwise ignore. Such inputs keep their full certificate storage.
        for(byte[] extra:List.of(frame(10,bytes("PGP")),frame(21,b(0)),frame(2,packets(original.encoded).get(1).body()))){
            int cs=certBackend.calls,ss=signBackend.calls;reject(()->UltraCertificate.template(new PublicIdentity(cat(original.encoded,extra))));check(certBackend.calls==cs&&signBackend.calls==ss,"Unsupported conversion contacted a signer");
        }
        // A valid-but-unrelated cached certificate must also be refused before
        // the wrapping key is asked to decrypt anything.
        try(var unrelated=Level5Companion.create(123456,hardware,List.of("other@example.test"),certBackend,signBackend)){int ec=backend.ecCalls;reject(()->Level5Companion.restore(ultra,123456,hardware,backend,unrelated.own));check(backend.ecCalls==ec,"Unrelated cache caused unwrap");}
        // All five UIDs are understood by the template codec. The envelope's
        // separate 64 KiB expansion limit still applies to larger certificates.
        try(var five=Level5Companion.create(123456,hardware,List.of("one@example.test","two@example.test","three@example.test","four@example.test","five@example.test"),certBackend,signBackend)){
            byte[] fiveTemplate=UltraCertificate.template(five.own);UltraCertificate.validateCached(fiveTemplate,five.own);check(five.own.certifiedEmails().size()==5,"Five UID template lost an address");
        }
        backend.assertWiped();
        if(args.length==1){Path dir=Path.of(args[0]);Files.createDirectories(dir);Files.write(dir.resolve("full.pqcomp"),full);Files.write(dir.resolve("companion.pqcomp"),ultra);Files.write(dir.resolve("public.pgp"),regenerated.encoded);Files.write(dir.resolve("original-public.pgp"),original.encoded);Files.write(dir.resolve("template.pgp"),template);Files.write(dir.resolve("java-signed.pgp"),originalSigned);Files.write(dir.resolve("java-encrypted.pgp"),originalEncrypted);Files.write(dir.resolve("plain.txt"),plain);for(var entry:Map.of("86",certification,"9c",signing,"9d",kem,"82",wrapping).entrySet()){Files.write(dir.resolve(entry.getKey()+".der"),entry.getValue().getPublic().getEncoded());Files.write(dir.resolve(entry.getKey()+"-test-private.der"),entry.getValue().getPrivate().getEncoded());}}
        System.out.println("PASS ultra companion "+full.length+" -> "+ultra.length+" bytes; metadata/fingerprints/keys retained with fresh signature salts; five UID templates supported; reconstruction and cached sign/decrypt work; "+badTemplates.size()+" malformed authenticated templates and invalid caches rejected before private calls");
    }
}
