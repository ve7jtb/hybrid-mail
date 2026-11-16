package dev.hybridmail;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import jakarta.activation.DataHandler;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;

public final class SelfTest {
    private static int checks;
    private static void check(boolean value,String label) {if(!value)throw new AssertionError(label);checks++;System.out.println("PASS " + label);}
    private static void rejects(String label, Throwing action)throws Exception{try{action.run();}catch(Exception e){checks++;System.out.println("PASS " + label);return;}throw new AssertionError("Accepted: "+label);}
    @FunctionalInterface interface Throwing{void run()throws Exception;}
    private static ExternalMu.Backend simulator(Identity id){
        PrivateKey key=id.signingKey() instanceof CompositePrivateKey c?c.getPrivateKeys().get(0):id.signingKey();
        return (pub,mu)->{check(mu.length==64,"external adapter receives 64-byte mu");MLDSASigner s=new MLDSASigner();s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(key.getEncoded()),new SecureRandom()));return s.generateMuSignature(mu);};
    }
    public static void main(String[]args)throws Exception{
        MailEngine.init();
        Path dir=Files.createTempDirectory("hybrid-mail-test-");
        try{
            Identity[] alice={Identity.generate("alice@example.test",false),Identity.generate("alice@example.test",true)};
            Identity[] bob={Identity.generate("bob@example.test",false),Identity.generate("bob@example.test",true)};
            String text="Hello hybrid world!\r\nUnicode: café 日本語\r\n";
            for(int s=0;s<2;s++)for(int k=0;k<2;k++){
                MimeMessage m=MailEngine.compose(alice[s],"alice@example.test","bob@example.test","Test",text,bob[k].encryptionCert(),null);
                var opened=MailEngine.open(MailEngine.parse(MailEngine.encode(m)),bob[k],alice[s].signingCert());
                check(opened.encrypted()&&opened.pinned()&&opened.fromMatches()&&opened.text().equals(text),"S/MIME round-trip signing="+s+" encryption="+k);
                check(new SMIMEAuthEnveloped(m).getEncryptionAlgOID().equals("2.16.840.1.101.3.4.1.46"),"AES-256-GCM on wire");
                final Identity other=bob[1-k]; rejects("wrong recipient rejected",()->MailEngine.open(m,other,alice[0].signingCert()));
                // Change the authenticated tag while preserving a well-formed CMS structure.
                ContentInfo ci=ContentInfo.getInstance(m.getInputStream().readAllBytes());
                AuthEnvelopedData env=AuthEnvelopedData.getInstance(ci.getContent());
                byte[] mac=env.getMac().getOctets().clone();mac[0]^=1;
                var broken=new AuthEnvelopedData(env.getOriginatorInfo(),env.getRecipientInfos(),env.getAuthEncryptedContentInfo(),env.getAuthAttrs(),new DEROctetString(mac),env.getUnauthAttrs());
                MimeMessage tampered=MailEngine.parse(MailEngine.encode(m));
                tampered.setDataHandler(new DataHandler(new ByteArrayDataSource(new ContentInfo(ci.getContentType(),broken).getEncoded(),m.getContentType())));tampered.saveChanges();
                final Identity receiver=bob[k]; rejects("modified GCM tag rejected",()->MailEngine.open(tampered,receiver,null));
            }
            for(int i=0;i<2;i++){
                Identity a=alice[i];
                MimeMessage signed=MailEngine.compose(a,"alice@example.test","bob@example.test","Signed",text,null,simulator(a));
                check(MailEngine.open(signed,null,a.signingCert()).text().equals(text),"external-mu S/MIME verified by BC profile="+i);
                check(!MailEngine.open(signed,null,bob[i].signingCert()).pinned(),"valid untrusted signer distinguished");
                byte[] originalCms=signed.getInputStream().readAllBytes();
                byte[] signature=new SMIMESigned(signed).getSignerInfos().getSigners().iterator().next().getSignature();
                int sigOffset=indexOf(originalCms,signature);
                check(sigOffset>=0,"located signature value");
                int[] flips=i==1?new int[]{0,3309}:new int[]{0};
                for(int offset:flips){
                    byte[] corrupted=originalCms.clone();corrupted[sigOffset+offset]^=1;
                    MimeMessage bad=MailEngine.parse(MailEngine.encode(signed));
                    bad.setDataHandler(new DataHandler(new ByteArrayDataSource(corrupted,signed.getContentType())));bad.saveChanges();
                    rejects("corrupted signature component rejected at offset "+offset,()->MailEngine.open(bad,null,null));
                }
                Identity tokenOnly=new Identity(a.signingCert(),null,null,null,
                    a.signingKey() instanceof CompositePrivateKey c?c.getPrivateKeys().get(1):null);
                var tokenMail=MailEngine.compose(tokenOnly,"alice@example.test","bob@example.test","Token only",text,null,simulator(a));
                check(MailEngine.open(tokenMail,null,a.signingCert()).pinned(),"external identity has no ML-DSA private key profile="+i);
                signed.setFrom(new InternetAddress("mallory@example.test"));
                check(!MailEngine.open(signed,null,a.signingCert()).fromMatches(),"unsigned From spoof flagged");
                rejects("bad external signature rejected",()->MailEngine.compose(a,"alice@example.test","bob@example.test","Bad",text,null,(pub,mu)->new byte[3309]));
                // Mutate encapsulated content but retain original signature and attributes.
                byte[] cms=signed.getInputStream().readAllBytes();byte[] needle="Hello hybrid world!".getBytes(StandardCharsets.US_ASCII);
                int at=indexOf(cms,needle);check(at>=0,"located signed MIME payload");cms[at]^=1;
                MimeMessage changed=MailEngine.parse(MailEngine.encode(signed));changed.setDataHandler(new DataHandler(new ByteArrayDataSource(cms,signed.getContentType())));changed.saveChanges();
                rejects("modified signed body rejected",()->MailEngine.open(changed,null,null));
                Path file=dir.resolve("identity"+i+".p12");char[] password="test-only-long-password".toCharArray();a.save(file,password);
                Identity loaded=Identity.load(file,password);
                check(Arrays.equals(a.signingCert().getEncoded(),loaded.signingCert().getEncoded()),"PKCS12 profile="+i);
                MimeMessage restored=MailEngine.compose(loaded,"alice@example.test","bob@example.test","Reloaded",text,bob[i].encryptionCert(),null);
                check(MailEngine.open(restored,bob[i],a.signingCert()).text().equals(text),"reloaded keys sign correctly profile="+i);
                rejects("wrong PKCS12 password rejected",()->Identity.load(file,"wrong".toCharArray()));
                rejects("sender certificate mismatch rejected",()->MailEngine.compose(a,"mallory@example.test","bob@example.test","Bad",text,null,null));
                rejects("recipient certificate mismatch rejected",()->MailEngine.compose(a,"alice@example.test","mallory@example.test","Bad",text,bob[0].encryptionCert(),null));
            }
            // A real subprocess exercises the adapter protocol, using software only.
            Path keyFile=dir.resolve("simulator.pk8");Files.write(keyFile,alice[0].signingKey().getEncoded());
            Path executable=dir.resolve("adapter");
            String java=Path.of(System.getProperty("java.home"),"bin","java").toString();
            String cp=Arrays.stream(System.getProperty("java.class.path").split(File.pathSeparator)).map(p->Path.of(p).toAbsolutePath().toString()).reduce((a,b)->a+File.pathSeparator+b).orElseThrow();
            Files.writeString(executable,"#!/bin/sh\nexec "+quote(java)+" -cp "+quote(cp)+" dev.hybridmail.TestMuAdapter "+quote(keyFile.toString())+"\n");executable.toFile().setExecutable(true,true);
            var wire=MailEngine.compose(alice[0],"alice@example.test","bob@example.test","Process",text,null,ExternalMu.executable(executable.toString()));
            check(MailEngine.open(wire,null,alice[0].signingCert()).pinned(),"external executable protocol round-trip");
            System.out.println("SUCCESS: "+checks+" checks; no mail sent, no hardware used.");
        }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    private static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    private static int indexOf(byte[] a,byte[] b){outer:for(int i=0;i<=a.length-b.length;i++){for(int j=0;j<b.length;j++)if(a[i+j]!=b[j])continue outer;return i;}return -1;}
}
