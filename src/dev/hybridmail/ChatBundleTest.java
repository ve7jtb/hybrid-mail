package dev.hybridmail;

import java.io.*;
import java.util.*;
import jakarta.mail.internet.*;
import org.bouncycastle.openpgp.*;

/** Synthetic keys only. Exercises the same external-signing interface used by
 * YubiKeys, without touching any connected device or writing account data. */
public final class ChatBundleTest {
    static final String EMAIL="bundle@example.test";
    static final String TEXT="Plain text café\r\n"+"A compressible Chat message.\n".repeat(300);
    static final String HTML="<html><body><h1>Chat café</h1><p><b>Formatted</b> message</p></body></html>";
    static byte[] binary(){byte[] bytes=new byte[96*1024];new Random(42).nextBytes(bytes);return bytes;}
    static final byte[] FILE=binary();
    static final List<MailEngine.Attachment> FILES=List.of(new MailEngine.Attachment("../sample.bin",FILE),new MailEngine.Attachment("notes.txt","File text, not the message body".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    static void check(boolean value,String why){if(!value)throw new AssertionError(why);}
    interface Action{void run()throws Exception;}
    static void rejects(Action action,String why)throws Exception{try{action.run();}catch(Exception expected){System.out.println("PASS rejects "+why);return;}throw new AssertionError("Accepted "+why);}
    record Fixture(Identity id,OpenPgp.PublicIdentity own,ExternalMu.Backend signing,ExternalKem.Backend decryption){}
    static Fixture level3()throws Exception{
        var id=Identity.generateSoftwareProfile(EMAIL,TokenProfile.LEVEL3,List.of()).getLast();var hw=new Rfc9980Test.Hardware(id);
        return new Fixture(id,OpenPgp.createRfc9980(id,hw,hw.ed.getPublic(),hw.x.getPublic()),hw,hw);
    }
    static Fixture level5()throws Exception{
        var id=SoftwareIdentityVault.addLevel5OpenPgp(Identity.generateSoftwareProfile(EMAIL,TokenProfile.LEVEL5,List.of())).getLast();return new Fixture(id,id.softwareOpenPgp().own(),null,null);
    }
    static byte[] create(Fixture fixture,OpenPgp.PublicIdentity recipient)throws Exception{return ChatBundle.create(fixture.id,fixture.own,recipient,EMAIL,EMAIL,"Chat bundle test",TEXT,HTML,FILES,fixture.signing);}
    static void content(ChatBundle.Opened opened)throws Exception{
        check(opened.from().equals(EMAIL)&&opened.to().equals(EMAIL)&&opened.subject().equals("Chat bundle test"),"Signed headers changed");
        check(opened.text().equals(TEXT)&&opened.html().equals(HTML),"MIME alternatives changed");
        check(opened.attachments().size()==2&&opened.attachments().get(0).name().equals("sample.bin")&&Arrays.equals(FILE,opened.attachments().get(0).data()),"Attachment bytes/name changed");
        var message=MailEngine.parse(opened.mime());check(message.isMimeType("multipart/mixed"),"Missing mixed wrapper");
        var mixed=(MimeMultipart)message.getContent();check(mixed.getBodyPart(0).isMimeType("multipart/alternative"),"Missing alternative wrapper");
        check(opened.postQuantum(),"Hybrid signature not recognized");
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();var a=level3();var b=level5();
        for(var sender:List.of(a,b))for(var receiver:List.of(a,b))for(boolean encrypted:new boolean[]{false,true}){
            byte[] bundle=create(sender,encrypted?receiver.own:null);var opened=ChatBundle.open(bundle,sender.own,receiver.own,receiver.id,receiver.decryption);content(opened);check(opened.encrypted()==encrypted,"Wrong encryption state");
            if(!encrypted){check((bundle[0]&0x40)!=0,"Legacy compression packet framing");check(LegacyOpenPgp.objects(bundle).nextObject() instanceof PGPCompressedData,"Signed bundle not compressed");check(bundle.length<opened.mime().length,"Fixture did not compress");}
            byte[] damaged=bundle.clone();damaged[damaged.length/2]^=1;rejects(()->ChatBundle.open(damaged,sender.own,receiver.own,receiver.id,receiver.decryption),"tampered "+(encrypted?"ciphertext":"compressed signature"));
            rejects(()->ChatBundle.open(bundle,sender==a?b.own:a.own,receiver.own,receiver.id,receiver.decryption),"wrong signer certificate");
        }
        byte[] signed=create(a,null);byte[] packets=ChatBundle.expand(signed),bad=packets.clone();bad[bad.length-1]^=1;
        rejects(()->ChatBundle.open(ChatBundle.compress(bad,1),a.own,null,null,null),"invalid signature after successful decompression");
        rejects(()->ChatBundle.open(OpenPgp.cat(signed,OpenPgp.frame(11,new byte[]{1})),a.own,null,null,null),"appended packets");
        byte[] nested=packets;for(int i=0;i<4;i++)nested=ChatBundle.compress(nested,1);final byte[] deep=nested;
        rejects(()->ChatBundle.open(deep,a.own,null,null,null),"excessive compression nesting");
        byte[] bomb=ChatBundle.compress(new byte[ChatBundle.MAX_BYTES+1],1);rejects(()->ChatBundle.open(bomb,a.own,null,null,null),"decompression size bomb");
        rejects(()->ChatBundle.open(new byte[ChatBundle.MAX_BYTES+1],a.own,null,null,null),"oversized encoded input");
        rejects(()->ChatBundle.create(a.id,a.own,null,"wrong@example.test",EMAIL,"x","x",null,List.of(),a.signing),"sender mismatch");
        rejects(()->ChatBundle.create(a.id,a.own,b.own,EMAIL,"wrong@example.test","x","x",null,List.of(),a.signing),"recipient mismatch");
        rejects(()->ChatBundle.mime(EMAIL,EMAIL,"x\r\nInjected: yes","x",null,List.of()),"header injection");
        rejects(()->ChatBundle.mime(EMAIL,EMAIL,"x","x",null,Collections.nCopies(21,FILES.getFirst())),"attachment count");
        rejects(()->ChatBundle.mime(EMAIL,EMAIL,"x","x",null,List.of(new MailEngine.Attachment("large",new byte[ChatBundle.MAX_ATTACHMENT_BYTES+1]))),"attachment size");
        // Reissue ONLY this synthetic certificate's direct-key signature with
        // its historical no-compression preference. Existing real certificates
        // must not need a key change or silent policy override to receive Chat.
        var oldPackets=new ArrayList<>(OpenPgp.packets(a.own.encoded));
        byte[] preferences=OpenPgp.cat(OpenPgp.sub(27,OpenPgp.b(3)),OpenPgp.sub(11,OpenPgp.b(9)),OpenPgp.sub(21,OpenPgp.b(9)),OpenPgp.sub(22,OpenPgp.b(0)),OpenPgp.sub(30,OpenPgp.b(8)),OpenPgp.sub(39,OpenPgp.b(9,3,9,2)));
        var direct=OpenPgp.request(OpenPgp.keyHash(a.own.primary),31,OpenPgp.fingerprint(a.own.primary),preferences,30);
        byte[] oldSignature=direct.finish(OpenPgp.signer(a.id,a.signing,a.own.signing).sign(direct.digest()));
        var oldEncoding=new java.io.ByteArrayOutputStream();for(int i=0;i<oldPackets.size();i++){var p=oldPackets.get(i);oldEncoding.write(OpenPgp.frame(p.tag(),i==1?oldSignature:p.body()));}
        var oldOwn=new OpenPgp.PublicIdentity(oldEncoding.toByteArray());byte[] oldEnvelope=create(b,oldOwn);
        content(ChatBundle.open(oldEnvelope,b.own,oldOwn,a.id,a.decryption));
        var envelope=OpenPgp.envelope(oldEnvelope,oldOwn);byte[] kek=OpenPgp.recover(envelope.ct(),a.id,a.decryption,oldOwn);try{check(!(LegacyOpenPgp.objects(envelope.open(kek)).nextObject() instanceof PGPCompressedData),"Ignored recipient's no-compression preference");}finally{OpenPgp.wipe(kek);}
        byte[] encrypted=create(a,a.own);rejects(()->ChatBundle.open(encrypted,a.own,b.own,b.id,b.decryption),"wrong recipient key");
        // A valid OpenPGP signature cannot bless an unrelated email address.
        byte[] spoof=ChatBundle.mime("wrong@example.test",EMAIL,"x","x",null,List.of());
        byte[] spoofSigned=OpenPgp.signed(spoof,a.own,OpenPgp.signer(a.id,a.signing,a.own.signing));
        rejects(()->ChatBundle.open(ChatBundle.compress(spoofSigned,1),a.own,null,null,null),"signed From/certificate mismatch");
        byte[] noFiles=ChatBundle.create(b.id,b.own,null,EMAIL,EMAIL,"Simple","Hello",HTML,List.of(),null);
        var simple=ChatBundle.open(noFiles,b.own,null,null,null);check(MailEngine.parse(simple.mime()).isMimeType("multipart/alternative"),"Unneeded mixed wrapper");
        noFiles=ChatBundle.create(b.id,b.own,null,EMAIL,EMAIL,"Simple","Hello",null,List.of(),null);
        simple=ChatBundle.open(noFiles,b.own,null,null,null);check(simple.text().equals("Hello")&&simple.html()==null&&simple.attachments().isEmpty(),"Plain-only message");
        System.out.println("PASS Chat .pgp Level 3/5 cross-profile signed/encrypted round trips, multipart alternatives, binary attachments, bounded decompression and authentication failures; no network/hardware");
    }
}
