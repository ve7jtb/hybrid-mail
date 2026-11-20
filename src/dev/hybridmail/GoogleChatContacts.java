package dev.hybridmail;

import java.util.*;

/** Local certificate/trust annotations, independent of Google display names. */
final class GoogleChatContacts {
    record Certificate(String kind,String fingerprint,int version,boolean trusted,boolean encryption,boolean hybrid,String algorithms){}
    record Status(String email,List<Certificate> certificates,int unusable){
        String summary(){
            if(certificates.isEmpty())return unusable>0?"Saved certificate unavailable or invalid":"No saved certificate";
            return certificates.stream().map(c->c.kind()+(c.version()>0?" v"+c.version():"")+" · "+(c.trusted()?"Trusted":"Not trusted")+(c.kind().equals("OpenPGP")?" · "+(!c.encryption()?"No encryption key":c.hybrid()?"Hybrid encryption":"Classical encryption"):"")).distinct().collect(java.util.stream.Collectors.joining("; "));
        }
    }
    static Status inspect(DesktopState state,String email)throws Exception{
        // A display name or Google user ID without a verified email mapping
        // must never select a certificate or inherit another person's trust.
        if(email==null||email.isBlank())return new Status("",List.of(),0);
        String address=GoogleChatVault.email(email);List<Certificate> found=new ArrayList<>();Set<String> seen=new HashSet<>();int invalid=0;
        for(var contact:state.pgpContacts())try{
            var cert=state.pgpCertificate(contact);if(!cert.matchesEmail(address))continue;
            String fp=cert.fingerprint();if(!seen.add(fp))continue;
            found.add(new Certificate("OpenPGP",fp,cert.version(),state.isPgpTrusted(address,fp),cert.canEncrypt(),cert.quantumEncryption(),cert.signingAlgorithms()+" / "+cert.encryptionAlgorithm()));
        }catch(Exception unusable){if(contact.email().equalsIgnoreCase(address))invalid++;}
        for(var contact:state.contacts())if(contact.email().equalsIgnoreCase(address))try{
            var cert=state.contactCertificate(contact);cert.checkValidity();if(!Identity.matchesEmail(cert,address))continue;
            found.add(new Certificate("S/MIME "+contact.role(),Identity.fingerprint(cert),0,state.isTrusted(cert,contact.role()),contact.role().equals("encryption"),false,cert.getPublicKey().getAlgorithm()));
        }catch(Exception unusable){invalid++;}
        // Show v6 first, but retain every fingerprint and its own trust state.
        // This is decoration, not permission to select a key or send a message.
        found.sort(Comparator.comparingInt(Certificate::version).reversed().thenComparing(Certificate::fingerprint));
        return new Status(address,List.copyOf(found),invalid);
    }
}
