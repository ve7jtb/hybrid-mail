package dev.hybridmail;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.util.Arrays;
/** Create a certificate-only token identity, optionally with a host conventional key. */
public final class TokenSetup {
    public static void main(String[] args)throws Exception{
        if(args.length!=2&&args.length!=4)throw new IllegalArgumentException("TokenSetup signing.cer output.p12 [traditional.p12 alias]");
        MailEngine.init();
        Console console=System.console();if(console==null)throw new IllegalStateException("Run from a terminal to enter passwords safely");
        char[] password=console.readPassword("New identity password (12+ characters): ");
        if(password==null||password.length<12)throw new IllegalArgumentException("Password too short");
        try{
            var cert=Identity.readCertificate(Path.of(args[0]));
            KeyStore ks=KeyStore.getInstance("PKCS12","BC");ks.load(null,password);ks.setCertificateEntry("sign",cert);
            if(args.length==4){
                char[] sourcePassword=console.readPassword("Traditional key store password: ");
                try(InputStream in=Files.newInputStream(Path.of(args[2]))){
                    KeyStore source=KeyStore.getInstance("PKCS12","BC");source.load(in,sourcePassword);
                    Key key=source.getKey(args[3],sourcePassword);if(!(key instanceof PrivateKey))throw new IllegalArgumentException("No private key under alias");
                    ks.setKeyEntry("traditional",key,password,source.getCertificateChain(args[3]));
                }finally{if(sourcePassword!=null)Arrays.fill(sourcePassword,'\0');}
            }
            Path out=Path.of(args[1]);Files.createFile(out,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            try(OutputStream stream=Files.newOutputStream(out)){ks.store(stream,password);}
            System.out.println("Created token signing identity. ML-DSA private key is not stored in this file.");
        }finally{Arrays.fill(password,'\0');}
    }
}
