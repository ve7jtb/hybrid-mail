package dev.hybridmail;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
/** Software-only subprocess fixture. NOT a YubiKey implementation. */
public final class TestMuAdapter {
    public static void main(String[] args)throws Exception{
        BufferedReader in=new BufferedReader(new InputStreamReader(System.in,java.nio.charset.StandardCharsets.US_ASCII));
        if(!"ML-DSA-65".equals(in.readLine()))throw new IllegalArgumentException("algorithm");
        byte[] spki=Base64.getDecoder().decode(in.readLine());
        byte[] mu=Base64.getDecoder().decode(in.readLine());
        MLDSASigner s=new MLDSASigner();s.init(true,new ParametersWithRandom(PrivateKeyFactory.createKey(Files.readAllBytes(Path.of(args[0]))),new SecureRandom()));
        System.out.println(Base64.getEncoder().encodeToString(s.generateMuSignature(mu)));
    }
}
