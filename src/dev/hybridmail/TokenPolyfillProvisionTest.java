package dev.hybridmail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import com.google.gson.JsonObject;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

/** Synthetic public keys and a fake process only; never enumerates a card. */
public final class TokenPolyfillProvisionTest {
    interface Checked {void run()throws Exception;}
    static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static void rejects(Checked action)throws Exception{try{action.run();}catch(Exception expected){return;}throw new AssertionError("Invalid polyfill input accepted");}
    static PublicKey generate(String algorithm)throws Exception{return KeyPairGenerator.getInstance(algorithm,"BC").generateKeyPair().getPublic();}
    static PublicKey ec(String curve)throws Exception{var g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new ECGenParameterSpec(curve));return g.generateKeyPair().getPublic();}
    static JsonObject json(Map<String,PublicKey> keys){var out=new JsonObject();keys.forEach((s,k)->out.addProperty(s,Base64.getEncoder().encodeToString(k.getEncoded())));return out;}
    static void wiped(char[] value){for(char c:value)check(c==0,"Process failure left credentials in memory");}
    public static void main(String[] args)throws Exception{
        MailEngine.init();
        var keys=Map.of("82",generate("Ed25519"),"9c",generate("Ed25519"),"9d",generate("X25519"),"83",ec("secp384r1"));
        String output=json(keys).toString();
        check(TokenProvision.decodePolyfill(output).keySet().equals(keys.keySet()),"Lost hardware roles");
        var missing=json(keys);missing.remove("83");rejects(()->TokenProvision.decodePolyfill(missing.toString()));
        var extra=json(keys);extra.addProperty("84",extra.get("82").getAsString());rejects(()->TokenProvision.decodePolyfill(extra.toString()));
        var duplicate=json(keys);duplicate.addProperty("9c",duplicate.get("82").getAsString());rejects(()->TokenProvision.decodePolyfill(duplicate.toString()));
        rejects(()->TokenProvision.decodePolyfill(output.substring(0,output.length()-1)+",\"82\":"+json(keys).get("82")+"}"));
        rejects(()->TokenProvision.decodePolyfill(output+"{}"));
        for(String slot:TokenProvision.POLYFILL_SLOTS){
            var wrong=json(keys);wrong.addProperty(slot,Base64.getEncoder().encodeToString((slot.equals("83")?ec("secp256r1"):slot.equals("9d")?keys.get("82"):keys.get("9d")).getEncoded()));
            rejects(()->TokenProvision.decodePolyfill(wrong.toString()));
        }
        // RFC 8410 keys require absent parameters, not ASN.1 NULL. Named-curve
        // P-384 is also mandatory, avoiding an attacker-controlled curve.
        var info=SubjectPublicKeyInfo.getInstance(keys.get("82").getEncoded());
        var withNull=new SubjectPublicKeyInfo(new AlgorithmIdentifier(info.getAlgorithm().getAlgorithm(),DERNull.INSTANCE),info.getPublicKeyData().getOctets());
        var nullParameters=json(keys);nullParameters.addProperty("82",Base64.getEncoder().encodeToString(withNull.getEncoded()));rejects(()->TokenProvision.decodePolyfill(nullParameters.toString()));
        Path temp=Files.createTempDirectory("polyfill-provision-test-"),helper=temp.resolve("fake-provision"),journal=temp.resolve("journal");
        try{
            // The fake helper checks the command contract and stdin, then emits
            // synthetic public data. No real serial/PIN or card API is used.
            String script="#!/bin/sh\nset -eu\ncase \"$1\" in\n"+
                "detect-polyfill) test \"$#\" = 1; echo 123456;;\n"+
                "check-polyfill) test \"$2\" = 123456; echo EMPTY;;\n"+
                "create|resume|read) test \"$2\" = 123456; test \"$3\" = level3-polyfill; test \"$#\" = 4; if test \"$1\" != read; then IFS= read -r pin; IFS= read -r management; test \"$pin\" = 654321; test \"$management\" = 00000000000000000000000000000000; fi; printf '%s\\n' '"+output+"';;\n"+
                "*) exit 91;;\nesac\n";
            Files.writeString(helper,script,StandardCharsets.US_ASCII);check(helper.toFile().setExecutable(true,true),"Cannot mark fake helper executable");
            System.setProperty("pqmail.provision.helper",helper.toString());
            check(TokenProvision.detectPolyfillEmpty().equals("123456"),"Wrong detected serial");TokenProvision.checkPolyfill("123456");
            char[] pin="654321".toCharArray(),management="00000000000000000000000000000000".toCharArray();
            check(TokenProvision.createPolyfill("123456",journal,pin,management).size()==4,"Create mapping");wiped(pin);wiped(management);
            pin="654321".toCharArray();management="00000000000000000000000000000000".toCharArray();
            check(TokenProvision.resumePolyfill("123456",journal,pin,management).size()==4,"Resume mapping");wiped(pin);wiped(management);
            check(TokenProvision.readPolyfill("123456",journal).size()==4,"Read mapping");
            rejects(()->TokenProvision.checkPolyfill("0"));rejects(()->TokenProvision.checkPolyfill("4294967296"));
            char[] badPin="654321".toCharArray(),badManagement="00000000000000000000000000000000".toCharArray();
            rejects(()->TokenProvision.createPolyfill("0",journal,badPin,badManagement));wiped(badPin);wiped(badManagement);
            Files.createDirectory(journal);for(String slot:TokenProvision.POLYFILL_SLOTS)Files.write(journal.resolve(slot+"-public.der"),keys.get(slot).getEncoded());
            check(!TokenProvision.allPolyfillKeysSaved(journal),"Recovery accepted missing initial journal");Files.writeString(journal.resolve("provisioning.json"),"{}");check(TokenProvision.allPolyfillKeysSaved(journal),"Complete journal not detected");
            System.setProperty("pqmail.provision.helper",temp.resolve("missing-helper").toString());
            char[] failedPin="654321".toCharArray(),failedManagement="00000000000000000000000000000000".toCharArray();
            rejects(()->TokenProvision.createPolyfill("123456",journal,failedPin,failedManagement));wiped(failedPin);wiped(failedManagement);
        }finally{
            System.clearProperty("pqmail.provision.helper");try(var paths=Files.walk(temp)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
        }
        System.out.println("PASS polyfill provisioning command routes, exact slot/algorithm decoding, duplicate and malformed output rejection, recovery files, and credential clearing; no hardware used");
    }
}
