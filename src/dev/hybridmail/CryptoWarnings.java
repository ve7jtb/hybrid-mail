package dev.hybridmail;
import java.security.PublicKey;
import java.util.Locale;
import org.bouncycastle.jcajce.CompositePublicKey;
/** UI classification is conservative: unrecognized algorithms do not get a PQ label. */
final class CryptoWarnings {
 static boolean pq(PublicKey key,boolean signing){
  if(key==null)return false;
  if(key instanceof CompositePublicKey composite)return composite.getPublicKeys().stream().anyMatch(k->pq(k,signing));
  String name=key.getAlgorithm().toUpperCase(Locale.ROOT).replace("-","");return name.startsWith(signing?"MLDSA":"MLKEM");
 }
 static final String SIGNATURE="WARNING: Valid classical signature — not post-quantum resistant.\nIt does not provide post-quantum protection against signature forgery.\n";
 static String encryption(String algorithm){return "WARNING: Encryption is not post-quantum resistant.\nAlgorithm: "+algorithm+"\n\nA future cryptographically relevant quantum computer could decrypt captured messages. A hybrid signature does not make this encryption post-quantum resistant.\n\nContinue with classical encryption?";}
}
