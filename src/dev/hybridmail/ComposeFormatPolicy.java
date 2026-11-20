package dev.hybridmail;
import java.util.Locale;
/** Recipient-scoped default; choosing a format never implies certificate trust. */
final class ComposeFormatPolicy {
 private String address="";
 private Boolean manual;
 private static String normalize(String value){return value.trim().toLowerCase(Locale.ROOT);}
 void choose(String recipient,boolean openPgp){address=normalize(recipient);manual=openPgp;}
 boolean select(String recipient,boolean hasPgp,boolean hasSmime){
  String next=normalize(recipient);
  if(!next.equals(address)){address=next;manual=null;}
  return manual!=null?manual:hasPgp||!hasSmime;
 }
}
