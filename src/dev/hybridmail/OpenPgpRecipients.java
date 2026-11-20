package dev.hybridmail;
import java.util.*;
/** Compose lookup state: stale network responses never select a different recipient. */
final class OpenPgpRecipients {
 record Ticket(long generation,String address){}
 private long generation;
 private String address="";
 private final Map<String,OpenPgp.PublicIdentity> known=new LinkedHashMap<>();
 Ticket change(String value){address=value.trim();return new Ticket(++generation,address);}
 boolean current(Ticket ticket){return ticket.generation()==generation&&ticket.address().equals(address);}
 void clear(){known.clear();generation++;}
 void remember(OpenPgp.PublicIdentity key)throws Exception{known.put(key.fingerprint(),key);}
 boolean accept(Ticket ticket,OpenPgp.PublicIdentity key)throws Exception{
  if(!current(ticket)||!key.matchesEmail(address))return false;remember(key);return true;
 }
 List<OpenPgp.PublicIdentity> choices(){return known.values().stream().filter(k->k.matchesEmail(address)).sorted(Comparator.comparingInt(OpenPgp.PublicIdentity::version).reversed().thenComparing(k->!k.quantumEncryption())).toList();}
}
