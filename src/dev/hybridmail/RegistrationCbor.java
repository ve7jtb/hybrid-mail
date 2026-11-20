package dev.hybridmail;
import java.util.*;
import java.nio.charset.StandardCharsets;
/** Bounded CBOR reader for the registration attestation object's authData bytes only. */
final class RegistrationCbor {
 private final byte[] bytes;private int offset;
 private RegistrationCbor(byte[] b){if(b.length>65536)throw new SecurityException("Attestation too large");bytes=b;}
 private int octet(){if(offset>=bytes.length)throw new SecurityException("Truncated attestation");return bytes[offset++]&255;}
 private int length(int ai){if(ai<24)return ai;int n=switch(ai){case 24->1;case 25->2;case 26->4;default->throw new SecurityException("Unsupported CBOR length");};long value=0;for(int i=0;i<n;i++)value=(value<<8)|octet();if(value>65536)throw new SecurityException("Oversized CBOR item");return (int)value;}
 private Object item(int depth){if(depth>12)throw new SecurityException("Attestation nesting too deep");int head=octet(),major=head>>5,len=length(head&31);if(major<=1||major==7)return null;if(major==2||major==3){if(len>bytes.length-offset)throw new SecurityException("Truncated CBOR data");byte[] b=Arrays.copyOfRange(bytes,offset,offset+len);offset+=len;return major==2?b:new String(b,StandardCharsets.UTF_8);}if(major==4){if(len>100)throw new SecurityException("Oversized CBOR array");for(int i=0;i<len;i++)item(depth+1);return null;}if(major==5){if(len>100)throw new SecurityException("Oversized CBOR map");var map=new HashMap<Object,Object>();for(int i=0;i<len;i++){Object key=item(depth+1),value=item(depth+1);if(map.containsKey(key))throw new SecurityException("Duplicate CBOR map key");map.put(key,value);}return map;}throw new SecurityException("Unsupported CBOR type");}
 static byte[] authData(byte[] input){var reader=new RegistrationCbor(input);Object obj=reader.item(0);if(reader.offset!=input.length||!(obj instanceof Map<?,?> map)||!(map.get("authData") instanceof byte[] data))throw new SecurityException("Invalid attestation object");return data;}
}
