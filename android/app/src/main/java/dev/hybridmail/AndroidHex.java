package dev.hybridmail;
final class AndroidHex {
    static String format(byte[] bytes) {
        StringBuilder b=new StringBuilder();
        for(byte v:bytes){if(b.length()>0)b.append(':');b.append(String.format(java.util.Locale.ROOT,"%02X",v&255));}
        return b.toString();
    }
}
