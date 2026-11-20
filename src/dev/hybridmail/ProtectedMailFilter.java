package dev.hybridmail;

import jakarta.mail.internet.ContentType;
import java.util.Locale;

/** Header-only inbox classification, not cryptographic verification.
 * Inline OpenPGP and protected messages nested in attachments need body reads
 * and intentionally do not match this metadata-only filter. */
final class ProtectedMailFilter {
    static boolean matches(String value) {
        try {
            var type=new ContentType(value);
            String base=type.getBaseType().toLowerCase(Locale.ROOT);
            String protocol=type.getParameter("protocol");
            if(base.equals("application/pkcs7-mime")||base.equals("application/x-pkcs7-mime"))return true;
            if(protocol==null)return false;
            if(base.equals("multipart/signed"))return protocol.equalsIgnoreCase("application/pkcs7-signature")
                ||protocol.equalsIgnoreCase("application/x-pkcs7-signature")||protocol.equalsIgnoreCase("application/pgp-signature");
            return base.equals("multipart/encrypted")&&protocol.equalsIgnoreCase("application/pgp-encrypted");
        } catch(Exception invalidHeader) { return false; }
    }
}
