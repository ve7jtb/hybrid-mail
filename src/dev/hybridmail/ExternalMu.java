package dev.hybridmail;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;

/** Host computes FIPS 204 mu using the public key; backend never receives message bytes. */
public final class ExternalMu {
    @FunctionalInterface public interface Backend {
        byte[] sign(PublicKey publicKey, byte[] mu) throws Exception;
    }
    public record TokenKey(PublicKey publicKey, Backend backend) implements PrivateKey {
        public String getAlgorithm() { return "ML-DSA-65"; }
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
    }
    public static final Provider PROVIDER = new Provider("ExternalMu", "1.0", "External mu ML-DSA adapter") {{
        put("Signature.ML-DSA-65", MuSignature.class.getName());
    }};
    public static final class MuSignature extends SignatureSpi {
        private TokenKey key;
        private byte[] context = new byte[0];
        private MLDSASigner digest;
        private boolean started;
        private void resetDigest() throws InvalidKeyException {
            try {
                digest = new MLDSASigner();
                digest.init(false, new ParametersWithContext(PublicKeyFactory.createKey(key.publicKey().getEncoded()), context));
                started = false;
            } catch (Exception e) { throw new InvalidKeyException(e); }
        }
        protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
            if (!(k instanceof TokenKey t)) throw new InvalidKeyException("Expected external token key");
            key = t; resetDigest();
        }
        protected void engineInitVerify(PublicKey k) throws InvalidKeyException { throw new InvalidKeyException("Use BC to verify"); }
        protected void engineUpdate(byte b) { started = true; digest.update(b); }
        protected void engineUpdate(byte[] b, int off, int len) { started = true; digest.update(b, off, len); }
        protected byte[] engineSign() throws SignatureException {
            try {
                byte[] mu = digest.generateMu();
                byte[] sig = key.backend().sign(key.publicKey(), mu.clone());
                if (sig == null || !digest.verifyMuSignature(mu, sig))
                    throw new SignatureException("External signer returned an invalid signature for this key/mu");
                return sig;
            } catch (Exception e) { throw new SignatureException("External mu signing failed", e); }
            finally { try { resetDigest(); } catch (Exception ignored) {} }
        }
        protected boolean engineVerify(byte[] s) { return false; }
        protected void engineSetParameter(AlgorithmParameterSpec p) throws InvalidAlgorithmParameterException {
            if (started || !(p instanceof ContextParameterSpec c) || c.getContext().length > 255)
                throw new InvalidAlgorithmParameterException("Expected context before message");
            context = c.getContext().clone();
            if (key != null) try { resetDigest(); } catch (Exception e) { throw new InvalidAlgorithmParameterException(e); }
        }
        @Deprecated protected void engineSetParameter(String n, Object v) { throw new UnsupportedOperationException(); }
        @Deprecated protected Object engineGetParameter(String n) { throw new UnsupportedOperationException(); }
    }
    /** Executable protocol: 3 UTF-8 lines on stdin, one base64 signature on stdout. No shell. */
    public static Backend executable(String executable) {
        return (publicKey, mu) -> {
            Process p = new ProcessBuilder(executable).redirectError(ProcessBuilder.Redirect.DISCARD).start();
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<byte[]> output = pool.submit(() -> {
                    byte[] result = p.getInputStream().readNBytes(16385);
                    if (result.length > 16384) throw new IOException("Adapter output too large");
                    return result;
                });
                try (OutputStream out = p.getOutputStream()) {
                    out.write(("ML-DSA-65\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n"
                        + Base64.getEncoder().encodeToString(mu) + "\n").getBytes(StandardCharsets.US_ASCII));
                }
                if (!p.waitFor(60, TimeUnit.SECONDS)) throw new IOException("Token adapter timed out");
                if (p.exitValue() != 0) throw new IOException("Token adapter failed (exit " + p.exitValue() + ")");
                return Base64.getDecoder().decode(new String(output.get(1, TimeUnit.SECONDS), StandardCharsets.US_ASCII).trim());
            } finally { p.destroyForcibly(); pool.shutdownNow(); }
        };
    }
}
