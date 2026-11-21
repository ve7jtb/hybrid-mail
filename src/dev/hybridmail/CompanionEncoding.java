package dev.hybridmail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/** Storage compression only: the enclosed signature, AAD and ciphertext are
 * preserved byte for byte. No private-key operation is needed to compact an
 * existing companion. Expansion is bounded before allocating its output. */
final class CompanionEncoding {
    static final int MAX = 65536;
    static final byte[] MAGIC = {'P','Q','M','C','Z','0','0','1'};

    static boolean compressed(byte[] encoded) {
        return encoded.length >= MAGIC.length
            && Arrays.equals(MAGIC, Arrays.copyOf(encoded, MAGIC.length));
    }

    /** Convert either representation to one bounded zlib wrapper. The original
     * representation remains readable so an interrupted replacement can recover
     * from its durable encrypted backup without recreating any identity keys. */
    static byte[] pack(byte[] encoded) throws IOException {
        byte[] inner = unpack(encoded);
        Deflater compressor = new Deflater(Deflater.BEST_COMPRESSION);
        try {
            compressor.setInput(inner);
            compressor.finish();
            var out = new ByteArrayOutputStream();
            out.writeBytes(MAGIC);
            out.writeBytes(ByteBuffer.allocate(4).putInt(inner.length).array());
            byte[] buffer = new byte[4096];
            while (!compressor.finished()) {
                int count = compressor.deflate(buffer);
                if (count == 0 || out.size() + count > MAX)
                    throw new IOException("Compressed companion exceeds storage limit");
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        } finally { compressor.end(); }
    }

    /** A single zlib stream must consume the entire input and produce exactly
     * the declared size. Never recursively decompress or trust that size alone:
     * untrusted card/file data can otherwise cause unbounded memory use. */
    static byte[] unpack(byte[] encoded) throws IOException {
        if (encoded.length == 0 || encoded.length > MAX)
            throw new IOException("Companion exceeds storage limit");
        if (!compressed(encoded)) return encoded.clone();
        if (encoded.length <= 12) throw new IOException("Truncated compressed companion");
        int size = ByteBuffer.wrap(encoded, 8, 4).getInt();
        if (size <= 0 || size > MAX) throw new IOException("Invalid companion expansion length");
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(encoded, 12, encoded.length - 12);
            var out = new ByteArrayOutputStream(size);
            byte[] buffer = new byte[4096];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (out.size() + count > size)
                    throw new IOException("Companion expansion exceeds declared length");
                out.write(buffer, 0, count);
                if (count == 0 && !inflater.finished())
                    throw new IOException("Incomplete compressed companion");
            }
            if (out.size() != size || inflater.getRemaining() != 0)
                throw new IOException("Invalid compressed companion length or trailing data");
            byte[] inner = out.toByteArray();
            if (compressed(inner)) throw new IOException("Nested companion compression is forbidden");
            return inner;
        } catch (DataFormatException e) {
            throw new IOException("Invalid compressed companion", e);
        } finally { inflater.end(); }
    }
}
