import java.nio.file.*;
import java.util.Properties;

/** Build-time policy; check the JDK and the actual jlink image before shipping. */
class CheckJava {
    static final String MINIMUM = "25.0.5.1";
    static boolean supported(String text) {
        try {
            var v = Runtime.Version.parse(text);
            return v.feature() == 25 && v.pre().isEmpty()
                && v.compareToIgnoreOptional(Runtime.Version.parse(MINIMUM)) >= 0;
        } catch (IllegalArgumentException e) { return false; }
    }
    static void require(String version) {
        if (!supported(version)) throw new IllegalStateException(
            "PQ Mail requires a GA JDK 25 runtime >= " + MINIMUM + "; found " + version);
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--test")) {
            for (String v : new String[]{"25", "25.0.5+8", "25.0.5.0.3+1", "25.0.5.1-ea+2", "24.0.9", "26", "invalid"})
                if (supported(v)) throw new AssertionError("Accepted " + v);
            for (String v : new String[]{"25.0.5.1", "25.0.5.1+2", "25.0.6+1", "25.0.10+1"})
                if (!supported(v)) throw new AssertionError("Rejected " + v);
            System.out.println("PASS Java runtime version policy");
            return;
        }
        require(Runtime.version().toString());
        String version = Runtime.version().toString();
        String arch = System.getProperty("os.arch");
        if (args.length == 2) {
            var p = new Properties();
            try (var in = Files.newInputStream(Path.of(args[0], "release"))) { p.load(in); }
            version = p.getProperty("JAVA_VERSION", "").replace("\"", "");
            require(version);
            String imageArch = p.getProperty("OS_ARCH", arch).replace("\"", "");
            if (!imageArch.equals(arch)) throw new IllegalStateException("Runtime architecture mismatch: " + imageArch);
            Files.writeString(Path.of(args[1]), "Bundled Java: " + version + "\nArchitecture: " + imageArch
                + "\nBuild JDK: " + Runtime.version() + "\nVendor: " + System.getProperty("java.vendor") + "\n");
        } else if (args.length != 0) throw new IllegalArgumentException("Usage: CheckJava [runtime-home evidence-file | --test]");
        System.out.println("PASS Java runtime " + version + " (" + arch + "), minimum " + MINIMUM);
    }
}
