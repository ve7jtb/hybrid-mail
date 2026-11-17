package dev.hybridmail;
import java.nio.file.*;
final class PrivateFiles {
    static void create(Path path)throws java.io.IOException {
        Files.createFile(path); // CREATE_NEW: never silently overwrite an identity.
        path.toFile().setReadable(false,false);path.toFile().setWritable(false,false);
        if(!path.toFile().setReadable(true,true)||!path.toFile().setWritable(true,true))throw new java.io.IOException("Cannot protect private identity file");
    }
}
