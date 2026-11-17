package dev.hybridmail;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.io.IOException;
final class PrivateFiles {
 static void protect(Path path,boolean directory)throws IOException{
  if(Files.getFileStore(path).supportsFileAttributeView("posix")){Files.setPosixFilePermissions(path,PosixFilePermissions.fromString(directory?"rwx------":"rw-------"));return;}
  var view=Files.getFileAttributeView(path,AclFileAttributeView.class);if(view==null)throw new IOException("Filesystem cannot protect private identity files");
  var entry=AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(path)).setPermissions(EnumSet.allOf(AclEntryPermission.class));
  if(directory)entry.setFlags(AclEntryFlag.FILE_INHERIT,AclEntryFlag.DIRECTORY_INHERIT);view.setAcl(List.of(entry.build()));
 }
 static void directory(Path path)throws IOException{Files.createDirectories(path);protect(path,true);}
 static void create(Path path)throws IOException{Files.createFile(path);protect(path,false);}
 static Path temporary(Path parent)throws IOException{Path path=Files.createTempFile(parent,".save-",".tmp");protect(path,false);return path;}
}
