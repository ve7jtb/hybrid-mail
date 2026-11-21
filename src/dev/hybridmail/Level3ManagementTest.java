package dev.hybridmail;
import java.nio.file.*;
import java.util.*;
/** Malformed backup credentials must fail before any card or filesystem work. */
public final class Level3ManagementTest {
    public static void main(String[] args)throws Exception {
        for(String value:List.of("","123456"," ","g".repeat(48),"é".repeat(48))){
            Path root=Files.createTempDirectory("management-test-");Path target=root.resolve("must-not-exist");char[] pin="123456".toCharArray(),management=value.toCharArray();
            try{
                try{Level3PolyfillSetup.run(123456,List.of("test@example.test"),target,pin,management,false,new Level3PolyfillSetup.Paths("unused","unused",Map.of()));throw new AssertionError("Accepted invalid management input");}
                catch(java.security.GeneralSecurityException expected){if(!expected.getMessage().startsWith("Management key must"))throw expected;}
                if(Files.exists(target)||!Arrays.equals(pin,new char[pin.length])||!Arrays.equals(management,new char[management.length]))throw new AssertionError("Invalid input caused side effects or retained credentials");
            }finally{Files.deleteIfExists(root);}
        }
        for(int size:List.of(32,48,64))Level3PolyfillSetup.validateManagement("0123456789abcdef".repeat(4).substring(0,size).toCharArray());
        System.out.println("PASS management validation: malformed input rejected before card/filesystem access; credential arrays cleared; valid hexadecimal sizes accepted");
    }
}
