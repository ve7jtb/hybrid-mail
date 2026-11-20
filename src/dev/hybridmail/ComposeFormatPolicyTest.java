package dev.hybridmail;
public final class ComposeFormatPolicyTest {
 private static void check(boolean condition){if(!condition)throw new AssertionError("Compose format policy");}
 public static void main(String[] args){
  var policy=new ComposeFormatPolicy();
  check(policy.select("none@example.test",false,false));
  check(policy.select("pgp@example.test",true,false));
  check(!policy.select("smime@example.test",false,true));
  check(policy.select("both@example.test",true,true));
  policy.choose("both@example.test",false);
  check(!policy.select(" BOTH@example.test ",true,true));
  check(policy.select("new@example.test",true,true));
  check(!policy.select("new@example.test",false,true));
  check(policy.select("new@example.test",true,true));
  policy.choose("new@example.test",true);
  check(policy.select("new@example.test",false,true));
  check(!policy.select("other@example.test",false,true));
  System.out.println("PASS Compose format: OpenPGP default, S/MIME-only fallback, both/unknown contacts, manual override and recipient changes");
 }
}
