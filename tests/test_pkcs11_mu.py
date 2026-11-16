import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location("pkcs11_mu",Path(__file__).parents[1]/"adapters"/"pkcs11-mu.py")
ADAPTER=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(ADAPTER)
PUBLIC=b"p"*1974;MU=bytes(range(64));SIGNATURE=b"s"*3309

class Pkcs11AdapterTest(unittest.TestCase):
    def setUp(self):self.terminal=io.BytesIO();self.commands=[];self.paths=[]
    def fake(self,wrong_key=False,fail_sign=False,bad_length=False,fail_export=False):
        def run(command,**kwargs):
            self.commands.append(command)
            self.assertNotIn("--pin",command);self.assertNotIn("-passin",command)
            self.assertFalse(any("pin-value" in x or "pin-source" in x for x in command))
            self.assertIs(kwargs["stdin"],self.terminal);self.assertIs(kwargs["stderr"],self.terminal)
            self.assertNotIn("PKCS11_PROVIDER_MODULE",kwargs["env"])
            self.assertNotIn("PKCS11_PROVIDER_DEBUG",kwargs["env"])
            conf=Path(kwargs["env"]["OPENSSL_CONF"]);self.paths.append(conf)
            self.assertIn('module = "/provider/pkcs11.dylib"',conf.read_text())
            self.assertIn('pkcs11-module-path = "/module/libykcs11.dylib"',conf.read_text())
            self.assertNotIn("token-pin",conf.read_text())
            out=Path(command[-1]);self.paths.append(out)
            if command[1]=="pkey":
                self.assertIn("pkcs11:serial=123456;id=%02;type=public",command)
                if fail_export:return subprocess.CompletedProcess(command,1)
                out.write_bytes(b"wrong" if wrong_key else PUBLIC)
            else:
                self.assertIn("pkcs11:serial=123456;id=%02;type=private",command)
                self.assertEqual(command[command.index("-pkeyopt")+1],"mu:1")
                self.assertNotIn("-rawin",command)
                self.assertFalse(any("context-string" in x for x in command))
                self.assertEqual(Path(command[command.index("-in")+1]).read_bytes(),MU)
                if fail_sign:return subprocess.CompletedProcess(command,1)
                out.write_bytes(b"bad" if bad_length else SIGNATURE)
            return subprocess.CompletedProcess(command,0)
        return run
    def call(self,runner,serial="123456",provider="/provider/pkcs11.dylib"):
        return ADAPTER.sign(PUBLIC,MU,"/openssl",provider,"/module/libykcs11.dylib",serial,self.terminal,runner)
    def test_sign_and_cleanup(self):
        with patch.dict(os.environ,{"PKCS11_PROVIDER_MODULE":"/wrong","PKCS11_PROVIDER_DEBUG":"file:/wrong"}):
            self.assertEqual(self.call(self.fake()),SIGNATURE)
        self.assertEqual(len(self.commands),2);self.assertTrue(all(not p.exists() for p in self.paths))
    def test_wrong_key_does_not_sign(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(wrong_key=True))
        self.assertEqual(len(self.commands),1)
    def test_export_failure(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(fail_export=True))
        self.assertEqual(len(self.commands),1)
    def test_sign_failure_no_retry(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(fail_sign=True))
        self.assertEqual(len(self.commands),2)
    def test_invalid_signature_length(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(bad_length=True))
    def test_explicit_serial(self):
        for serial in ("","123;id=%01","abc"):
            with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(),serial=serial)
        self.assertEqual(self.commands,[])
    def test_config_injection(self):
        for path in ('relative','/bad\nactivate=0','/bad"','/$ENV::HOME','/bad\\path'):
            with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(),provider=path)
        self.assertEqual(self.commands,[])
    def test_paths_with_spaces(self):self.assertIn('"/some folder/provider"',ADAPTER.configuration('/some folder/provider','/module'))
    def test_timeout_no_retry(self):
        def timeout(command,**kwargs):
            self.commands.append(command);raise subprocess.TimeoutExpired(command,30)
        with self.assertRaises(subprocess.TimeoutExpired):self.call(timeout)
        self.assertEqual(len(self.commands),1)

if __name__=="__main__":unittest.main()
