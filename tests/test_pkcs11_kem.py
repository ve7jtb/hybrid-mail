import base64
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
SPEC=importlib.util.spec_from_file_location('kem',Path(__file__).parents[1]/'adapters/pkcs11-kem.py')
KEM=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(KEM)

class KemAdapterTest(unittest.TestCase):
    def run_case(self,algorithm='ML-KEM-768',wrong_key=False,fail=False,bad_length=False):
        public=b'p'*(1206 if algorithm=='ML-KEM-768' else 91)
        data=b'c'*(1088 if algorithm=='ML-KEM-768' else 91)
        pin=bytearray(b'654321');calls=[];paths=[]
        def run(command,**kwargs):
            calls.append(command)
            self.assertFalse(any('654321' in arg for arg in command))
            self.assertFalse(any('654321' in value for value in kwargs['env'].values()))
            config=Path(kwargs['env']['OPENSSL_CONF']);paths.append(config)
            self.assertNotIn('654321',config.read_text())
            if command[1]=='pkey':
                self.assertIn('pkcs11-module-login-behavior = never',config.read_text())
                target=Path(command[-1]);paths.append(target);target.write_bytes(b'w'*len(public) if wrong_key else public)
                return subprocess.CompletedProcess(command,0,stderr=b'')
            self.assertIs(kwargs['stdout'],subprocess.PIPE)
            self.assertNotIn('-out',command);self.assertNotIn('-secret',command)
            if algorithm=='ML-KEM-768':
                self.assertIn('-decap',command);self.assertIn('pkcs11:serial=123456;id=%03;type=private',command)
                infile=Path(command[command.index('-in')+1])
            else:
                self.assertIn('-derive',command);self.assertIn('pkcs11:serial=123456;id=%05;type=private',command)
                self.assertIn('-peerform',command);infile=Path(command[command.index('-peerkey')+1])
            paths.append(infile);self.assertEqual(infile.read_bytes(),data)
            fd=kwargs['pass_fds'][0];self.assertEqual(os.read(fd,20),b'654321\n')
            return subprocess.CompletedProcess(command,1 if fail else 0,stdout=b's'*(31 if bad_length else 32),stderr=b'')
        try:
            result=KEM.recover(algorithm,public,data,'/openssl','/provider','/module','123456','9d' if algorithm=='ML-KEM-768' else '82',pin,run)
            self.assertEqual(result,b's'*32)
        finally:
            self.assertEqual(pin,bytearray(6));self.assertTrue(all(not p.exists() for p in paths))
            self.assertEqual(len(calls),1 if wrong_key else 2)
    def test_mlkem_pipe_and_cleanup(self):self.run_case()
    def test_ecdh_pipe_and_cleanup(self):self.run_case('ECDH-P256')
    def test_wrong_key_no_private_operation(self):
        with self.assertRaises(KEM.AdapterError):self.run_case(wrong_key=True)
    def test_failure_no_retry(self):
        with self.assertRaises(KEM.AdapterError):self.run_case(fail=True)
    def test_wrong_secret_length(self):
        with self.assertRaises(KEM.AdapterError):self.run_case(bad_length=True)
    def test_slot_guards(self):
        for slot in ('9a','9c','9e','','9d;type=private'):
            with self.assertRaises(KEM.AdapterError):KEM.object_id(slot)
    def test_request_length(self):
        def request(data):return io.BytesIO(b'ML-KEM-768\n'+base64.b64encode(b'p'*1206)+b'\n'+base64.b64encode(data)+b'\n')
        self.assertEqual(KEM.read_request(request(b'c'*1088))[0],'ML-KEM-768')
        for size in (0,1087,1089):
            with self.assertRaises(KEM.AdapterError):KEM.read_request(request(b'c'*size))
    def test_timeout_clears_pin(self):
        pin=bytearray(b'654321');calls=[]
        def timeout(command,**kwargs):calls.append(command);raise subprocess.TimeoutExpired(command,30)
        with self.assertRaises(subprocess.TimeoutExpired):KEM.recover('ML-KEM-768',b'p'*1206,b'c'*1088,'/openssl','/provider','/module','123456','9d',pin,timeout)
        self.assertEqual(pin,bytearray(6));self.assertEqual(len(calls),1)
if __name__=='__main__':unittest.main()
