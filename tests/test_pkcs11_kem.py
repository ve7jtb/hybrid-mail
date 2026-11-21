import base64
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
import tempfile
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
    def test_single_process_pipe_cleanup_and_no_retry(self):
        for failure in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                executable=Path(directory)/'openssl'
                (Path(directory)/'pqmail-pkcs11-kem').touch()
                pin=bytearray(b'654321');calls=[];paths=[]
                def run(command,**kwargs):
                    calls.append(command);paths.extend([Path(command[-1]),Path(command[-2])])
                    self.assertEqual(kwargs['input'],b'654321\n')
                    self.assertTrue(kwargs['start_new_session'])
                    self.assertEqual(kwargs['env']['YKCS11_DISCOVERY_ID'],'3')
                    self.assertFalse(any('654321' in arg for arg in command))
                    self.assertFalse(any('654321' in value for value in kwargs['env'].values()))
                    return subprocess.CompletedProcess(command,1 if failure else 0,stdout=b's'*32,stderr=b'')
                if failure:
                    with self.assertRaises(KEM.AdapterError):KEM.recover('ML-KEM-1024',b'p'*1582,b'c'*1568,str(executable),'/provider','/module','123456','9d',pin,run)
                else:
                    self.assertEqual(KEM.recover('ML-KEM-1024',b'p'*1582,b'c'*1568,str(executable),'/provider','/module','123456','9d',pin,run),b's'*32)
                self.assertEqual(len(calls),1);self.assertEqual(pin,bytearray(6))
                self.assertTrue(all(not path.exists() for path in paths))
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
    def test_single_process_failure_reports_only_bounded_diagnostics(self):
        result=subprocess.CompletedProcess([],1,stderr=(
            b'PIN=654321; private diagnostic /secret/path\n'
            b'PQ Mail single-session decryption failed at PIN input; no retry\n'
            b'PQMAIL_ERROR 03000096 operation not supported for this keytype\n'
            b'PQMAIL_KEM_STEP derive-set-peer\n'
            b'PQMAIL_KEM_STEP secret 654321\n'
            b'PQMAIL_PIN_CALLBACKS 0\n'
            b'PQMAIL_PIN_CALLBACKS 0\n'
            b'PQMAIL_ERROR 03000096 /secret/path\n'
            b'error:03000096:lib:func:secret 654321\n'))
        message=KEM.single_process_failure(result,'ECDH-P384')
        self.assertIn('failed at PIN input; no retry',message)
        self.assertIn('PQMAIL_ERROR 03000096 operation not supported for this keytype',message)
        self.assertEqual(message.count('PQMAIL_PIN_CALLBACKS'),1)
        self.assertIn('PQMAIL_KEM_STEP derive-set-peer',message)
        self.assertEqual(message.count('PQMAIL_KEM_STEP'),1)
        self.assertNotIn('654321',message);self.assertNotIn('/secret/path',message)
        self.assertNotIn('error:',message)
    def test_single_process_failure_rejects_unknown_or_injected_stage(self):
        for raw in (None,'not bytes',b'PQ Mail single-session decryption failed at secret 654321; no retry\n',
                    b'PQ Mail single-session decryption failed at recover /secret/path; no retry\n'):
            message=KEM.single_process_failure(subprocess.CompletedProcess([],1,stderr=raw),'X25519')
            self.assertEqual(message,'Single-process PKCS#11 X25519 failed; no retry')
if __name__=='__main__':unittest.main()
