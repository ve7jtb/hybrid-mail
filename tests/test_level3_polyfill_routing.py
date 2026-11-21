"""Closed slot routing tests with fake native processes; never access a token."""
import base64
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parents[1]/'adapters'/file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


SIGN=load('polyfill_sign','pkcs11-mu.py')
KEM=load('polyfill_kem','pkcs11-kem.py')


class Level3PolyfillRoutingTest(unittest.TestCase):
    def test_message_and_certification_signing_use_distinct_fixed_slots(self):
        for certification,expected in [(False,'%02'),(True,'%05')]:
            with tempfile.TemporaryDirectory() as directory:
                executable=Path(directory)/'openssl';(Path(directory)/'pqmail-pkcs11-sign').touch()
                calls=[];pin=bytearray(b'654321')
                def run(command,**kwargs):
                    calls.append(command)
                    self.assertEqual(command[2],'pkcs11:serial=123456;id='+expected+';type=')
                    self.assertEqual(kwargs['env']['YKCS11_DISCOVERY_ID'],str(int(expected[1:],16)))
                    self.assertEqual(kwargs['input'],b'654321\n')
                    self.assertNotIn('654321',' '.join(command))
                    self.assertNotIn('654321',str(kwargs['env']))
                    self.assertEqual(Path(command[4]).read_bytes(),b'd'*64)
                    Path(command[5]).write_bytes(b's'*64)
                    return subprocess.CompletedProcess(command,0)
                env={'PQMAIL_LEVEL3_POLYFILL':'1'}
                if certification:env['PQMAIL_POLYFILL_CERTIFICATION']='1'
                with patch.dict(os.environ,env,clear=True):
                    result=SIGN.sign(b'p'*44,b'd'*64,str(executable),'/provider','/module','123456',io.BytesIO(),run,algorithm='Ed25519',ec_slot='84',pin=pin)
                self.assertEqual(result,b's'*64);self.assertEqual(len(calls),1);self.assertEqual(pin,bytearray(6))

    def test_wrapping_and_message_decryption_use_distinct_fixed_slots(self):
        for algorithm,slot,object_id,length in [('ECDH-P384','83','%06',48),('X25519','9d','%03',32)]:
            with tempfile.TemporaryDirectory() as directory:
                executable=Path(directory)/'openssl';(Path(directory)/'pqmail-pkcs11-kem').touch()
                calls=[];pin=bytearray(b'654321')
                def run(command,**kwargs):
                    calls.append(command)
                    self.assertEqual(command[2],'pkcs11:serial=123456;id='+object_id+';type=')
                    self.assertEqual(kwargs['env']['YKCS11_DISCOVERY_ID'],str(int(object_id[1:],16)))
                    self.assertEqual(kwargs['input'],b'654321\n')
                    return subprocess.CompletedProcess(command,0,stdout=b's'*length,stderr=b'')
                with patch.dict(os.environ,{'PQMAIL_LEVEL3_POLYFILL':'1','PKCS11_ECDH_SLOT':'85'},clear=True):
                    self.assertEqual(KEM.selected_slot(algorithm),slot)
                    result=KEM.recover(algorithm,b'p'*44,b'q'*44,str(executable),'/provider','/module','123456',slot,pin,run)
                self.assertEqual(result,b's'*length);self.assertEqual(len(calls),1);self.assertEqual(pin,bytearray(6))

    def test_rejects_token_pq_or_wrong_slot_before_any_process(self):
        def forbidden(*args,**kwargs):self.fail('Rejected request started a process')
        with patch.dict(os.environ,{'PQMAIL_LEVEL3_POLYFILL':'1'},clear=True):
            for algorithm in ['ML-DSA-44','ML-DSA-65','ML-DSA-87','ECDSA-P384-SHA384']:
                pin=bytearray(b'654321')
                with self.assertRaises(SIGN.AdapterError):SIGN.sign(b'p',b'd','/openssl','/provider','/module','123456',io.BytesIO(),forbidden,algorithm=algorithm,pin=pin)
                self.assertEqual(pin,bytearray(6))
            for algorithm,slot in [('ML-KEM-768','9d'),('ML-KEM-1024','9d'),('ECDH-P256','83'),('ECDH-P384','82'),('X25519','85')]:
                pin=bytearray(b'654321')
                with self.assertRaises(KEM.AdapterError):KEM.recover(algorithm,b'p',b'd','/openssl','/provider','/module','123456',slot,pin,forbidden)
                self.assertEqual(pin,bytearray(6))

    def test_rejects_conflicting_profile_flags(self):
        conflicts=[{'PQMAIL_LEVEL3_POLYFILL':x} for x in ['', '0','true']]
        conflicts += [{'PQMAIL_POLYFILL_CERTIFICATION':'1'}]
        conflicts += [{'PQMAIL_LEVEL3_POLYFILL':'1',name:value} for name,value in [
            ('PQMAIL_POLYFILL_CERTIFICATION','0'),('PQMAIL_LEVEL5_COMPATIBILITY','1'),
            ('PQMAIL_COMPATIBILITY_SLOT','88'),('PQMAIL_CERTIFICATION_SLOTS','86,87')]]
        for env in conflicts:
            with patch.dict(os.environ,env,clear=True):
                with self.assertRaises(SIGN.AdapterError):SIGN.signing_object_id('Ed25519','')
                with self.assertRaises(KEM.AdapterError):KEM.selected_slot('X25519')
        with patch.dict(os.environ,{'PQMAIL_LEVEL3_POLYFILL':'1','PQMAIL_POLYFILL_CERTIFICATION':'1'},clear=True):
            with self.assertRaises(KEM.AdapterError):KEM.selected_slot('ECDH-P384')

    def test_existing_profile_and_digest_size_guards_remain(self):
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(SIGN.signing_object_id('Ed25519',''),'%07')
            self.assertEqual(KEM.selected_slot('X25519'),'85')
            with self.assertRaises(SIGN.AdapterError):SIGN.ec_object_id('9c')
        for length in [48,64]:
            request=b'Ed25519\n'+base64.b64encode(b'p'*44)+b'\n'+base64.b64encode(b'd'*length)+b'\n'
            self.assertEqual(len(SIGN.read_request(io.BytesIO(request))[2]),length)
        for length in [0,32,47,49,63,65]:
            request=b'Ed25519\n'+base64.b64encode(b'p'*44)+b'\n'+base64.b64encode(b'd'*length)+b'\n'
            with self.assertRaises(SIGN.AdapterError):SIGN.read_request(io.BytesIO(request))


if __name__=='__main__':unittest.main()
