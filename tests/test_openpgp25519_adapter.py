import base64, importlib.util, io, subprocess, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
def module(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/'adapters'/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
SIGN=module('sign25519','pkcs11-mu.py');KEM=module('kem25519','pkcs11-kem.py')
class ExtraKeysTest(unittest.TestCase):
 def test_ed25519_uses_raw_message_and_slot84(self):
  pub=b'p'*44;digest=b'd'*48;calls=[]
  def run(cmd,**kwargs):
   calls.append(cmd)
   self.assertIn('pkcs11:serial=123456;id=%07;type='+('public' if cmd[1]=='pkey' else 'private'),cmd)
   if cmd[1]!='pkey':self.assertIn('-rawin',cmd);self.assertNotIn('-pkeyopt',cmd)
   Path(cmd[-1]).write_bytes(pub if cmd[1]=='pkey' else b's'*64)
   return subprocess.CompletedProcess(cmd,0)
  self.assertEqual(SIGN.sign(pub,digest,'/openssl','/provider','/module','123456',io.BytesIO(),run,algorithm='Ed25519',ec_slot='83'),b's'*64)
  self.assertEqual(len(calls),2)
 def test_request_sizes(self):
  for mod,alg,size in [(SIGN,'Ed25519',48),(SIGN,'Ed25519',64),(KEM,'X25519',44)]:
   request=lambda n:io.BytesIO(alg.encode()+b'\n'+base64.b64encode(b'p'*44)+b'\n'+base64.b64encode(b'd'*n)+b'\n')
   self.assertEqual(mod.read_request(request(size))[0],alg)
   with self.assertRaises(mod.AdapterError):mod.read_request(request(size+1))

 def test_ed25519_rejects_other_hash_lengths(self):
  for size in (0,32,47,49,63,65,128):
   request=io.BytesIO(b'Ed25519\n'+base64.b64encode(b'p'*44)+b'\n'+base64.b64encode(b'd'*size)+b'\n')
   with self.assertRaises(SIGN.AdapterError):SIGN.read_request(request)

 def test_dedicated_signing_slots(self):
  for env,alg,object_id,size in [({'PQMAIL_CERTIFICATION_SLOTS':'86,87'},'ML-DSA-65','%09',3309),({'PQMAIL_CERTIFICATION_SLOTS':'86,87'},'Ed25519','%0A',64),({'PQMAIL_COMPATIBILITY_SLOT':'88'},'Ed25519','%0B',64),({'PQMAIL_LEVEL5_COMPATIBILITY':'1'},'ECDSA-P384-SHA384','%0B',96)]:
   pub=b'p'*44
   def run(cmd,**kwargs):
    self.assertIn('pkcs11:serial=123456;id='+object_id+';type='+('public' if cmd[1]=='pkey' else 'private'),cmd)
    Path(cmd[-1]).write_bytes(pub if cmd[1]=='pkey' else b's'*size)
    return subprocess.CompletedProcess(cmd,0)
   with patch.dict(SIGN.os.environ,env,clear=True):self.assertEqual(len(SIGN.sign(pub,b'd'*64,'/openssl','/provider','/module','123456',io.BytesIO(),run,algorithm=alg,ec_slot="83")),size)

 def test_level5_kem_slot_routes(self):
  with patch.dict(KEM.os.environ,{'PQMAIL_LEVEL5_COMPATIBILITY':'1'},clear=True):
   for alg,slot in [('ML-KEM-768','84'),('X25519','85'),('ECDH-P384','89')]:self.assertEqual(KEM.selected_slot(alg),slot)
   for alg in ['ML-KEM-1024','ECDH-P256','Ed25519']:
    with self.assertRaises(KEM.AdapterError):KEM.selected_slot(alg)
