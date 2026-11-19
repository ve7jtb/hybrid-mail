import base64, importlib.util, io, subprocess, unittest
from pathlib import Path
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
  for mod,alg,size in [(SIGN,'Ed25519',48),(KEM,'X25519',44)]:
   request=lambda n:io.BytesIO(alg.encode()+b'\n'+base64.b64encode(b'p'*44)+b'\n'+base64.b64encode(b'd'*n)+b'\n')
   self.assertEqual(mod.read_request(request(size))[0],alg)
   with self.assertRaises(mod.AdapterError):mod.read_request(request(size+1))
