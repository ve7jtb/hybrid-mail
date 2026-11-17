import base64,importlib.util,io,os,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
root=Path(__file__).parents[1]
def load(name,path):
 s=importlib.util.spec_from_file_location(name,root/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
SIGN=load('sign87','adapters/pkcs11-mu.py');KEM=load('kem87','adapters/pkcs11-kem.py')
class Profiles87(unittest.TestCase):
 def test_signature_lengths_options_and_pin_clear(self):
  for algorithm,publen,hashlen,siglen,option in [('ML-DSA-44',1334,64,2420,'mu:1'),('ML-DSA-87',2614,64,4627,'mu:1'),('ECDSA-P384-SHA384',120,48,102,'digest:sha384')]:
   public=b'p'*publen;payload=b'm'*hashlen;pin=bytearray(b'123456')
   request=io.BytesIO(algorithm.encode()+b'\n'+base64.b64encode(public)+b'\n'+base64.b64encode(payload)+b'\n')
   self.assertEqual(SIGN.read_request(request),(algorithm,public,payload))
   def run(command,**kwargs):
    if command[1]=='pkey':Path(command[-1]).write_bytes(public)
    else:
     self.assertIn(option,command);self.assertNotIn('123456',repr(command));self.assertEqual(os.read(kwargs['pass_fds'][0],20),b'123456\n');Path(command[command.index('-out')+1]).write_bytes(b's'*siglen)
    return subprocess.CompletedProcess(command,0)
   result=SIGN.sign(public,payload,'/openssl','/provider','/module','123',io.BytesIO(),run,algorithm,'9a',pin)
   self.assertEqual(len(result),siglen);self.assertEqual(pin,bytearray(6))
 def test_kem1024_and_p384(self):
  for algorithm,publen,datalen,secretlen in [('ML-KEM-1024',1590,1568,32),('ECDH-P384',120,120,48)]:
   public=b'p'*publen;data=b'c'*datalen;pin=bytearray(b'123456')
   request=io.BytesIO(algorithm.encode()+b'\n'+base64.b64encode(public)+b'\n'+base64.b64encode(data)+b'\n');self.assertEqual(KEM.read_request(request),(algorithm,public,data))
   def run(command,**kwargs):
    if command[1]=='pkey':Path(command[-1]).write_bytes(public);return subprocess.CompletedProcess(command,0)
    self.assertIn('-decap' if algorithm.startswith('ML-KEM') else '-derive',command);self.assertEqual(os.read(kwargs['pass_fds'][0],20),b'123456\n');return subprocess.CompletedProcess(command,0,stdout=b's'*secretlen)
   self.assertEqual(len(KEM.recover(algorithm,public,data,'/openssl','/provider','/module','123','9d',pin,run)),secretlen);self.assertEqual(pin,bytearray(6))
