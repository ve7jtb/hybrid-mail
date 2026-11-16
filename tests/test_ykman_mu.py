import base64
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest

SPEC = importlib.util.spec_from_file_location("ykman_mu", Path(__file__).parents[1] / "adapters" / "ykman-mu.py")
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
PUBLIC = b"p" * 1974
MU = bytes(range(64))
SIGNATURE = b"s" * 3309

class AdapterTest(unittest.TestCase):
    def request(self, public=PUBLIC, mu=MU, algorithm=b"ML-DSA-65"):
        return io.BytesIO(algorithm+b"\n"+base64.b64encode(public)+b"\n"+base64.b64encode(mu)+b"\n")

    def fake(self, wrong_key=False, failure=False, short_signature=False):
        self.commands=[]
        self.files=[]
        def run(command, **kwargs):
            self.commands.append(command)
            self.assertNotIn("--pin",command)
            self.assertEqual(command[:7],["/test/ykman","--device","123456","--color","never","piv","keys"])
            target=Path(command[-1]);self.files.append(target)
            if "export" in command:
                self.assertIn("der",command)
                target.write_bytes(b"wrong" if wrong_key else PUBLIC)
            else:
                self.assertEqual(command[7:10],["sign","--mu","9c"])
                self.assertEqual(Path(command[-2]).read_bytes(),MU)
                self.assertIs(kwargs["stdin"],self.terminal)
                self.assertIs(kwargs["stderr"],self.terminal)
                if failure:return subprocess.CompletedProcess(command,1)
                target.write_bytes(b"short" if short_signature else SIGNATURE)
            return subprocess.CompletedProcess(command,0)
        return run

    def setUp(self):self.terminal=io.BytesIO()
    def test_protocol(self):self.assertEqual(ADAPTER.read_request(self.request()),(PUBLIC,MU))
    def test_bad_algorithm(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(self.request(algorithm=b"HashML-DSA"))
    def test_short_mu(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(self.request(mu=b"x"*63))
    def test_long_mu(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(self.request(mu=b"x"*65))
    def test_bad_base64(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(io.BytesIO(b"ML-DSA-65\n%%%\n%%%\n"))
    def test_oversized_input(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(io.BytesIO(b"x"*16385+b"\n"))
    def test_exact_command_and_cleanup(self):
        self.assertEqual(ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9c",self.terminal,self.fake()),SIGNATURE)
        self.assertEqual(len(self.commands),2)
        self.assertTrue(all(not p.exists() for p in self.files))
    def test_wrong_key_never_signs(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9c",self.terminal,self.fake(wrong_key=True))
        self.assertEqual(len(self.commands),1)
    def test_failure_never_retries(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9c",self.terminal,self.fake(failure=True))
        self.assertEqual(len(self.commands),2)
        self.assertTrue(all(not p.exists() for p in self.files))
    def test_bad_signature_length(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9c",self.terminal,self.fake(short_signature=True))
    def test_explicit_device_required(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.sign(PUBLIC,MU,"/test/ykman","","9c",self.terminal,self.fake())
        self.assertEqual(len(self.commands),0)
    def test_wrong_slot_rejected(self):
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9a",self.terminal,self.fake())
        self.assertEqual(len(self.commands),0)
    def test_timeout_cleanup(self):
        def timeout(*args,**kwargs):raise subprocess.TimeoutExpired("ykman",15)
        with self.assertRaises(subprocess.TimeoutExpired):ADAPTER.sign(PUBLIC,MU,"/test/ykman","123456","9c",self.terminal,timeout)

if __name__ == "__main__":unittest.main()
