import ctypes as C
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('presence',Path(__file__).parents[1]/'adapters/pkcs11-presence.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class Module:
    def __init__(self,serials,fail=False):self.serials=serials;self.finalized=False;self.fail=fail
    def C_Initialize(self,args):return 0
    def C_Finalize(self,args):self.finalized=True;return 0
    def C_GetSlotList(self,present,slots,count):
        assert present==1
        if self.fail:return 5
        C.cast(count,C.POINTER(p.U))[0]=len(self.serials)
        if slots is not None:
            for i in range(len(self.serials)):slots[i]=i
        return 0
    def C_GetTokenInfo(self,slot,info):C.cast(info,C.POINTER(p.TokenInfo))[0].serial=self.serials[slot].encode().ljust(16,b' ');return 0
class Tests(unittest.TestCase):
    def test_presence(self):
        for serials,expected in [([],False),(['12345'],True),(['99999'],False),(['99999','12345'],True)]:
            module=Module(serials);self.assertEqual(p.present(module,'12345'),expected);self.assertTrue(module.finalized)
    def test_module_error(self):
        module=Module([],True)
        with self.assertRaises(RuntimeError):p.present(module,'12345')
        self.assertTrue(module.finalized)
