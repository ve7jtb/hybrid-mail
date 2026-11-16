import importlib.util
from pathlib import Path
import subprocess
import unittest
SPEC=importlib.util.spec_from_file_location('provision',Path(__file__).parents[1]/'scripts/provision-no-touch.py')
MODULE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MODULE)
class ProvisionGuardTest(unittest.TestCase):
    def test_only_explicit_empty_status_is_empty(self):
        empty='Error: Failed to get slot metadata: Connection error: APDU error: SW=0x6A88'
        self.assertIsNone(MODULE.slot_state(subprocess.CompletedProcess([],1,'',empty)))
        for message in ('no reader','PIN failed','APDU error: SW=0x6A88','Failed to get slot metadata: Connection error: APDU error: SW=0x6982'):
            with self.assertRaises(RuntimeError):MODULE.slot_state(subprocess.CompletedProcess([],1,'',message))
    def test_existing_slot_is_not_empty(self):
        self.assertEqual(MODULE.slot_state(subprocess.CompletedProcess([],0,'Algorithm: Rsa3072','')),'Algorithm: Rsa3072')
if __name__=='__main__':unittest.main()
