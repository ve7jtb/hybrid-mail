"""Portable parsing tests. Never invoke WebAuthn or a real passkey."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WindowsPasskeyProtocol(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang++') or shutil.which('g++')
        if compiler is None:
            raise unittest.SkipTest('C++ compiler unavailable; Windows CI also runs the MSVC helper self-test')
        cls.temp = tempfile.TemporaryDirectory(prefix='pqmail-passkey-test-')
        cls.helper = pathlib.Path(cls.temp.name) / 'passkey-protocol'
        subprocess.run([compiler, '-std=c++17', str(ROOT / 'native-src/passkey-win.cpp'), '-o', str(cls.helper)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_protocol_self_test(self):
        result = subprocess.run([str(self.helper), '--self-test'], capture_output=True, check=True, timeout=10)
        self.assertIn(b'no authenticator accessed', result.stdout)

    def test_bad_requests_fail_before_api_access(self):
        for request in [b'', b'{}', b'PQPRF001', b'x' * 4097]:
            result = subprocess.run([str(self.helper)], input=request, capture_output=True, timeout=5)
            self.assertEqual(1, result.returncode)
            self.assertIn(b'vault remains locked', result.stdout)

    def test_no_extra_cli_arguments(self):
        result = subprocess.run([str(self.helper), 'secret-must-not-be-an-argument'], capture_output=True, timeout=5)
        self.assertEqual(1, result.returncode)
        self.assertNotIn(b'secret-must-not-be-an-argument', result.stdout + result.stderr)
