#!/usr/bin/env python3
"""OpenSSL pkcs11-provider PR #818 -> Yubico PKCS#11 external-mu signing.

No PIN in arguments, environment, files or protocol. OpenSSL prompts on /dev/tty.
Requires OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL.
"""
import base64
import hmac
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

# Share only the wire protocol; no ykman command or fallback is used.
_spec = importlib.util.spec_from_file_location("mu_protocol", Path(__file__).with_name("ykman-mu.py"))
_protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_protocol)
AdapterError = _protocol.AdapterError
read_request = _protocol.read_request


def config_path(value):
    if not Path(value).is_absolute() or any(c in value for c in '\r\n"$\\'):
        raise AdapterError("Provider/module paths must be absolute and contain no config metacharacters")
    return '"' + value + '"'


def configuration(provider, module):
    return ("openssl_conf = init\nconfig_diagnostics = 1\n"
            "[init]\nproviders = providers\n"
            "[providers]\ndefault = default_provider\npkcs11 = token_provider\n"
            "[default_provider]\nactivate = 1\n"
            "[token_provider]\nmodule = " + config_path(provider) + "\n"
            "pkcs11-module-path = " + config_path(module) + "\n"
            # Cache only inside this short-lived OpenSSL invocation, for an
            # ALWAYS_AUTHENTICATE key's context-specific login after user login.
            "pkcs11-module-cache-pins = cache\nactivate = 1\n")


def sign(spki, mu, executable, provider, module, serial, terminal, run=subprocess.run):
    if not serial.isdecimal():
        raise AdapterError("Set PKCS11_SERIAL to the intended token serial")
    if not Path(executable).is_absolute():
        raise AdapterError("OPENSSL_BIN must be an absolute path")
    config = configuration(provider, module)
    # The Yubico module maps PIV signature slot 9c to binary CKA_ID 02.
    uri = "pkcs11:serial=" + serial + ";id=%02;type="
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-pkcs11-") as temporary:
        folder = Path(temporary)
        config_file, public_file, mu_file, sig_file = (folder / n for n in ("openssl.cnf", "public.der", "mu.bin", "signature.bin"))
        config_file.write_text(config, encoding="utf-8")
        env = os.environ.copy()
        for name in list(env):
            if name.startswith("PKCS11_PROVIDER_") or name in ("OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES"):
                del env[name]
        env["OPENSSL_CONF"] = str(config_file)
        common = dict(stdin=terminal, stderr=terminal, stdout=subprocess.DEVNULL, env=env)
        exported = run([executable,"pkey","-provider","default","-provider","pkcs11",
                        "-pubin","-in",uri+"public","-pubout","-outform","DER","-out",str(public_file)],
                       timeout=30, **common)
        if exported.returncode:
            raise AdapterError("Cannot export PKCS#11 public key; check module, serial and slot 9c")
        if public_file.stat().st_size > 4096 or not hmac.compare_digest(public_file.read_bytes(),spki):
            raise AdapterError("PKCS#11 slot 9c public key does not match this identity")
        mu_file.write_bytes(mu)
        terminal.write(b"\nHybrid Mail: PKCS#11 external-mu signing. Enter PIN at OpenSSL's prompt and touch the key.\n")
        terminal.flush()
        signed = run([executable,"pkeyutl","-provider","default","-provider","pkcs11",
                      "-sign","-pkeyopt","mu:1","-inkey",uri+"private",
                      "-in",str(mu_file),"-out",str(sig_file)],timeout=100,**common)
        if signed.returncode:
            raise AdapterError("PKCS#11 signing failed or was cancelled; no retry or ykman fallback")
        if sig_file.stat().st_size != 3309:
            raise AdapterError("Unexpected ML-DSA-65 signature length")
        return sig_file.read_bytes()


def main():
    terminal = None
    try:
        spki,mu=read_request(sys.stdin.buffer)
        values=[os.environ.get(n,"") for n in ("OPENSSL_BIN","PKCS11_PROVIDER","PKCS11_MODULE","PKCS11_SERIAL")]
        if not all(values):
            raise AdapterError("Set OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL")
        try:
            terminal=open("/dev/tty","r+b",buffering=0)
        except OSError as error:
            raise AdapterError("Launch from Terminal for OpenSSL's PIN/touch prompts") from error
        result=sign(spki,mu,*values,terminal)
        sys.stdout.buffer.write(base64.b64encode(result)+b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (AdapterError,OSError,subprocess.SubprocessError) as error:
        message=str(error) if isinstance(error,AdapterError) else "PKCS#11 adapter I/O failure or timeout"
        stream=terminal if terminal is not None else sys.stderr.buffer
        stream.write(("Hybrid Mail: "+message+"\n").encode());stream.flush()
        return 1
    finally:
        if terminal is not None:terminal.close()


if __name__=="__main__":sys.exit(main())
