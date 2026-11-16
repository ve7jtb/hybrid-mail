#!/usr/bin/env python3
"""OpenSSL pkcs11-provider PR #818 -> Yubico PKCS#11 external-mu signing.

PIN uses an anonymous pipe from the app to OpenSSL; never args/env/files.
Terminal callers can use the provider native PIN prompt.
Requires OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL.
"""
import base64
import hmac
import io
import importlib.util
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

# Share only the wire protocol; no ykman command or fallback is used.
_spec = importlib.util.spec_from_file_location("mu_protocol", Path(__file__).with_name("ykman-mu.py"))
_protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_protocol)
AdapterError = _protocol.AdapterError
def read_request(stream):
    algorithm = stream.readline(16385)
    if algorithm == b"ML-DSA-65\n":
        # Reuse the bounded existing parser without reading unbounded stdin.
        rest = stream.readline(16385) + stream.readline(16385)
        spki, payload = _protocol.read_request(io.BytesIO(algorithm + rest))
        return "ML-DSA-65", spki, payload
    if algorithm not in (b"ECDSA-P256-SHA256\n",b"RSA3072-PSS-SHA256\n"):
        raise AdapterError("Unsupported signing algorithm")
    fields = [stream.readline(16385) for _ in range(2)]
    if any(len(line)>16384 or not line.endswith(b"\n") for line in fields):
        raise AdapterError("Malformed ECDSA request")
    try:
        spki, payload = [base64.b64decode(line.strip(),validate=True) for line in fields]
    except ValueError as error:
        raise AdapterError("Invalid base64 request") from error
    spki_ok = 80<=len(spki)<=150 if algorithm.startswith(b"ECDSA") else 390<=len(spki)<=500
    if len(payload)!=32 or not spki_ok:
        raise AdapterError("Expected conventional SPKI and 32-byte SHA-256 digest")
    return algorithm.decode().strip(), spki, payload


def ec_object_id(slot):
    # Yubico PIV mapping: 9a=1, 9c=2, 9d=3, 9e=4; retired 82..95=5..24.
    slots = {"9a":1,"9d":3,"9e":4}
    slots.update({format(n,"02x"):n-0x82+5 for n in range(0x82,0x96)})
    if slot.lower() not in slots:
        raise AdapterError("Set PKCS11_TRADITIONAL_SLOT to the existing conventional slot; 9c is reserved for ML-DSA")
    return "%" + format(slots[slot.lower()],"02X")


def config_path(value):
    if not Path(value).is_absolute() or any(c in value for c in '\r\n"$\\'):
        raise AdapterError("Provider/module paths must be absolute and contain no config metacharacters")
    return '"' + value + '"'


def configuration(provider, module, public=False):
    return ("openssl_conf = init\nconfig_diagnostics = 1\n"
            "[init]\nproviders = providers\n"
            "[providers]\ndefault = default_provider\npkcs11 = token_provider\n"
            "[default_provider]\nactivate = 1\n"
            "[token_provider]\nmodule = " + config_path(provider) + "\n"
            "pkcs11-module-path = " + config_path(module) + "\n"
            # Cache only inside this short-lived OpenSSL invocation, for an
            # ALWAYS_AUTHENTICATE key's context-specific login after user login.
            "pkcs11-module-cache-pins = cache\nactivate = 1\n" + ("pkcs11-module-login-behavior = never\n" if public else ""))


def child_environment(config_file):
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("PKCS11_PROVIDER_") or name in ("OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES"):
            del env[name]
    env["OPENSSL_CONF"] = str(config_file)
    return env


def export_traditional(executable, provider, module, serial, slot, terminal, ml=False):
    if not serial.isdecimal() or not Path(executable).is_absolute():
        raise AdapterError("Set explicit token serial and absolute OpenSSL path")
    uri="pkcs11:serial="+serial+";id="+("%02" if ml else ec_object_id(slot))+";type=public"
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-ec-public-") as temporary:
        folder=Path(temporary);config=folder/"openssl.cnf";public=folder/"public.der"
        config.write_text(configuration(provider,module,public=True),encoding="utf-8")
        result=subprocess.run([executable,"pkey","-provider","default","-provider","pkcs11",
                               "-pubin","-in",uri,"-pubout","-outform","DER","-out",str(public)],
                              stdin=terminal,stderr=terminal,stdout=subprocess.DEVNULL,env=child_environment(config),timeout=30)
        if result.returncode or not public.exists() or not (1900<=public.stat().st_size<=2100 if ml else 80<=public.stat().st_size<=500):
            raise AdapterError("Cannot export conventional public key from configured slot")
        return public.read_bytes()


def public_keys_match(expected, actual_file, algorithm, executable, folder, env, run):
    actual=actual_file.read_bytes()
    if hmac.compare_digest(expected,actual):return True
    if algorithm!="RSA3072-PSS-SHA256":return False
    # Composite key decoding may omit rsaEncryption's NULL parameters. Compare
    # canonical PKCS#1 RSAPublicKey (modulus and exponent), not SPKI wrappers.
    expected_file=folder/"expected-public.der";expected_file.write_bytes(expected)
    canonical=[]
    for index,source in enumerate((expected_file,actual_file)):
        target=folder/("rsa-canonical-"+str(index)+".der")
        result=run([executable,"rsa","-provider","default","-pubin","-inform","DER","-in",str(source),
                    "-RSAPublicKey_out","-outform","DER","-out",str(target)],
                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,timeout=10)
        if result.returncode or not target.exists() or not 390<=target.stat().st_size<=410:
            raise AdapterError("Cannot canonicalize RSA-3072 public key")
        canonical.append(target.read_bytes())
    return hmac.compare_digest(*canonical)


def safe_openssl_error(result):
    # Only OpenSSL error identifiers and reason fields; never input values or debug dumps.
    raw=getattr(result,"stderr",None)
    if not isinstance(raw,bytes):return ""
    matches=re.findall(rb"error:[0-9A-Fa-f]+:[^:\r\n]+:[^:\r\n]*:[^:\r\n]+",raw)
    return "; "+b"; ".join(matches[:3]).decode("ascii",errors="replace")[:600] if matches else ""


def sign(spki, mu, executable, provider, module, serial, terminal, run=subprocess.run, algorithm="ML-DSA-65", ec_slot="", pin=None):
    if not serial.isdecimal():
        raise AdapterError("Set PKCS11_SERIAL to the intended token serial")
    if not Path(executable).is_absolute():
        raise AdapterError("OPENSSL_BIN must be an absolute path")
    config = configuration(provider, module)
    # The Yubico module maps PIV signature slot 9c to binary CKA_ID 02.
    if algorithm not in ("ML-DSA-65", "ECDSA-P256-SHA256", "RSA3072-PSS-SHA256"):
        raise AdapterError("Unsupported signing algorithm")
    object_id = "%02" if algorithm == "ML-DSA-65" else ec_object_id(ec_slot)
    uri = "pkcs11:serial=" + serial + ";id=" + object_id + ";type="
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-pkcs11-") as temporary:
        folder = Path(temporary)
        config_file, public_file, mu_file, sig_file = (folder / n for n in ("openssl.cnf", "public.der", "mu.bin", "signature.bin"))
        config_file.write_text(configuration(provider,module,public=True), encoding="utf-8")
        env = child_environment(config_file)
        common = dict(stdin=terminal, stderr=subprocess.PIPE if pin is not None else terminal, stdout=subprocess.DEVNULL, env=env)
        exported = run([executable,"pkey","-provider","default","-provider","pkcs11",
                        "-pubin","-in",uri+"public","-pubout","-outform","DER","-out",str(public_file)],
                       timeout=30, **common)
        if exported.returncode:
            raise AdapterError("Cannot export PKCS#11 public key; check module, serial and selected slot"+safe_openssl_error(exported))
        if public_file.stat().st_size > 4096 or not public_keys_match(spki,public_file,algorithm,executable,folder,env,run):
            raise AdapterError("PKCS#11 selected slot public key does not match this identity")
        config_file.write_text(config,encoding="utf-8")
        mu_file.write_bytes(mu)
        terminal.write(("\nHybrid Mail: PKCS#11 " + algorithm + " signing. Enter PIN and touch the key.\n").encode())
        terminal.flush()
        options = ["-pkeyopt","mu:1"] if algorithm == "ML-DSA-65" else ["-pkeyopt","digest:sha256"]
        if algorithm == "RSA3072-PSS-SHA256":
            options += ["-pkeyopt","rsa_padding_mode:pss","-pkeyopt","rsa_pss_saltlen:32","-pkeyopt","rsa_mgf1_md:sha256"]
        command = [executable,"pkeyutl","-provider","default","-provider","pkcs11",
                      "-sign"] + options + ["-inkey",uri+"private",
                      "-in",str(mu_file),"-out",str(sig_file)]
        if pin is None:
            signed=run(command,timeout=100,**common)
        else:
            if not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):
                raise AdapterError("Invalid PIN input format")
            read_fd,write_fd=os.pipe()
            try:
                os.write(write_fd,pin);os.write(write_fd,b"\n")
                os.close(write_fd);write_fd=-1
                env["HYBRID_MAIL_PIN_STDIN"]="1"
                signed=run(command+["-passin","fd:"+str(read_fd)],pass_fds=(read_fd,),timeout=100,**common)
            finally:
                os.close(read_fd)
                if write_fd!=-1:os.close(write_fd)
                pin[:]=b"\0"*len(pin)
        if signed.returncode:
            raise AdapterError("PKCS#11 "+algorithm+" signing failed; no retry"+safe_openssl_error(signed))
        size = sig_file.stat().st_size
        if (algorithm == "ML-DSA-65" and size != 3309) or (algorithm == "ECDSA-P256-SHA256" and not 8 <= size <= 72) or (algorithm=="RSA3072-PSS-SHA256" and size!=384):
            raise AdapterError("Unexpected signature length")
        return sig_file.read_bytes()


def main():
    terminal = None
    pin = None
    try:
        values=[os.environ.get(n,"") for n in ("OPENSSL_BIN","PKCS11_PROVIDER","PKCS11_MODULE","PKCS11_SERIAL")]
        if not all(values):
            raise AdapterError("Set OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL")
        try:
            terminal=open(os.devnull if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1" else "/dev/tty","r+b",buffering=0)
        except OSError as error:
            raise AdapterError("Launch from Terminal for OpenSSL's PIN/touch prompts") from error
        if sys.argv[1:] in (["--export-traditional"],["--export-ml"]):
            sys.stdout.buffer.write(export_traditional(*values,os.environ.get("PKCS11_TRADITIONAL_SLOT",""),terminal,ml=sys.argv[1]=="--export-ml"))
            return 0
        if len(sys.argv)!=1:
            raise AdapterError("Unsupported adapter arguments")
        algorithm,spki,mu=read_request(sys.stdin.buffer)
        if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1":
            pin=bytearray(sys.stdin.buffer.readline(10))
            if not pin.endswith(b"\n"):
                raise AdapterError("Missing app PIN input")
            del pin[-1:]
        result=sign(spki,mu,*values,terminal,algorithm=algorithm,ec_slot=os.environ.get("PKCS11_TRADITIONAL_SLOT",""),pin=pin)
        sys.stdout.buffer.write(base64.b64encode(result)+b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (AdapterError,OSError,subprocess.SubprocessError) as error:
        message=str(error) if isinstance(error,AdapterError) else "PKCS#11 adapter I/O failure or timeout"
        stream=sys.stderr.buffer if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1" else (terminal if terminal is not None else sys.stderr.buffer)
        stream.write(("Hybrid Mail: "+message+"\n").encode());stream.flush()
        return 1
    finally:
        if pin is not None:pin[:]=b"\0"*len(pin)
        if terminal is not None:terminal.close()


if __name__=="__main__":sys.exit(main())
