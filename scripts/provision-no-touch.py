#!/usr/bin/env python3
"""Explicit provisioning: replace 9c; create RSA-3072 in empty 9a. Never reset PIV."""
import os
from pathlib import Path
import subprocess
import sys


def slot_state(result):
    text=(result.stdout+result.stderr).strip()
    if result.returncode==0:
        return text
    if text.endswith("Failed to get slot metadata: Connection error: APDU error: SW=0x6A88"):
        return None
    raise RuntimeError("Cannot establish slot state; no key replacement attempted: "+text)


def main():
    if len(sys.argv)!=2:raise RuntimeError("Usage: provision-no-touch.py new-public-backup-directory")
    serial=os.environ.get("PKCS11_SERIAL","")
    executable=os.environ.get("YKMAN_BIN","/usr/local/bin/ykman")
    if not serial.isdecimal() or not Path(executable).is_absolute():raise RuntimeError("Set explicit token serial and absolute ykman path")
    prefix=[executable,"--device",serial,"--color","never","piv","keys"]
    def info(slot):return subprocess.run(prefix+["info",slot],text=True,capture_output=True,timeout=20)
    state9a=slot_state(info("9a"))
    if state9a is not None and not all(value in state9a for value in ("Algorithm: Rsa3072","PIN policy: Always","Touch policy: Never")):
        raise RuntimeError("Slot 9a is occupied by a different key/policy; refusing to overwrite it.\n"+state9a)
    state9c=slot_state(info("9c"))
    if state9c is None or "Algorithm: MlDsa65" not in state9c:
        raise RuntimeError("Expected existing ML-DSA-65 in 9c; stopping before changes.\n"+str(state9c))
    out=Path(sys.argv[1]).absolute();out.mkdir(mode=0o700)
    (out/"before-9c.txt").write_text(state9c+"\n")
    subprocess.run(prefix+["export","--format","der","9c",str(out/"old-9c-public.der")],check=True)
    if state9a is None:
        print("Generating authorized RSA-3072 key in empty slot 9a (PIN always, touch never).",flush=True)
        subprocess.run(prefix+["generate","--algorithm","rsa3072","--pin-policy","always","--touch-policy","never","--format","der","9a",str(out/"rsa3072-public.der")],check=True)
    print("Replacing authorized ML-DSA-65 key in 9c (PIN always, touch never). Existing private key will be removed.",flush=True)
    subprocess.run(prefix+["generate","--algorithm","ml-dsa65","--pin-policy","always","--touch-policy","never","--format","der","9c",str(out/"mldsa65-public.der")],check=True)
    for slot in ("9a","9c"):
        after=slot_state(info(slot))
        if after is None or "PIN policy: Always" not in after or "Touch policy: Never" not in after:
            raise RuntimeError("Post-provision metadata verification failed for "+slot)
        (out/("after-"+slot+".txt")).write_text(after+"\n")
        print(after)
    (out/"result.txt").write_text("SUCCESS: RSA-3072 9a and ML-DSA-65 9c; PIN always, touch never.\n")
    print("Provisioning complete. Existing certificate identities must be replaced with new local demo certificates.")

if __name__=="__main__":
    try:main()
    except (RuntimeError,OSError,subprocess.SubprocessError) as error:
        print("Setup stopped: "+str(error),file=sys.stderr);sys.exit(1)
