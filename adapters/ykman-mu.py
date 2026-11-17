#!/usr/bin/env python3
"""Beta0 ML-DSA-65 external-mu adapter. PIN entry belongs to ykman on /dev/tty.

Run the mail app from a terminal. No PIN arguments, environment variables, files
or retries. Requires explicit YKMAN_SERIAL; never selects the first device.
"""
import base64
import hmac
import os
from pathlib import Path
import subprocess
import sys
import tempfile


class AdapterError(Exception):
    pass


def read_request(stream):
    fields = []
    for _ in range(3):
        line = stream.readline(16385)
        if len(line) > 16384 or not line.endswith(b"\n"):
            raise AdapterError("Malformed adapter request")
        fields.append(line.strip())
    if fields[0] != b"ML-DSA-65":
        raise AdapterError("Only ML-DSA-65 is supported")
    try:
        spki = base64.b64decode(fields[1], validate=True)
        mu = base64.b64decode(fields[2], validate=True)
    except ValueError as error:
        raise AdapterError("Invalid base64 request") from error
    if len(mu) != 64 or not 1900 <= len(spki) <= 2100:
        raise AdapterError("Expected ML-DSA-65 SPKI and 64-byte mu")
    return spki, mu


def sign(spki, mu, executable, serial, slot, terminal, run=subprocess.run):
    if not serial.isdecimal() or slot.lower() != "9c":
        raise AdapterError("Set YKMAN_SERIAL and use signature slot 9c")
    prefix = [executable, "--device", serial, "--color", "never", "piv", "keys"]
    # Private directory prevents other local users from swapping the request/output.
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-mu-") as temporary:
        folder = Path(temporary)
        public_file, mu_file, signature_file = (folder / n for n in ("public.der", "mu.bin", "signature.bin"))
        exported = run(prefix + ["export", "--format", "der", slot, str(public_file)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=15)
        if exported.returncode:
            raise AdapterError("Cannot read slot public key; check device access and slot 9c")
        if public_file.stat().st_size > 4096 or not hmac.compare_digest(public_file.read_bytes(), spki):
            raise AdapterError("Slot 9c public key does not match this mail identity")
        mu_file.write_bytes(mu)
        terminal.write(b"\nPQ Mail: signing with ML-DSA-65 in slot 9c. Enter PIN if prompted, then touch the key.\n")
        terminal.flush()
        # stdin and stderr go only to the user's controlling terminal. Protocol
        # stdout stays clean, and ykman's native hidden PIN prompt handles secrets.
        signed = run(prefix + ["sign", "--mu", slot, str(mu_file), str(signature_file)],
                     stdin=terminal, stdout=subprocess.DEVNULL, stderr=terminal, timeout=100)
        if signed.returncode:
            raise AdapterError("YubiKey signing failed or was cancelled; no automatic retry")
        if signature_file.stat().st_size != 3309:
            raise AdapterError("Unexpected ML-DSA-65 signature length")
        return signature_file.read_bytes()


def main():
    terminal = None
    try:
        spki, mu = read_request(sys.stdin.buffer)
        executable = os.environ.get("YKMAN_BIN", "/usr/local/bin/ykman")
        serial = os.environ.get("YKMAN_SERIAL", "")
        slot = os.environ.get("YKMAN_SLOT", "9c")
        if not Path(executable).is_absolute():
            raise AdapterError("YKMAN_BIN must be an absolute path")
        try:
            terminal = open("/dev/tty", "r+b", buffering=0)
        except OSError as error:
            raise AdapterError("Launch PQ Mail from Terminal for the YubiKey PIN/touch prompts") from error
        result = sign(spki, mu, executable, serial, slot, terminal)
        sys.stdout.buffer.write(base64.b64encode(result) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (AdapterError, OSError, subprocess.SubprocessError) as error:
        # Never echo request bytes, subprocess stderr, or credentials.
        message = str(error) if isinstance(error, AdapterError) else "YubiKey adapter I/O failure or timeout"
        stream = terminal if terminal is not None else sys.stderr.buffer
        stream.write(("PQ Mail: " + message + "\n").encode())
        stream.flush()
        return 1
    finally:
        if terminal is not None:
            terminal.close()


if __name__ == "__main__":
    sys.exit(main())
