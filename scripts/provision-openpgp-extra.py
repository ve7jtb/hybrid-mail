#!/usr/bin/env python3
"""Add Ed25519/X25519 only to empty PIV 84/85; never replace keys."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
spec = importlib.util.spec_from_file_location('guards', Path(__file__).with_name('provision-no-touch.py'))
guards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guards)

def main():
    if len(sys.argv) != 2:
        raise RuntimeError('Usage: provision-openpgp-extra.py new-output-directory')
    serial = os.environ.get('PKCS11_SERIAL', '')
    exe = os.environ.get('YKMAN_BIN', '/usr/local/bin/ykman')
    if not serial.isdecimal() or not Path(exe).is_absolute():
        raise RuntimeError('Explicit serial and absolute ykman path required')
    prefix = [exe, '--device', serial, '--color', 'never', 'piv', 'keys']
    def info(slot):
        return guards.slot_state(subprocess.run(prefix + ['info', slot], capture_output=True, text=True, timeout=20))
    for slot, algorithm in [('9c', 'MlDsa65'), ('9d', 'MlKem768')]:
        state = info(slot)
        if state is None or 'Algorithm: ' + algorithm not in state:
            raise RuntimeError('Expected parameter set 2 key in ' + slot)
    for slot in ['84', '85']:
        if info(slot) is not None:
            raise RuntimeError('Slot ' + slot + ' is occupied; no changes made. Do not rerun after partial provisioning.')
    out = Path(sys.argv[1]).absolute()
    out.mkdir(mode=0o700)
    existing = ['9c', '9d', '82', '83']
    for slot in existing:
        subprocess.run(prefix + ['export', '--format', 'der', slot, str(out / ('before-' + slot + '.der'))], check=True)
    for slot, algorithm, metadata in [('84', 'ed25519', 'Ed25519'), ('85', 'x25519', 'X25519')]:
        if info(slot) is not None:
            raise RuntimeError('Slot became occupied: ' + slot)
        print('Creating ' + algorithm + ' in empty slot ' + slot + ': PIN always, touch never.', flush=True)
        subprocess.run(prefix + ['generate', '--algorithm', algorithm, '--pin-policy', 'always', '--touch-policy', 'never', '--format', 'der', slot, str(out / (slot + '-public.der'))], check=True)
        state = info(slot)
        if state is None or not all(x in state for x in ['Algorithm: ' + metadata, 'PIN policy: Always', 'Touch policy: Never']):
            raise RuntimeError('Unexpected generated key metadata in ' + slot)
        (out / (slot + '-metadata.txt')).write_text(state)
    for slot in existing:
        after = out / ('after-' + slot + '.der')
        subprocess.run(prefix + ['export', '--format', 'der', slot, str(after)], check=True)
        if after.read_bytes() != (out / ('before-' + slot + '.der')).read_bytes():
            raise RuntimeError('Existing public key changed: ' + slot)
    (out / 'result.txt').write_text('PASS: Ed25519 84, X25519 85; existing four public keys unchanged. No certificates or bundle written. OpenPGP RFC 9980 application integration remains separate.\n')
    print((out / 'result.txt').read_text())

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('Setup stopped: ' + str(error), file=sys.stderr)
        sys.exit(1)
