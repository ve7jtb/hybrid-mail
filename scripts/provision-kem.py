#!/usr/bin/env python3
"""Generate only absent encryption keys in 9d / 82; never overwrite existing keys."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
_spec=importlib.util.spec_from_file_location('guards',Path(__file__).with_name('provision-no-touch.py'))
_guards=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_guards)


def main():
    if len(sys.argv)!=2:raise RuntimeError('Usage: provision-kem.py new-public-metadata-directory')
    serial=os.environ.get('PKCS11_SERIAL','');executable=os.environ.get('YKMAN_BIN','/usr/local/bin/ykman')
    if not serial.isdecimal() or not Path(executable).is_absolute():raise RuntimeError('Set explicit token serial and absolute ykman path')
    prefix=[executable,'--device',serial,'--color','never','piv','keys']
    def info(slot):return _guards.slot_state(subprocess.run(prefix+['info',slot],capture_output=True,text=True,timeout=20))
    wanted=[('9d','ml-kem768','MlKem768'),('82','eccp256','EccP256')]
    states={slot:info(slot) for slot,_,_ in wanted}
    for slot,_,algorithm in wanted:
        state=states[slot]
        if state is not None and not all(value in state for value in ('Algorithm: '+algorithm,'PIN policy: Always','Touch policy: Never')):
            raise RuntimeError('Slot '+slot+' is occupied by another key/policy; refusing any changes.\n'+state)
    out=Path(sys.argv[1]).absolute();out.mkdir(mode=0o700)
    for slot,algorithm,expected in wanted:
        if states[slot] is None:
            print('Generating '+algorithm+' in empty slot '+slot+' (PIN always, touch never).',flush=True)
            subprocess.run(prefix+['generate','--algorithm',algorithm,'--pin-policy','always','--touch-policy','never','--format','der',slot,str(out/(slot+'-public.der'))],check=True)
        state=info(slot)
        if state is None or not all(value in state for value in ('Algorithm: '+expected,'PIN policy: Always','Touch policy: Never')):
            raise RuntimeError('Encryption key metadata check failed for '+slot)
        (out/(slot+'-metadata.txt')).write_text(state+'\n');print(state)
    (out/'result.txt').write_text('SUCCESS: encryption keys ready: ML-KEM-768 9d, ECDH P-256 82, PIN always / touch never. Signing slots unchanged.\n')

if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,subprocess.SubprocessError) as error:
        print('KEM setup stopped: '+str(error),file=sys.stderr);sys.exit(1)
