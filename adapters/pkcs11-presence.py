#!/usr/bin/env python3
"""Read-only PKCS#11 token enumeration. No sessions, login or private operations."""
import ctypes as C
import os
from pathlib import Path
import sys

U=C.c_ulong
class Version(C.Structure):
    _fields_=[('major',C.c_ubyte),('minor',C.c_ubyte)]
class TokenInfo(C.Structure):
    _fields_=[('label',C.c_char*32),('manufacturer',C.c_char*32),('model',C.c_char*16),('serial',C.c_char*16)]+[(name,U) for name in ('flags','max_sessions','sessions','max_rw_sessions','rw_sessions','max_pin','min_pin','total_public','free_public','total_private','free_private')]+[('hardware',Version),('firmware',Version),('utc',C.c_char*16)]

def present(module,serial):
    def checked(code):
        if code:raise RuntimeError('PKCS#11 enumeration failed')
    checked(module.C_Initialize(None))
    try:
        count=U();checked(module.C_GetSlotList(1,None,C.byref(count)))
        if count.value>256:raise RuntimeError('Invalid token count')
        if count.value==0:return False
        slots=(U*count.value)();checked(module.C_GetSlotList(1,slots,C.byref(count)))
        for slot in slots[:count.value]:
            info=TokenInfo();result=module.C_GetTokenInfo(slot,C.byref(info))
            if result in (0xE0,0xE1):continue  # device removed during enumeration
            checked(result)
            if bytes(info.serial).decode('ascii').strip(' \x00')==serial:return True
        return False
    finally:module.C_Finalize(None)

def main():
    try:
        path=os.environ.get('PKCS11_MODULE','');serial=os.environ.get('PKCS11_SERIAL','')
        if not Path(path).is_absolute() or not serial.isdecimal():raise ValueError('Invalid token configuration')
        module=C.CDLL(path)
        module.C_Initialize.argtypes=[C.c_void_p];module.C_Initialize.restype=U
        module.C_Finalize.argtypes=[C.c_void_p];module.C_Finalize.restype=U
        module.C_GetSlotList.argtypes=[C.c_ubyte,C.POINTER(U),C.POINTER(U)];module.C_GetSlotList.restype=U
        module.C_GetTokenInfo.argtypes=[U,C.POINTER(TokenInfo)];module.C_GetTokenInfo.restype=U
        return 0 if present(module,serial) else 2
    except Exception:
        print('Cannot check YubiKey presence; check the configured PKCS#11 module and serial.',file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
