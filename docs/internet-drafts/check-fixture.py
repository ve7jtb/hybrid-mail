#!/usr/bin/env python3
"""Validate public base-format framing vectors; NOT a signature verifier.

No network, card access, credentials, or private keys are used. Cryptographic
verification of these vectors is covered separately by the Sequoia adapter.
"""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zlib

MAX = 65536


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Reader:
    """Length-check every read before slicing attacker-controlled input."""
    def __init__(self, data):
        require(len(data) <= MAX, 'input limit')
        self.data, self.at = data, 0

    def take(self, size):
        require(0 <= size <= len(self.data) - self.at, 'truncated field')
        out = self.data[self.at:self.at + size]
        self.at += size
        return out

    def u32(self):
        return int.from_bytes(self.take(4), 'big')

    def blob(self):
        return self.take(self.u32())

    def end(self):
        require(self.at == len(self.data), 'trailing data')


def unpack(packed):
    """Bound output before expansion; reject dictionaries/members/trailers."""
    r = Reader(packed)
    require(r.take(8) == b'PQMZIP01', 'compression magic')
    size = r.u32()
    require(0 < size <= MAX, 'expanded length')
    dec = zlib.decompressobj()
    raw = dec.decompress(r.take(len(packed) - 12), size + 1)
    require(len(raw) == size and dec.eof and not dec.unused_data
            and not dec.unconsumed_tail, 'zlib boundary')
    return raw


def envelope(packed):
    """Inspect exact B2 fields, without claiming certificate validation."""
    raw = unpack(packed)
    r = Reader(raw)
    require(r.take(8) == b'PQMAILS1', 'envelope magic')
    payload, signer, signature = r.blob(), r.u32(), r.blob()
    r.end()
    require(signature, 'empty signature')
    p = Reader(payload)
    require(p.take(8) == b'PQMAILB2', 'payload magic')
    count = p.u32()
    require(2 <= count <= 16 and signer < count, 'profile count/signer')
    profiles = []
    for _ in range(count):
        serial, slots = p.u32(), p.take(4)
        certs = [p.blob() for _ in range(4)]
        require(serial == 123456 and slots == bytes.fromhex('9c839d82'), 'fixture mapping')
        require(certs[0] and certs[1], 'missing X.509 certificate')
        profiles.append([len(c) for c in certs])
    p.end()
    return {'compressed': len(packed), 'expanded': len(raw),
            'signer': signer, 'profileFieldLengths': profiles,
            'sha256': hashlib.sha256(packed).hexdigest()}


def frame(packed, generation=1):
    """Construct the single bank from an already signed compressed fixture."""
    manifest = b'PQMIDX01' + struct.pack('>QI', generation, len(packed)) + hashlib.sha256(packed).digest()
    chunks = [b'PQMCHK01' + struct.pack('>QI', generation, i) + packed[start:start+2048]
              for i, start in enumerate(range(0, len(packed), 2048))]
    return manifest, chunks


def unframe(manifest, chunks):
    require(len(manifest) == 52 and manifest[:8] == b'PQMIDX01', 'manifest')
    gen, size = struct.unpack('>QI', manifest[8:20])
    require(0 < gen < 2**63 and 0 < size <= MAX, 'manifest bounds')
    require(len(chunks) == (size+2047)//2048, 'chunk count')
    raw = bytearray()
    for i, c in enumerate(chunks):
        require(c[:8] == b'PQMCHK01' and len(c) == 20+min(2048, size-i*2048), 'chunk size')
        require(struct.unpack('>QI', c[8:20]) == (gen, i), 'chunk generation/index')
        raw.extend(c[20:])
    require(hashlib.sha256(raw).digest() == manifest[20:], 'manifest digest')
    return bytes(raw)


def rejected(action):
    try:
        action()
    except (ValueError, zlib.error):
        return
    raise AssertionError('invalid framing was accepted')


def main():
    source = json.loads(Path(__file__).with_name('fixture-level3-public.json').read_text())
    require(set(source) == {'serial', 'fingerprint', 'keys', 'pure', 'hybrid'}, 'unexpected fixture fields')
    report = {}
    for name in ('pure', 'hybrid'):
        packed = base64.b64decode(source[name], validate=True)
        report[name] = envelope(packed)
        manifest, chunks = frame(packed)
        require(unframe(manifest, chunks) == packed, 'bank round trip')
        report[name]['manifestHex'] = manifest.hex()
        report[name]['chunks'] = len(chunks)
        rejected(lambda: unpack(packed[:-1]))
        rejected(lambda: unpack(packed+b'trailing'))
        rejected(lambda: unpack(packed[:8]+struct.pack('>I', MAX+1)+packed[12:]))
        rejected(lambda: unframe(manifest, chunks[:-1]))
        bad = chunks.copy()
        bad[0] = bad[0][:16]+struct.pack('>I', 1)+bad[0][20:]
        rejected(lambda: unframe(manifest, bad))
        rejected(lambda: unframe(manifest[:-1]+bytes([manifest[-1]^1]), chunks))
    print(json.dumps(report, indent=2))
    print('PASS framing and negative checks; signature verification is a separate requirement.')


if __name__ == '__main__':
    main()
