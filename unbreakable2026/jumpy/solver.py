from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

BASE = 0x400000
CHALL = Path('/home/cht2308/unbreakable/jumpy/chall').read_bytes()
ENC = Path('/home/cht2308/unbreakable/jumpy/enc.sky').read_bytes()

RO_3060 = bytes.fromhex('f0ebe7f797939f9fe2d7c4dceccbd1c0d7c9c0c4d3c0f6c7cadd9f9fd394')
RO_3080 = bytes.fromhex('5ac311807701f0339c4d6610a07f0255')
RO_3090 = bytes.fromhex('49f4d15e51ab4bff42e0d8ffe25b1bcc')

ADDRS = [
    0x401FD3, 0x402089, 0x4020DE, 0x402123, 0x40218A, 0x4021F7, 0x402215,
    0x40228E, 0x4022E1, 0x4023F0, 0x402493, 0x40254D, 0x402648, 0x4026B3,
    0x40274B,
]
ORDER = [2, 4, 5, 0, 1, 3, 6, 7, 10, 8, 9, 12, 11, 13]


def rol32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def derive_initial_sha() -> bytes:
    seed_a = bytes(b ^ 0xA5 for b in RO_3060)
    seed_b = bytes(a ^ b for a, b in zip(RO_3080, RO_3090))
    return hashlib.sha256(seed_a + seed_b).digest()


def build_state(digest: bytes) -> list[int]:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + digest[i % 32]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def block_sizes() -> list[int]:
    return [ADDRS[i + 1] - ADDRS[i] for i in range(len(ADDRS) - 1)]


def mutate_block(idx: int, data: bytes) -> bytes:
    out = bytearray(data)
    for pos in range(len(out)):
        key = (((idx * 9) * 4 + idx) + (((pos * 2) + pos) * 4 + pos)) ^ 0xCB
        out[pos] ^= key & 0xFF
    return bytes(out)


def collect_mutated_blocks() -> list[bytes]:
    sizes = block_sizes()
    blocks = []
    for idx, addr in enumerate(ADDRS[:-1]):
        off = addr - BASE
        raw = CHALL[off:off + sizes[idx]]
        blocks.append(mutate_block(idx, raw))
    return blocks


def mix_hashes(blocks: list[bytes]) -> tuple[list[int], int]:
    vals = []
    acc = fnv1a32(RO_3060) ^ 0x9E3779B9
    for block_index in ORDER:
        h = fnv1a32(blocks[block_index])
        acc = rol32(acc, 7) ^ h ^ 0x9E3779B9
        vals.append(acc)
    return vals, acc


def keystream_from_state(state: list[int], n: int) -> bytes:
    i = 0
    j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def main() -> None:
    digest = derive_initial_sha()
    state = build_state(digest)
    blocks = collect_mutated_blocks()
    vals, acc = mix_hashes(blocks)

    print('initial_sha =', digest.hex())
    print('block_sizes =', block_sizes())
    print('mutated_first_bytes =', [b[:8].hex() for b in blocks])
    print('mix_vals =', [hex(v) for v in vals])
    print('final_mix =', hex(acc))

    ks = keystream_from_state(state[:], len(ENC))
    dec = bytes(a ^ b for a, b in zip(ENC, ks))
    print('rc4_guess_hex =', dec.hex())
    print('rc4_guess_ascii =', ''.join(chr(c) if 32 <= c < 127 else '.' for c in dec))

    for name, material in [('sha_only', digest), ('sha_plus_mix', digest + acc.to_bytes(4, 'little'))]:
        mask = hashlib.sha256(material).digest()
        out = bytes(ENC[i] ^ mask[i % len(mask)] for i in range(len(ENC)))
        print(name, out.hex())
        print(name, ''.join(chr(c) if 32 <= c < 127 else '.' for c in out))

    tbl_2b0 = list(hashlib.sha256(bytes(range(0x26))).digest())
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + digest[i % len(digest)]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i

    def f8(cur_byte: int, idx: int, phase: int) -> tuple[int, int]:
        t = (29 * idx + 17 * phase) & 0xFF
        out = (cur_byte ^ t) + (((cur_byte & t) << 1) & 0xFF)
        return out & 0xFF, 3 if phase else 2

    def f9(cur_byte: int, phase: int) -> tuple[int, int, int]:
        out = cur_byte ^ (cur_byte >> 1)
        if phase:
            return out & 0xFF, 0, 3
        return out & 0xFF, 1, 2

    def f10(cur_byte: int, idx: int, phase: int) -> tuple[int, int]:
        out = cur_byte ^ tbl_2b0[idx & 31]
        return out & 0xFF, 1

    def f11(cur_byte: int, idx: int, phase: int) -> tuple[int, int, int]:
        r = (tbl_2b0[idx & 31] + 8) & 7
        out = ((cur_byte << r) | (cur_byte >> ((-r) & 7))) & 0xFF
        if phase:
            return out, 3, 4
        return out, 1, 2

    def f12(cur_byte: int) -> tuple[int, int]:
        return sbox[cur_byte], 4

    def f13(cur_byte: int, state: int) -> tuple[int, int]:
        state = ((state ^ ((cur_byte | 0xA5) + 0x77)) << 8 | ((state ^ ((cur_byte | 0xA5) + 0x77)) >> 24)) & 0xFFFFFFFF
        return state, 1

    sample = list(ENC[:38])
    print('sample_input_hex =', bytes(sample).hex())
    state = 0
    transformed = []
    for idx, b in enumerate(sample):
        phase = 0
        cur = b
        cur, next_phase = f10(cur, idx, phase)
        phase = next_phase
        cur, phase, _ = f11(cur, idx, phase)
        cur, phase, _ = f9(cur, phase)
        cur, phase = f8(cur, idx, phase)
        state, _ = f13(cur if phase == 0 else cur, state)
        cur, _ = f12(cur)
        transformed.append(cur)
    print('sample_transformed =', bytes(transformed).hex())
    print('sample_state =', hex(state))

    def run_chall(hex_input: str) -> bytes:
        work = Path('/home/cht2308/unbreakable/jumpy')
        orig = ENC
        (work / 'enc.sky').write_bytes(orig)
        subprocess.run(
            ['./chall'],
            input=(hex_input + '\n').encode(),
            cwd=work,
            env=os.environ.copy(),
            capture_output=True,
            timeout=3,
            check=True,
        )
        return (work / 'enc.sky').read_bytes()

    probes = {
        'zeros': '00' * 38,
        'ff': 'ff' * 38,
        'seq': ''.join(f'{i:02x}' for i in range(38)),
    }
    for name, hex_input in probes.items():
        out = run_chall(hex_input)
        print(f'{name}_out_sha256 =', hashlib.sha256(out).hexdigest())
        print(f'{name}_out_prefix =', out[:32].hex())


if __name__ == '__main__':
    main()
