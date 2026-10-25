#!/usr/bin/env python3
"""Vectorized evaluator for symwalk expression JSON (numpy).

Compiles one expression tree into numpy uint64 operations over:
  * the row index array i
  * raw column arrays read from the metadata body at (base + i*stride + off)
  * hdr[slot] resolved against the header copy bytes (constant)

Expression node format: see symwalk.py docstring.
"""
import struct
import numpy as np

M64 = np.uint64(0xFFFFFFFFFFFFFFFF)


def read_col(body, base, stride, off, width, rows):
    a = np.frombuffer(body, dtype=np.uint8)
    n = rows
    idx = np.arange(n, dtype=np.int64)
    start = base + off
    if start < 0 or start + stride * (n - 1) + width > len(body):
        raise ValueError('column out of body bounds')
    if width == 1:
        return a[start + stride * idx].astype(np.uint64)
    if width == 2:
        b0 = a[start + stride * idx].astype(np.uint64)
        b1 = a[start + stride * idx + 1].astype(np.uint64)
        return b0 | (b1 << np.uint64(8))
    if width == 4:
        v = a[start + stride * idx].astype(np.uint64)
        for k in (1, 2, 3):
            v |= a[start + stride * idx + k].astype(np.uint64) << np.uint64(8 * k)
        return v
    if width == 8:
        v = a[start + stride * idx].astype(np.uint64)
        for k in range(1, 8):
            v |= a[start + stride * idx + k].astype(np.uint64) << np.uint64(8 * k)
        return v
    raise ValueError('bad width')


class ExprVM:
    """Evaluate one expression for rows [0, rows).

    symmap: {'<sym name>': np.uint64 array} -- typically {'rax': idx}.
    hdr: bytes of the header copy (0x210) to resolve hdr[slot].
    """

    def __init__(self, body, base, stride, rows, symmap, hdr):
        self.body = body
        self.base = base
        self.stride = stride
        self.rows = rows
        self.symmap = symmap
        self.hdr = hdr
        self._colcache = {}

    def col(self, off, w):
        k = (off, w)
        if k not in self._colcache:
            self._colcache[k] = read_col(self.body, self.base, self.stride, off, w, self.rows)
        return self._colcache[k]

    def ev(self, e):
        t = e[0]
        if t == 'imm':
            return np.uint64(e[1] & 0xFFFFFFFFFFFFFFFF)
        if t == 'sym':
            name = e[1]
            if name in self.symmap:
                return self.symmap[name]
            raise ValueError('unresolved sym ' + name)
        if t == 'hdr':
            slot = e[1]
            if slot + 4 > len(self.hdr):
                raise ValueError('hdr slot oob')
            return np.uint64(struct.unpack_from('<I', self.hdr, slot)[0])
        if t == 'raw':
            return self.col(e[1], e[2] // 8)
        if t == 'op2':
            op = e[1]
            a = self.ev(e[2])
            b = self.ev(e[3])
            if op == '+': return (a + b) & M64
            if op == '-': return (a - b) & M64
            if op == '*': return (a * b) & M64
            if op == '^': return a ^ b
            if op == '&': return a & b
            if op == '|': return a | b
            if op == '>>':
                sh = int(b) if isinstance(b, np.uint64) else b
                return a >> np.uint64(int(sh))
            if op == '<<':
                sh = int(b) if isinstance(b, np.uint64) else b
                return (a << np.uint64(int(sh))) & M64
            raise ValueError('bad op ' + op)
        if t == 'lo':
            n = e[1]
            return self.ev(e[2]) & np.uint64((1 << n) - 1)
        if t == 'ext':
            n = e[1]
            a = self.ev(e[2]) & np.uint64((1 << n) - 1)
            if e[3]:
                sign = np.uint64(1 << (n - 1))
                a = a | ((a & sign) * np.uint64(0xFFFFFFFFFFFFFFFF >> (n - 1) << 1 | 0))
                # simpler: where top bit set, OR with high mask
                mask = np.uint64(((1 << (64 - n)) - 1) << n)
                a = np.where((a & sign) != 0, a | mask, a).astype(np.uint64)
            return a.astype(np.uint64)
        raise ValueError('bad node ' + t)
