# offsec-toolkit

Automation for the repetitive parts of OffSec exam work. Original tools only —
no exam content, no leaks; everything here is methodology + scaffolds you fill
with YOUR target data.

For authorized use only: OffSec labs/exams and infrastructure you own or are
explicitly permitted to test.

## exp301/ — OSED (Windows user-mode exploit dev)

The exam is a loop: crash → pattern → offset → badchars → egghunter/ROP →
shellcode. Automate the loop:

```bash
python3 exp301.py cyclic 3000            # metasploit-style pattern
python3 exp301.py offset 6f41356f        # EIP value -> offset
python3 exp301.py badchars crash.bin     # diff memory dump vs 0x01-0xff corpus
python3 exp301.py egghunter W00T         # 32-byte NtAccessCheck egghunter
python3 exp301.py encode sc.bin --bad 00,0a,0d   # xor-encode shellcode + stub
python3 exp301.py rop mona_rop.txt       # gadget file -> ROP chain scaffold
```

Templates (fill CONFIG block, fire): `stack_bof.py` (vanilla EIP),
`seh_bof.py` (pop/pop/ret + short jmp), `dep_rop.py` (VirtualProtect/pushad),
`format_string.py` (leak probe + %hhn write builder).

## web300/ — OSWE (advanced web exploitation)

```bash
python3 web300.py replay capture.req --set Cookie=session=...
python3 web300.py blindsqli capture.req --marker "Welcome" --param id \
    --sql "SELECT password FROM users WHERE id=1"     # boolean binary-search exfil
python3 web300.py juggle                              # PHP magic-hash / coercion notes
python3 web300.py audit /path/to/source --lang php    # vuln-class grep checklists
```

`templates/exploit_skeleton.py` — the exam-standard four-stage shape
(auth → trigger → RCE → flag), pre-wired through Burp.
`payloads/payloads.txt` — exam-speed corpus: SSTI ladder, blind SQLi, PHP type
juggling, .NET deser/ViewState, SSRF, XXE, prototype pollution, upload bypass.

## Companion
See also the OSAI-arsenal repo for AI-300 tooling (recon, LLM probes, payload
corpus, exam AI-orchestration harness).
