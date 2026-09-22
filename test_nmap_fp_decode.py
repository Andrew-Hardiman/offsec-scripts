#!/usr/bin/env python3
# test_nmap_fp_decode.py
"""Regression tests for nmap_fp_decode.py.

Runs under pytest (`pytest test_nmap_fp_decode.py`) on Kali. Also runnable
standalone (`python3 test_nmap_fp_decode.py`) via the __main__ harness below,
for environments without pytest.

Breadth strategy: a SOURCE-FAITHFUL ENCODER (encode_fp) mirrors nmap's
addToServiceFingerprint exactly — the escape rules (service_scan.cc:1730-1763),
the 74-col wrap with `\\nSF:` prefixing (addServiceChar), the
`%r(name,HEXLEN,"...")` framing, ~900B response truncation, and the raw `;`
terminator. Decoding an encoded fingerprint must ROUND-TRIP to the original
bytes for arbitrary input (incl. all 256 byte values), so the decode is proven
against the exact format nmap emits for any service, not just copied samples.
"""
from __future__ import annotations

import os
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nmap_fp_decode as fp  # noqa: E402


# ==========================================================================
# Source-faithful encoder (mirrors nmap service_scan.cc)
# ==========================================================================

_SPECIAL = set('\\?"[]().*+$^|')


def esc_byte(b: int, nxt: int | None) -> str:
    ch = chr(b)
    if b < 128 and ch.isalnum():
        return ch
    if b == 0:
        return "\\0" if (nxt is None or not (0x30 <= nxt <= 0x39)) else "\\x00"
    if ch in _SPECIAL:
        return "\\" + ch
    if b < 128 and ch in string.punctuation:
        return ch
    if b == 0x0D:
        return "\\r"
    if b == 0x0A:
        return "\\n"
    if b == 0x09:
        return "\\t"
    return "\\x%02x" % b


def encode_fp(port: int, probes: list[tuple[str, bytes]], *,
              proto: str = "TCP", tls: bool = False,
              respcap: int = 900, wrap: int = 74) -> str:
    """Produce a byte-faithful SF-Port fingerprint string."""
    buf: list[str] = []
    length = 0

    def add_char(c: str) -> None:
        nonlocal length
        if wrap > 0 and length % (wrap + 1) == wrap:
            buf.append("\nSF:")
            length += 4
        buf.append(c)
        length += 1

    def add_string(s: str) -> None:
        for c in s:
            add_char(c)

    tls_tok = "%T=SSL" if tls else ""
    add_string(f"SF-Port{port}-{proto.upper()}:V=7.99{tls_tok}"
               f"%I=7%D=9/21%Time=6AB1334E%P=x86_64-pc-linux-gnu")
    for name, raw in probes:
        add_string(f'%r({name},{len(raw):X},"')
        used = raw[:respcap]
        for i, b in enumerate(used):
            nxt = used[i + 1] if i + 1 < len(used) else None
            add_string(esc_byte(b, nxt))
        add_string('")')
    buf.append(";")   # terminator is never wrapped
    return "".join(buf)


def wrap_in_report(block: str, extra_before: str = "", extra_after: str = "") -> str:
    """Simulate a full .nmap file around a fingerprint block."""
    pre = "PORT     STATE SERVICE VERSION\n3001/tcp open  nessus?\n"
    tail = "\nService Info: OS: Linux\n"
    return f"{pre}{extra_before}{block}\n{extra_after}{tail}"


# ==========================================================================
# Round-trip decode tests (breadth)
# ==========================================================================

def _decode_one(port: int, raw: bytes, *, proto: str = "tcp", wrap: int = 74) -> fp.Probe:
    block = encode_fp(port, [("Probe", raw)], proto=proto, wrap=wrap)
    parsed = fp.parse(wrap_in_report(block), port, proto)
    assert parsed is not None
    assert len(parsed.probes) == 1
    return parsed.probes[0]


def test_roundtrip_all_256_bytes() -> None:
    """Every byte value round-trips through encode->decode (the breadth proof)."""
    raw = bytes(range(256))
    got = _decode_one(3001, raw)
    assert got.data == raw
    assert got.declared_len == 256


def test_roundtrip_nul_then_letter() -> None:
    # NUL not followed by digit -> \0 short form
    got = _decode_one(3001, b"\x00A")
    assert got.data == b"\x00A"


def test_roundtrip_nul_then_digit() -> None:
    # NUL followed by digit -> \x00 (nmap disambiguation)
    got = _decode_one(3001, b"\x009")
    assert got.data == b"\x009"


def test_roundtrip_quotes_backslash_percent_parens() -> None:
    raw = b'a"b\\c%r(d)e[f]g.h*i+j$k^l|m?n'
    got = _decode_one(3001, raw)
    assert got.data == raw


def test_roundtrip_crlf_tab_space() -> None:
    raw = b"line1\r\nline2\ttabbed and spaced"
    got = _decode_one(3001, raw)
    assert got.data == raw


def test_roundtrip_high_bytes() -> None:
    raw = bytes([0x80, 0xFF, 0xAA, 0x7F, 0x01])
    got = _decode_one(3001, raw)
    assert got.data == raw


def test_roundtrip_single_byte() -> None:
    got = _decode_one(3001, b"X")
    assert got.data == b"X"


def test_truncation_over_900_bytes() -> None:
    raw = bytes([0x41]) * 2000
    got = _decode_one(3001, raw)
    assert got.declared_len == 2000        # hexlen = original length
    assert len(got.data) == 900            # escaped data truncated by nmap
    assert got.truncated is True
    assert got.data == b"A" * 900


def test_wrap_splits_escapes_across_lines() -> None:
    """At nmap's real wrap (74), escape sequences straddle line boundaries;
    reassembly must still round-trip (proves SF: reassembly is wrap-position
    independent). The header line is never split — nmap's header is <=74 chars."""
    raw = (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n"
           b"X-Powered-By: PHP/8.1\r\n\r\n" + bytes(range(48)))
    got = _decode_one(3001, raw)   # default wrap = 74 (nmap's value)
    assert got.data == raw


# ==========================================================================
# Structure / extraction tests
# ==========================================================================

def test_multi_probe() -> None:
    block = encode_fp(3001, [("NULL", b"\x00"), ("GetRequest", b"HTTP/1.1 200 OK\r\n"),
                             ("HTTPOptions", b"HTTP/1.1 400 Bad Request\r\n")])
    parsed = fp.parse(wrap_in_report(block), 3001, "tcp")
    assert parsed is not None
    assert [p.name for p in parsed.probes] == ["NULL", "GetRequest", "HTTPOptions"]


def test_two_blocks_no_bleed() -> None:
    b1 = encode_fp(3001, [("GetRequest", b"HTTP/1.1 200 OK\r\nServer: A\r\n")])
    b2 = encode_fp(6667, [("NULL", b":irc.example NOTICE\r\n")])
    text = wrap_in_report(b1, extra_after=b2 + "\n")
    p1 = fp.parse(text, 3001, "tcp")
    p2 = fp.parse(text, 6667, "tcp")
    assert p1 is not None and p2 is not None
    assert b"Server: A" in b"\n".join(x.data for x in p1.probes)
    assert b"irc.example" in b"\n".join(x.data for x in p2.probes)
    # 3001 block must not swallow the 6667 banner
    assert b"irc.example" not in b"\n".join(x.data for x in p1.probes)


def test_port_disambiguation() -> None:
    b_short = encode_fp(3001, [("GetRequest", b"SHORTPORT")])
    b_long = encode_fp(30011, [("GetRequest", b"LONGPORT")])
    text = wrap_in_report(b_short, extra_after=b_long + "\n")
    p = fp.parse(text, 3001, "tcp")
    assert p is not None
    joined = b"\n".join(x.data for x in p.probes)
    assert b"SHORTPORT" in joined and b"LONGPORT" not in joined


def test_literal_semicolon_in_content_not_truncated() -> None:
    """A `;` inside content (Content-Type: text/html; charset) landing at a
    line end must NOT end the block early — direct regression for the wrap-safe
    extract_block fix. Hand-crafts a block whose FIRST line ends in a content
    `;`, followed by an SF: continuation."""
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<!DOCTYPE html>"
    escaped = "".join(esc_byte(b, raw[i + 1] if i + 1 < len(raw) else None)
                      for i, b in enumerate(raw))
    head = f'SF-Port3001-TCP:V=7.99%I=7%D=9/21%Time=1%P=x%r(GetRequest,{len(raw):X},"'
    full = head + escaped + '")'
    semi = full.index(";", len(head))            # the content ';' in text/html;
    block = full[:semi + 1] + "\nSF:" + full[semi + 1:] + ";"
    assert block.splitlines()[0].endswith(";")   # first line really ends in a content ';'
    parsed = fp.parse(wrap_in_report(block), 3001, "tcp")
    assert parsed is not None
    assert parsed.probes[0].data == raw
    assert b"<!DOCTYPE html>" in parsed.probes[0].data


def test_udp_block() -> None:
    block = encode_fp(53, [("DNSVersionBindReqTCP", b"\x00\x0c\x00\x06")], proto="UDP")
    p = fp.parse(wrap_in_report(block), 53, "udp")
    assert p is not None and p.proto == "UDP"


def test_single_line_fingerprint() -> None:
    block = encode_fp(22, [("NULL", b"SSH-2.0-x\r\n")], wrap=0)  # no wrap
    assert "\nSF:" not in block
    p = fp.parse(wrap_in_report(block), 22, "tcp")
    assert p is not None and p.probes[0].data == b"SSH-2.0-x\r\n"


def test_no_block_returns_none() -> None:
    assert fp.parse("PORT STATE SERVICE\n80/tcp open http\n", 3001, "tcp") is None


# ==========================================================================
# Classification tests (field 4 = service, field 5 = version)
# ==========================================================================

def _classify_raw(port: int, probes: list[tuple[str, bytes]], *, tls: bool = False) -> tuple[str, str, list[str]]:
    block = encode_fp(port, probes, tls=tls)
    parsed = fp.parse(wrap_in_report(block), port, "tcp")
    assert parsed is not None
    return fp.classify(parsed)


def test_classify_http() -> None:
    svc, ver, ev = _classify_raw(3001, [
        ("NULL", b"HTTP/1.1 400 Bad Request\r\n"),
        ("GetRequest", b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nX-Powered-By: PHP/8.1\r\n\r\n<!DOCTYPE html>"),
    ])
    assert svc == "http"
    assert ver == "Apache/2.4.49"
    assert any("Apache/2.4.49" in e for e in ev)


def test_classify_https_tls() -> None:
    svc, ver, _ = _classify_raw(443, [("GetRequest", b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")], tls=True)
    assert svc == "https"
    assert ver == "nginx"


def test_classify_http_on_400_only() -> None:
    """A service that only ever 400s is still http."""
    svc, _, _ = _classify_raw(8080, [("NULL", b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")])
    assert svc == "http"


def test_classify_ssh() -> None:
    svc, ver, _ = _classify_raw(22, [("NULL", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")])
    assert svc == "ssh"
    assert "OpenSSH_8.9p1" in ver


def test_classify_ftp() -> None:
    svc, _, _ = _classify_raw(21, [("NULL", b"220 (vsFTPd 3.0.3)\r\n")])
    assert svc == "ftp"


def test_classify_smtp() -> None:
    svc, _, _ = _classify_raw(25, [("NULL", b"220 mail.example.com ESMTP Postfix\r\n")])
    assert svc == "smtp"


def test_classify_pop3() -> None:
    svc, _, _ = _classify_raw(110, [("NULL", b"+OK POP3 ready\r\n")])
    assert svc == "pop3"


def test_classify_imap() -> None:
    svc, _, _ = _classify_raw(143, [("NULL", b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n")])
    assert svc == "imap"


def test_classify_mysql() -> None:
    raw = b"\x4a\x00\x00\x00\x0a5.5.5-10.3\x00" + b"\x00" * 10 + b"mysql_native_password\x00"
    svc, _, _ = _classify_raw(3306, [("NULL", raw)])
    assert svc == "mysql"


def test_classify_redis() -> None:
    svc, _, _ = _classify_raw(6379, [("GetRequest", b"-ERR unknown command 'GET'\r\n")])
    assert svc == "redis"


def test_classify_vnc() -> None:
    svc, _, _ = _classify_raw(5900, [("NULL", b"RFB 003.008\n")])
    assert svc == "vnc"


def test_classify_telnet() -> None:
    svc, _, _ = _classify_raw(23, [("NULL", b"\xff\xfb\x01\xff\xfd\x18\xff\xfd\x1f")])
    assert svc == "telnet"


def test_classify_unknown_opaque() -> None:
    svc, _, ev = _classify_raw(9999, [("NULL", b"\x13\x37\xca\xfe\xba\xbe some proprietary blob")])
    assert svc == "UNKNOWN"
    assert ev  # evidence still present


def test_classify_220_ambiguous_no_guess() -> None:
    """220 banner with neither FTP nor SMTP token must NOT be force-guessed."""
    svc, _, _ = _classify_raw(2121, [("NULL", b"220 Service ready\r\n")])
    assert svc == "UNKNOWN"


# ==========================================================================
# Malformed-block handling
# ==========================================================================

def test_malformed_unterminated_quote() -> None:
    bad = 'SF-Port3001-TCP:V=7.99%I=7%D=9/21%Time=1%P=x%r(NULL,5,"abc'
    try:
        fp.parse(wrap_in_report(bad), 3001, "tcp")
        raised = False
    except fp.DecodeError:
        raised = True
    assert raised


def test_malformed_bad_hexlen() -> None:
    bad = 'SF-Port3001-TCP:V=7.99%I=7%D=9/21%Time=1%P=x%r(NULL,ZZ,"abc")'
    try:
        fp.parse(wrap_in_report(bad), 3001, "tcp")
        raised = False
    except fp.DecodeError:
        raised = True
    assert raised


# ==========================================================================
# REAL fixture — the actual 3001 Next.js block from the THM box
# ==========================================================================

REAL_3001 = (
    'PORT     STATE SERVICE VERSION\n'
    '3001/tcp open  nessus?\n'
    '1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :\n'
    'SF-Port3001-TCP:V=7.99%I=7%D=9/21%Time=6AB1334E%P=x86_64-pc-linux-gnu%r(NC\n'
    'SF:P,2F,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nConnection:\\x20close\\r\\n\\r\\\n'
    'SF:n")%r(GetRequest,1245,"HTTP/1\\.1\\x20200\\x20OK\\r\\nVary:\\x20RSC,\\x20Next-\n'
    'SF:Router-State-Tree,\\x20Next-Router-Prefetch,\\x20Next-Router-Segment-Pref\n'
    'SF:etch,\\x20Accept-Encoding\\r\\nx-nextjs-cache:\\x20HIT\\r\\nx-nextjs-prerende\n'
    'SF:r:\\x201\\r\\nx-nextjs-stale-time:\\x204294967294\\r\\nX-Powered-By:\\x20Next\\\n'
    'SF:.js\\r\\nCache-Control:\\x20s-maxage=31536000,\\x20\\r\\nETag:\\x20\\"1pqu4ojvi\n'
    'SF:f3at\\"\\r\\nContent-Type:\\x20text/html;\\x20charset=utf-8\\r\\nContent-Lengt\n'
    'SF:h:\\x204277\\r\\nDate:\\x20Mon,\\x2021\\x20Sep\\x202026\\x2013:38:27\\x20GMT\\r\\n\n'
    'SF:Connection:\\x20close\\r\\n\\r\\n<!DOCTYPE\\x20html><html\\x20lang=\\"en\\"><hea\n'
    'SF:d><meta\\x20charSet=\\"utf-8\\"/><meta\\x20name=\\"viewport\\"\\x20content=\\"w\n'
    'SF:idth=device-width,\\x20initial-scale=1\\"/><link\\x20rel=\\"preload\\"\\x20as\n'
    'SF:=\\"script\\"\\x20fetchPriority=\\"low\\"\\x20href=\\"/_next/static/chunks/web\n'
    'SF:pack-5adebf9f62dc3001\\.js\\"/><script\\x20src=\\"/_next/static/chunks/4bd1\n'
    'SF:b696-92810b4b4ece63ad\\.js\\"\\x20async=\\"\\"></script><script\\x20src=\\"/_n\n'
    'SF:ext/static/chunks/517-c94eb82a0c6a5f4b\\.js\\"\\x20async=\\"\\"></script><sc\n'
    'SF:ript\\x20src=\\"/_next/static/chunks/main-app-428d9450bbd1040e\\.js\\"\\x20a\n'
    'SF:sync=\\"\\"></script><script\\x20src=\\"/_next/s")%r(HTTPOptions,10C,"HTTP/\n'
    'SF:1\\.1\\x20400\\x20Bad\\x20Request\\r\\nvary:\\x20RSC,\\x20Next-Router-State-Tre\n'
    'SF:e,\\x20Next-Router-Prefetch,\\x20Next-Router-Segment-Prefetch\\r\\nAllow:\\x\n'
    'SF:20GET\\r\\nAllow:\\x20HEAD\\r\\nCache-Control:\\x20private,\\x20no-cache,\\x20n\n'
    'SF:o-store,\\x20max-age=0,\\x20must-revalidate\\r\\nDate:\\x20Mon,\\x2021\\x20Sep\n'
    'SF:\\x202026\\x2013:38:27\\x20GMT\\r\\nConnection:\\x20close\\r\\n\\r\\n")%r(RTSPReq\n'
    'SF:uest,10C,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nvary:\\x20RSC,\\x20Next-R\n'
    'SF:outer-State-Tree,\\x20Next-Router-Prefetch,\\x20Next-Router-Segment-Prefe\n'
    'SF:tch\\r\\nAllow:\\x20GET\\r\\nAllow:\\x20HEAD\\r\\nCache-Control:\\x20private,\\x2\n'
    'SF:0no-cache,\\x20no-store,\\x20max-age=0,\\x20must-revalidate\\r\\nDate:\\x20Mo\n'
    'SF:n,\\x2021\\x20Sep\\x202026\\x2013:38:27\\x20GMT\\r\\nConnection:\\x20close\\r\\n\\\n'
    'SF:r\\n")%r(RPCCheck,2F,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nConnection:\\\n'
    'SF:x20close\\r\\n\\r\\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\\.1\\x20400\\x20Bad\\x\n'
    'SF:20Request\\r\\nConnection:\\x20close\\r\\n\\r\\n");\n'
    'Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n'
)


def test_real_3001_parses_all_probes() -> None:
    parsed = fp.parse(REAL_3001, 3001, "tcp")
    assert parsed is not None
    names = [p.name for p in parsed.probes]
    assert names == ["NCP", "GetRequest", "HTTPOptions", "RTSPRequest", "RPCCheck", "DNSVersionBindReqTCP"]


def test_real_3001_classifies_http_nextjs() -> None:
    parsed = fp.parse(REAL_3001, 3001, "tcp")
    assert parsed is not None
    svc, ver, ev = fp.classify(parsed)
    assert svc == "http"
    assert ver == "Next.js"
    assert any("Next.js" in e for e in ev)


def test_real_3001_getrequest_decodes_cleanly() -> None:
    parsed = fp.parse(REAL_3001, 3001, "tcp")
    assert parsed is not None
    getreq = next(p for p in parsed.probes if p.name == "GetRequest")
    text = getreq.data.decode("latin-1")
    assert text.startswith("HTTP/1.1 200 OK")
    assert "X-Powered-By: Next.js" in text
    assert "<!DOCTYPE html>" in text
    assert '"1pqu4ojvi' in text  # escaped-quote (ETag) round-trips to a real quote


def test_real_3001_declared_len_matches_hex() -> None:
    parsed = fp.parse(REAL_3001, 3001, "tcp")
    assert parsed is not None
    getreq = next(p for p in parsed.probes if p.name == "GetRequest")
    assert getreq.declared_len == 0x1245  # 4677


# ==========================================================================
# Standalone runner (pytest ignores this block)
# ==========================================================================

def _run_standalone() -> int:
    tests = sorted((n, o) for n, o in globals().items()
                   if n.startswith("test_") and callable(o))
    passed = failed = 0
    for name, func in tests:
        try:
            func()
            print(f"PASS: {name}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL: {name}: {type(exc).__name__}: {exc}")
            failed += 1
    print("=" * 40)
    print(f"PASSED: {passed}   FAILED: {failed}   TOTAL: {passed + failed}")
    print("=" * 40)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
