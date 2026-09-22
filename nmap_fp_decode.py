#!/usr/bin/env python3
# nmap_fp_decode.py
"""Decode an nmap service fingerprint (SF-Port block) from -sV .nmap output.

MASTER WORKFLOW Step 5, Step 3.2 (Resolve service-identity gaps). When -sV
returns data it cannot match, nmap prints a `?`-suffixed service and dumps a
raw, escaped, line-wrapped SF-Port fingerprint. This decodes that block into
readable probe responses and suggests the services_<ip>.txt field 4 (service)
and field 5 (version) values, with an explicit UNKNOWN when nothing classifies.

The DECODE is deterministic and universal (nmap's escape format is fixed).
The CLASSIFY is a finite marker set over common services; anything outside it
returns UNKNOWN with the decoded evidence always shown, so the operator makes
the call. There is no silent false negative: absence of a marker prints
UNKNOWN, never a guess.

Usage:
    nmap_fp_decode.py <nmap_file> <port> [--proto tcp|udp]

Exit codes:
    0  fingerprint block decoded (classified OR UNKNOWN)
    2  usage error
    3  no SF-Port<port>-<PROTO> block in the file
    4  block found but malformed (could not parse)
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass


class DecodeError(Exception):
    """Raised when an SF-Port block is present but cannot be parsed."""


@dataclass
class Probe:
    name: str
    declared_len: int   # hexlen from the fingerprint = ORIGINAL response length
    data: bytes         # decoded bytes (may be < declared_len; nmap truncates ~900B)

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.declared_len


@dataclass
class Fingerprint:
    port: int
    proto: str          # "TCP" | "UDP"
    tls: bool           # header carried %T=SSL
    probes: list[Probe]


# --------------------------------------------------------------------------
# Extraction + reassembly
# --------------------------------------------------------------------------

def extract_block(text: str, port: int, proto: str) -> list[str] | None:
    """Return the raw lines of the SF-Port<port>-<PROTO> block, or None.

    The block is the header line `SF-Port<port>-<PROTO>:...` plus the run of
    continuation lines that immediately follow it and begin `SF:`. It ends at
    the first line that does NOT begin `SF:` — the next `SF-Port...` header, a
    later report line, or EOF. This boundary is wrap-safe: a literal `;` inside
    escaped content can land at an nmap line-wrap, so the terminating `;` is
    NOT a reliable block delimiter; the `SF:` prefix run is.
    """
    head = f"SF-Port{port}-{proto.upper()}:"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(head):
            out = [line]
            j = i + 1
            while j < len(lines) and lines[j].startswith("SF:"):
                out.append(lines[j])
                j += 1
            return out
    return None


def reassemble(block_lines: list[str]) -> str:
    """Join a block into one logical string: line 0 as-is, continuation lines
    with their leading `SF:` stripped, concatenated with no separator (nmap's
    74-col wrap can split anywhere, including mid-token)."""
    if not block_lines:
        return ""
    parts = [block_lines[0]]
    for line in block_lines[1:]:
        parts.append(line[3:] if line.startswith("SF:") else line)
    return "".join(parts).rstrip()


# --------------------------------------------------------------------------
# Escape-aware quoted-response scanner
# --------------------------------------------------------------------------

_SHORT = {"0": 0x00, "n": 0x0A, "r": 0x0D, "t": 0x09}
_HEX = set("0123456789abcdefABCDEF")


def scan_quoted(s: str, i: int) -> tuple[bytes, int]:
    """s[i] must be the opening '"'. Decode to bytes, return (bytes, index
    just past the closing unescaped '"'). Escapes per nmap service_scan.cc:
    \\xHH, \\0, \\r, \\n, \\t, and \\<char> (literal) for the regex-special set."""
    if i >= len(s) or s[i] != '"':
        raise DecodeError("expected opening quote for probe response")
    i += 1
    out = bytearray()
    while i < len(s):
        c = s[i]
        if c == '"':                       # unescaped closing quote
            return bytes(out), i + 1
        if c == "\\":
            if i + 1 >= len(s):
                raise DecodeError("dangling backslash in response")
            nxt = s[i + 1]
            if nxt == "x":
                if i + 3 >= len(s) or s[i + 2] not in _HEX or s[i + 3] not in _HEX:
                    raise DecodeError("malformed \\xHH escape")
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
            elif nxt in _SHORT:
                out.append(_SHORT[nxt])
                i += 2
            else:                          # \\<char> -> literal char
                out.append(ord(nxt) & 0xFF)
                i += 2
        else:
            out.append(ord(c) & 0xFF)
            i += 1
    raise DecodeError("unterminated probe response (no closing quote)")


# --------------------------------------------------------------------------
# Parse
# --------------------------------------------------------------------------

def parse(text: str, port: int, proto: str) -> Fingerprint | None:
    block = extract_block(text, port, proto)
    if block is None:
        return None
    body = reassemble(block)
    head = f"SF-Port{port}-{proto.upper()}:"
    if not body.startswith(head):
        raise DecodeError("block does not start with expected header")
    rest = body[len(head):]

    first_r = rest.find("%r(")
    header = rest if first_r < 0 else rest[:first_r]
    tls = "%T=SSL" in header

    probes: list[Probe] = []
    idx = first_r
    while idx >= 0 and rest.startswith("%r(", idx):
        idx += 3
        comma1 = rest.find(",", idx)
        if comma1 < 0:
            raise DecodeError("probe missing name/length separator")
        name = rest[idx:comma1]
        comma2 = rest.find(",", comma1 + 1)
        if comma2 < 0:
            raise DecodeError("probe missing length/data separator")
        hexlen = rest[comma1 + 1:comma2]
        try:
            declared = int(hexlen, 16)
        except ValueError as exc:
            raise DecodeError(f"bad hex length {hexlen!r}") from exc
        data, after = scan_quoted(rest, comma2 + 1)
        if after < len(rest) and rest[after] == ")":
            after += 1
        else:
            raise DecodeError("probe response not closed with ')'")
        probes.append(Probe(name=name, declared_len=declared, data=data))
        # next probe or terminator
        idx = rest.find("%r(", after)
    return Fingerprint(port=port, proto=proto.upper(), tls=tls, probes=probes)


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------

def render(data: bytes) -> str:
    """Human-readable rendering: printable ASCII as-is, CRLF as newlines,
    tab as tab, everything else as \\xHH."""
    out: list[str] = []
    for b in data:
        if b == 0x0A:
            out.append("\n")
        elif b == 0x0D:
            out.append("")
        elif b == 0x09:
            out.append("\t")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _text(fp: Fingerprint) -> str:
    """All decoded probe data as one latin-1 string for marker scanning."""
    return b"\n".join(p.data for p in fp.probes).decode("latin-1")


# --------------------------------------------------------------------------
# Classify  (service = field 4, version = field 5, evidence lines)
# --------------------------------------------------------------------------

def _header_value(hay: str, name: str) -> str | None:
    low = hay.lower()
    key = name.lower() + ":"
    pos = low.find(key)
    if pos < 0:
        return None
    line = hay[pos + len(key):]
    for end in ("\n", "\r"):
        cut = line.find(end)
        if cut >= 0:
            line = line[:cut]
    return line.strip() or None


def _starts_any(fp: Fingerprint, prefix: bytes) -> bool:
    return any(p.data.lstrip().startswith(prefix) for p in fp.probes)


def classify(fp: Fingerprint) -> tuple[str, str, list[str]]:
    """Return (field4_service, field5_version, evidence_lines).
    field4 == 'UNKNOWN' when no marker matches."""
    hay = _text(fp)
    raw = b"\n".join(p.data for p in fp.probes)

    # SSH
    if _starts_any(fp, b"SSH-"):
        ver = "-"
        for tag in ("SSH-2.0-", "SSH-1.99-", "SSH-1.5-"):
            pos = hay.find(tag)
            if pos >= 0:
                tail = hay[pos + len(tag):].split("\n")[0].strip()
                ver = tail or "-"
                break
        return "ssh", ver, [f"SSH banner: {hay.splitlines()[0].strip()}"] if hay else ["SSH banner"]

    # HTTP (status line or HTML) — TLS-aware
    http_hit = ("HTTP/1." in hay) or ("HTTP/2" in hay) or ("<!DOCTYPE" in hay) or ("<html" in hay.lower())
    if http_hit:
        service = "https" if fp.tls else "http"
        ev: list[str] = []
        server = _header_value(hay, "Server")
        xpb = _header_value(hay, "X-Powered-By")
        if server:
            ev.append(f"Server: {server}")
        if xpb:
            ev.append(f"X-Powered-By: {xpb}")
        version = server or xpb or "-"
        if not ev:
            ev.append("HTTP response present (no Server/X-Powered-By header)")
        return service, version, ev

    # SMTP vs FTP (both open with 220) — disambiguate on distinctive tokens
    smtp_tok = next((t for t in ("ESMTP", "SMTP", "Postfix", "Exim", "Sendmail") if t.lower() in hay.lower()), None)
    ftp_tok = next((t for t in ("FileZilla", "vsFTPd", "ProFTPD", "Pure-FTPd", "FTP") if t.lower() in hay.lower()), None)
    starts_220 = _starts_any(fp, b"220")
    if starts_220 and smtp_tok:
        return "smtp", hay.splitlines()[0].strip(), [f"SMTP banner ({smtp_tok}): {hay.splitlines()[0].strip()}"]
    if starts_220 and ftp_tok:
        return "ftp", hay.splitlines()[0].strip(), [f"FTP banner ({ftp_tok}): {hay.splitlines()[0].strip()}"]

    # POP3
    if _starts_any(fp, b"+OK"):
        return "pop3", "-", [f"POP3 banner: {hay.splitlines()[0].strip()}"]

    # IMAP
    if _starts_any(fp, b"* OK") and "IMAP" in hay.upper():
        return "imap", "-", [f"IMAP banner: {hay.splitlines()[0].strip()}"]

    # MySQL / MariaDB handshake
    if b"mysql_native_password" in raw or "mariadb" in hay.lower():
        return "mysql", "MariaDB" if "mariadb" in hay.lower() else "-", ["MySQL/MariaDB handshake (mysql_native_password)"]

    # Redis
    if _starts_any(fp, b"-ERR") or _starts_any(fp, b"-NOAUTH") or _starts_any(fp, b"-DENIED") or _starts_any(fp, b"+PONG"):
        return "redis", "-", [f"Redis RESP reply: {hay.splitlines()[0].strip()}"]

    # VNC / RFB
    if _starts_any(fp, b"RFB 003."):
        return "vnc", hay.splitlines()[0].strip(), [f"RFB banner: {hay.splitlines()[0].strip()}"]

    # Telnet (IAC negotiation bytes)
    if any(seq in raw for seq in (b"\xff\xfb", b"\xff\xfd", b"\xff\xfe", b"\xff\xfc")):
        return "telnet", "-", ["Telnet IAC negotiation bytes present"]

    # 220 banner but no FTP/SMTP distinguisher — do not guess
    if starts_220:
        return "UNKNOWN", "-", [f"220 banner (ftp or smtp, undetermined): {hay.splitlines()[0].strip()}"]

    return "UNKNOWN", "-", ["no known service marker matched — read the decoded responses below"]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def format_report(fp: Fingerprint) -> str:
    service, version, evidence = classify(fp)
    lines: list[str] = []
    lines.append(f"=== SF-Port{fp.port}-{fp.proto}"
                 f"{'  [%T=SSL]' if fp.tls else ''}  ({len(fp.probes)} probe response(s)) ===")
    for p in fp.probes:
        trunc = f"  [truncated by nmap: {p.declared_len} bytes original]" if p.truncated else ""
        lines.append(f"\n--- %r({p.name})  {len(p.data)} bytes{trunc} ---")
        lines.append(render(p.data))
    lines.append("\n" + "-" * 60)
    lines.append(f"FIELD 4 (service):  {service}")
    lines.append(f"FIELD 5 (version):  {version}")
    if evidence:
        lines.append("EVIDENCE:")
        for e in evidence:
            lines.append(f"  - {e}")
    if service == "UNKNOWN":
        lines.append("\nUNKNOWN — no marker matched. Read the decoded responses above and")
        lines.append("set field 4 by hand, or fall through to Step 3.3 (active probe).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode an nmap SF-Port service fingerprint and suggest service/version.")
    parser.add_argument("nmap_file", help="path to services_<ip>.nmap")
    parser.add_argument("port", type=int, help="port whose fingerprint to decode")
    parser.add_argument("--proto", default="tcp", choices=["tcp", "udp"],
                        help="transport protocol (default: tcp)")
    args = parser.parse_args(argv)

    try:
        with open(args.nmap_file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read {args.nmap_file}: {exc}", file=sys.stderr)
        return 2

    try:
        fp = parse(text, args.port, args.proto)
    except DecodeError as exc:
        print(f"MALFORMED: SF-Port{args.port}-{args.proto.upper()} block found but unparseable: {exc}",
              file=sys.stderr)
        return 4

    if fp is None:
        print(f"NO_FINGERPRINT: no SF-Port{args.port}-{args.proto.upper()} block in {args.nmap_file} "
              f"— go to Step 3.3 (active probe).")
        return 3

    print(format_report(fp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
