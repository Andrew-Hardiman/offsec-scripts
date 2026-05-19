#!/bin/bash
# searchsploit_ladder.tests.sh — regression tests for searchsploit_ladder.sh
#
# Usage:  bash ~/scripts/searchsploit_ladder.tests.sh
#         bash ~/scripts/searchsploit_ladder.tests.sh /path/to/searchsploit_ladder.sh
#
# Sources the main script (without running its main loop, thanks to the
# source-guard at the top of the main loop) and calls each helper function
# with known inputs, asserting expected outputs.
#
# Exit code: 0 on all-pass, 1 on any failure.
#
# When you (or anyone) changes searchsploit_ladder.sh in future, run this
# file first. Failures = previously-working behaviour now broken.
# Add new test cases as edge cases surface — the more cases, the safer.

SCRIPT="${1:-$HOME/scripts/searchsploit_ladder.sh}"
[ -f "$SCRIPT" ] || { echo "Cannot find script at $SCRIPT" >&2; exit 1; }

# Source helpers (main loop is guarded inside the script, won't fire here)
# shellcheck disable=SC1090
source "$SCRIPT"

# --- Test framework ---
PASS=0
FAIL=0
FAIL_NAMES=()

assert() {
    local label="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("$label")
        echo "FAIL: $label"
        echo "  actual:   '$actual'"
        echo "  expected: '$expected'"
    fi
}

# --- parse_field5 tests ---
echo "== parse_field5 =="

parse_field5 "Apache httpd 2.4.41"
assert "apache: PRODUCT"            "$PRODUCT"           "Apache httpd"
assert "apache: VFULL"              "$VFULL"             "2.4.41"
assert "apache: VSTRICT"            "$VSTRICT"           "2.4.41"
assert "apache: PRODUCT_STRIPPED"   "$PRODUCT_STRIPPED"  "Apache"
assert "apache: PRODUCT_SPACED"     "$PRODUCT_SPACED"    ""
assert "apache: INNER_PRODUCT"      "$INNER_PRODUCT"     "0"

parse_field5 "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)"
assert "openssh-banner: PRODUCT"         "$PRODUCT"        "OpenSSH"
assert "openssh-banner: VFULL"           "$VFULL"          "6.6.1p1"
assert "openssh-banner: VSTRICT"         "$VSTRICT"        "6.6.1"
assert "openssh-banner: INNER_PRODUCT"   "$INNER_PRODUCT"  "0"

parse_field5 "OpenSSH_8.2p1"
assert "openssh-underscore: PRODUCT"     "$PRODUCT"        "OpenSSH"
assert "openssh-underscore: VFULL"       "$VFULL"          "8.2p1"

parse_field5 "Apache/2.4.41"
assert "apache-slash: PRODUCT"           "$PRODUCT"        "Apache"
assert "apache-slash: VFULL"             "$VFULL"          "2.4.41"

parse_field5 "Samba smbd 4"
assert "samba-partial: PRODUCT"          "$PRODUCT"        "Samba smbd"
assert "samba-partial: VFULL"            "$VFULL"          "4"
assert "samba-partial: STRIPPED"         "$PRODUCT_STRIPPED" "Samba"

parse_field5 "lighttpd"
assert "lighttpd-no-version: PRODUCT"    "$PRODUCT"        "lighttpd"
assert "lighttpd-no-version: VFULL"      "$VFULL"          ""

parse_field5 "Node.js (Express middleware)"
assert "nodejs-inner: PRODUCT"           "$PRODUCT"        "Node.js"
assert "nodejs-inner: INNER_PRODUCT"     "$INNER_PRODUCT"  "1"

parse_field5 "Apache httpd 2.4.41 ((Ubuntu))"
assert "apache-ubuntu-paren: INNER_PRODUCT" "$INNER_PRODUCT" "0"

parse_field5 "vsftpd 3.0.5"
assert "vsftpd: PRODUCT"                 "$PRODUCT"         "vsftpd"
assert "vsftpd: STRIPPED"                "$PRODUCT_STRIPPED" "vsftp"

parse_field5 "HttpFileServer httpd 2.3"
assert "hfs: STRIPPED"                   "$PRODUCT_STRIPPED" "HttpFileServer"
assert "hfs: SPACED"                     "$PRODUCT_SPACED"   "Http File Server"

# --- classify tests ---
echo "== classify =="
assert "RCE → foothold"             "$(classify "Apache 2.4.49 - Path Traversal & Remote Code Execution")"        "foothold"
assert "Command Injection → foothold" "$(classify "OpenSSH 7.2p1 - (Authenticated) xauth Command Injection")"      "foothold"
assert "Backdoor → foothold"        "$(classify "vsftpd 2.3.4 - Backdoor Command Execution")"                     "foothold"
assert "Auth Bypass → foothold"     "$(classify "Some Product - Authentication Bypass")"                          "foothold"
assert "DoS → weak"                 "$(classify "lighttpd 1.4.31 - Denial of Service")"                           "weak"
assert "Username Enum → weak"       "$(classify "OpenSSH 2.3 < 7.7 - Username Enumeration")"                      "weak"
assert "Local PrivEsc → weak"       "$(classify "OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation")"          "weak"
assert "Disclosure → weak"          "$(classify "Some product - Source Code Disclosure")"                         "weak"
assert "Path Traversal → manual"    "$(classify "Apache 2.4.49 - Path Traversal")"                                "manual"
assert "Buffer Overflow → manual"   "$(classify "OpenSSH 3.x - Challenge-Response Buffer Overflow")"              "manual"

# --- parse_constraint tests ---
echo "== parse_constraint =="
assert "range"          "$(parse_constraint "OpenSSH 2.3 < 7.7 - Username Enumeration")"  "range:2.3:7.7"
assert "lt"             "$(parse_constraint "OpenSSH < 7.4 - foo")"                       "lt:7.4"
assert "lte-symbol"     "$(parse_constraint "Samba <= 3.6 - Bug")"                        "lte:3.6"
assert "or-prior"       "$(parse_constraint "lighttpd 1.4 or prior - Bug")"               "lte:1.4"
assert "and-below"      "$(parse_constraint "Old Server 1.0 and below - Bug")"            "lte:1.0"
assert "wildcard-major" "$(parse_constraint "Sambar Server 5.x - Open Proxy")"            "range:5:6"
assert "wildcard-minor" "$(parse_constraint "Lighttpd 1.4.x - mod_userdir")"              "range:1.4:1.5"
assert "slash-set"      "$(parse_constraint "Samba 3.5.11/3.6.3 - RCE")"                  "eq_set:3.5.11|3.6.3"
assert "exact"          "$(parse_constraint "Apache 2.4.49 - Path Traversal")"            "eq:2.4.49"
assert "no-version"     "$(parse_constraint "OpenSSH SCP Client - Write Arbitrary Files")" ""

# --- match_constraint tests ---
echo "== match_constraint (full target) =="
assert "lt-yes"      "$(match_constraint "lt:7.7" "6.6.1p1")"             "YES"
assert "lt-no"       "$(match_constraint "lt:6.6" "6.6.1p1")"             "NO"
assert "eq-yes"      "$(match_constraint "eq:6.6.1p1" "6.6.1p1")"         "YES"
assert "eq-no"       "$(match_constraint "eq:7.2p1" "6.6.1p1")"           "NO"
assert "range-in"    "$(match_constraint "range:2.3:7.7" "6.6.1p1")"      "YES"
assert "range-out"   "$(match_constraint "range:6.8:6.9" "6.6.1p1")"      "NO"
assert "eqset-yes"   "$(match_constraint "eq_set:3.5.11|3.6.3" "3.5.11")" "YES"
assert "eqset-no"    "$(match_constraint "eq_set:3.5.11|3.6.3" "4.0.0")"  "NO"
assert "empty-target"     "$(match_constraint "lt:7.7" "")"               "?"
assert "empty-constraint" "$(match_constraint "" "6.6.1p1")"              "?"

# --- is_partial_ambiguous tests ---
echo "== is_partial_ambiguous =="
assert "prefix-match"  "$(is_partial_ambiguous "4" "4.5.9")"   "AMBIGUOUS"
assert "prefix-differ" "$(is_partial_ambiguous "4" "3.5.11")"  ""
assert "target-longer" "$(is_partial_ambiguous "6.6.1p1" "7.7")" ""
assert "same-len-eq"   "$(is_partial_ambiguous "4" "4")"       ""
assert "same-len-diff" "$(is_partial_ambiguous "4" "5")"       ""

# --- match_constraint with partial target (the SambaCry case) ---
echo "== match_constraint (partial target) =="
assert "partial-eq-prefix-match"  "$(match_constraint "eq:4.5.9" "4")"       "?"
assert "partial-eq-prefix-differ" "$(match_constraint "eq:3.5.11" "4")"      "NO"
assert "partial-lt-clean"         "$(match_constraint "lt:7.7" "4")"         "YES"
assert "partial-lt-ambig"         "$(match_constraint "lt:4.5" "4")"         "?"
assert "partial-range-out-low"    "$(match_constraint "range:5:6" "4")"      "NO"
assert "partial-eqset-no"         "$(match_constraint "eq_set:3.5.11|3.6.3" "4")" "NO"

# --- title_contains_product tests ---
echo "== title_contains_product =="
PRODUCT="Samba smbd"; PRODUCT_STRIPPED="Samba"; PRODUCT_SPACED=""
title_contains_product "Samba 4.5.9 - SambaCry"                                   && r=yes || r=no
assert "Samba in 'Samba 4.5.9'"                                "$r" "yes"
title_contains_product "Sambar Server 5.x - foo"                                  && r=yes || r=no
assert "Sambar excluded (cross-product false positive)"        "$r" "no"
title_contains_product "Microsoft Windows XP/2003 - Samba Share Resource Exhaustion" && r=yes || r=no
assert "Samba mid-title"                                       "$r" "yes"
title_contains_product "samba 4.5.9 - rce"                                        && r=yes || r=no
assert "case-insensitive match"                                "$r" "yes"

PRODUCT="vsftpd"; PRODUCT_STRIPPED="vsftp"; PRODUCT_SPACED=""
title_contains_product "vsftpd 2.3.4 - Backdoor"                                  && r=yes || r=no
assert "vsftpd full-product match"                             "$r" "yes"
title_contains_product "vsftp 1.0 - Bug"                                          && r=yes || r=no
assert "vsftp stripped match"                                  "$r" "yes"
title_contains_product "Apache 2.4 - foo"                                         && r=yes || r=no
assert "Apache (off-product) excluded"                         "$r" "no"

# --- is_generic_product tests ---
echo "== is_generic_product =="
is_generic_product "Microsoft Windows"           && r=yes || r=no
assert "Microsoft Windows is generic"            "$r" "yes"
is_generic_product "Microsoft Windows RPC"       && r=yes || r=no
assert "Microsoft Windows RPC is not generic"    "$r" "no"
is_generic_product "Microsoft Windows Server"    && r=yes || r=no
assert "Microsoft Windows Server is not generic" "$r" "no"
is_generic_product "vsftpd"                      && r=yes || r=no
assert "vsftpd is not generic"                   "$r" "no"
is_generic_product ""                            && r=yes || r=no
assert "empty is not generic"                    "$r" "no"

# --- bucket_for tests ---
echo "== bucket_for =="
assert "/local/ path → local"                "$(bucket_for "/linux/local/41173.c" "OpenSSH 6.8 < 6.9 - PTY")"                        "local"
assert "/shellcode/ path → shellcode"        "$(bucket_for "/linux/shellcode/1234.c" "Generic shellcode")"                          "shellcode"
assert "(Authenticated) PrivEsc → local"     "$(bucket_for "/linux/remote/6094.txt" "Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation")" "local"
assert "(Authenticated) RCE → foothold (not blocked)"  "$(bucket_for "/multiple/remote/39569.py" "OpenSSH 7.2p1 - (Authenticated) xauth Command Injection")" "foothold"
assert "/remote/ RCE → foothold (no override fires)"   "$(bucket_for "/linux/remote/42060.py" "Samba 4.5.9 - SambaCry CVE-2017-7494 RCE")"             "foothold"
assert "/remote/ ambiguous → manual"          "$(bucket_for "/linux/remote/45000.c" "OpenSSH < 6.6 SFTP - Command Execution")"      "foothold"
assert "/remote/ DoS → weak"                  "$(bucket_for "/linux/remote/foo.py" "lighttpd 1.4.31 - Denial of Service")"           "weak"

# --- Summary ---
echo
TOTAL=$((PASS+FAIL))
echo "Tests: $TOTAL total, $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then
    echo "Failed tests:"
    for n in "${FAIL_NAMES[@]}"; do echo "  - $n"; done
    exit 1
fi
exit 0
