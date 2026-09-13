#!/usr/bin/env bash
# ip_scan_selftest.sh — positive control for scripts/ip_scan.sh.
#
# A gate that only ever says PASS proves nothing. For every HIGH and MED class
# the scanner knows, this builds a throwaway git repo containing exactly one
# planted, fictional identifier of that class, runs the scan, and requires it
# to FAIL with a hit recorded under that class. LOW classes must record a hit
# but not fail the gate. A clean tree must PASS, and an unrunnable pattern
# must make the scan exit 2 rather than report zero hits. The throwaway repos
# live under mktemp and are deleted on exit. No model, no network.
#
# Usage: scripts/ip_scan_selftest.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/ip_scan.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PRIV='fictional-employer|project zebra'
failures=0

mkrepo() {  # mkrepo <dir> <planted line>
    mkdir -p "$1" && ( cd "$1" && git init -q && git config user.email ci@example.com \
        && git config user.name ci && printf '%s\n' "$2" > note.txt && git add -A && git commit -qm plant )
}

# plant <expect: fail|pass> <class> <line>
plant() {
    local expect=$1 cls=$2 line=$3 rc=0
    local dir="$T/$cls" out="$T/out-$cls"
    mkrepo "$dir" "$line"
    IP_SCAN_PRIVATE_TERMS="$PRIV" bash "$SCAN" "$dir" "$out" > "$T/$cls.log" 2>&1 || rc=$?
    local hits=0; [ -s "$out/$cls.txt" ] && hits=$(wc -l < "$out/$cls.txt")
    local ok=1
    if [ "$rc" -eq 2 ]; then ok=0
    elif [ "$hits" -eq 0 ]; then ok=0
    elif [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then ok=0
    elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        printf '  %-4s %-18s caught (%d hit, exit %d)\n' "$expect" "$cls" "$hits" "$rc"
    else
        printf '  %-4s %-18s MISSED (%d hits, exit %d)\n' "$expect" "$cls" "$hits" "$rc"
        sed 's/^/      /' "$T/$cls.log" | head -25
        failures=$((failures + 1))
    fi
}

echo "== one plant per class: HIGH/MED must fail the scan, LOW must record a hit"
plant fail case_ids         'ticket INC-20240117 raised overnight'
plant fail tenant           'tenant: contoso-east'
plant fail vendor_urls      'console https://falcon.us-2.crowdstrike.com/ for detail'
plant fail corp_hostnames   'host USNYC01APP7 rebooted'
plant fail emails           'contact jdoe@contoso.com for access'
plant fail user_home        'copied from /home/jdoe and C:\Users\jdoe\Desktop'
plant fail secrets          'api_key = "sk_live_0123456789abcdef0123"'
plant fail sha256           'hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
plant fail uuid             'id 123e4567-e89b-12d3-a456-426614174000'
plant fail private_terms    'internal codename: Project Zebra (do not ship)'
plant fail rfc1918          'source 10.42.7.19 on the lab segment'
plant fail internal_domains 'share on fs01.corp via SMB'
plant fail domain_user      'logon by CORP\jdoe at 09:14'
plant fail hostnames        'endpoint DESKTOP-AB12CD isolated'
plant pass public_ip        'resolver 8.8.8.8 answered'
plant pass realdata_words   'this was tested on real customer data'

echo "== negative control: a clean tree must PASS"
mkrepo "$T/clean" 'hello from 192.0.2.10 (RFC 5737 documentation range), contact dev@example.com'
if IP_SCAN_PRIVATE_TERMS="$PRIV" bash "$SCAN" "$T/clean" "$T/out-clean" > "$T/clean.log" 2>&1; then
    echo "  clean tree passed"
else
    echo "  FAILED: clean tree did not pass"; sed 's/^/      /' "$T/clean.log" | head -25; failures=$((failures + 1))
fi

echo "== broken pattern: an unrunnable regex must exit 2, not report zero hits"
rc=0; IP_SCAN_PRIVATE_TERMS='[' bash "$SCAN" "$T/clean" "$T/out-broken" > "$T/broken.log" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -q '^BROKEN' "$T/broken.log"; then
    echo "  broken pattern detected (exit 2)"
else
    echo "  FAILED: broken pattern exited $rc"; sed 's/^/      /' "$T/broken.log" | head -25; failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "SELFTEST FAILED: $failures check(s) did not behave"; exit 1
fi
echo "SELFTEST PASSED: every class caught, clean tree passes, broken pattern is fatal"
