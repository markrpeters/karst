#!/usr/bin/env bash
# IP-safety scan for this repository. Exits non-zero on any HIGH or MED hit.
#
# Recreated from the pattern key of the 2026-09-12 portfolio assessment so it
# can run in CI. Scans every git-tracked text file (or every file under the
# tree when not in a git repo), excluding this script, and writes one hit
# list per pattern to $OUT (default: scan-results/, git-ignored).
#
# Severity policy:
#   HIGH  identifies a real environment on its own — case/ticket ids, tenant
#         ids, vendor console URLs, corporate hostname schemes, real e-mail
#         addresses, absolute home / mount paths, credentials, file hashes,
#         UUIDs. Organisation-specific terms (an employer or customer name,
#         an AD domain prefix) must NOT live in this file, or the scanner
#         becomes the leak: put them in scripts/ip_scan.private (git-ignored,
#         one extended regex per line) or in the IP_SCAN_PRIVATE_TERMS
#         environment variable (regex alternatives separated by "|"), which is
#         how CI supplies them from a secret. Both are scanned as HIGH,
#         case-insensitively.
#   MED   would need context to be harmless — RFC1918 addresses, internal AD
#         domains, DOMAIN\user tokens, generic hostname shapes. Test fixtures
#         in this repo use RFC 5737 documentation addresses and invented
#         names precisely so that MED stays at zero without an allowlist.
#   LOW   informational only, never fails the gate — public IPs outside the
#         documentation ranges, words that suggest real data was handled.
#
# Usage: scripts/ip_scan.sh [repo-root] [out-dir]
set -u
ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
OUT=${2:-$ROOT/scan-results}
SELF=scripts/ip_scan.sh
PRIVATE=scripts/ip_scan.private
mkdir -p "$OUT"
cd "$ROOT" || exit 2

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -z
else
    find . -type f -not -path './.git/*' -not -path './.venv/*' -not -path './scan-results/*' -print0
fi | xargs -0 file --mime-type 2>/dev/null \
   | grep -E 'text/|json|xml|csv' | cut -d: -f1 | sed 's#^\./##' \
   | grep -vxF "$SELF" | grep -vxF "$PRIVATE" | grep -v '^scan-results/' > "$OUT/files.txt"

N=$(wc -l < "$OUT/files.txt")
echo "scanning $N text files under $ROOT"

FAIL=0
scan() {  # scan <severity> <name> <grep flags...> <pattern>
    local sev=$1 name=$2; shift 2
    xargs -a "$OUT/files.txt" -d '\n' grep -nHI "$@" 2>/dev/null > "$OUT/$name.txt"
    local hits files
    hits=$(wc -l < "$OUT/$name.txt"); files=$(cut -d: -f1 "$OUT/$name.txt" | sort -u | wc -l)
    printf '%-5s %-22s %4d hits %3d files\n' "$sev" "$name" "$hits" "$files"
    if [ "$hits" -gt 0 ] && [ "$sev" != LOW ]; then FAIL=1; fi
}

# ---- HIGH: identifies a real environment on its own ------------------------
scan HIGH case_ids        -E  '\b(INV|INC|CASE|TKT|SIR|TICKET|ALERT)[-_ ]?[0-9]{4,}\b'
scan HIGH tenant          -iE 'tenant'
scan HIGH vendor_urls     -iE '(secureworks\.com|taegis|ctpx\.|crowdstrike\.com/|falcon\.(us|eu)-[0-9]|humio|logscale)'
scan HIGH corp_hostnames  -E  '\b(US|UK)[A-Z]{3}[A-Z0-9]{5,}\b'
scan HIGH emails          -iP '\b[a-z0-9._%+-]+@(?!example\.|test\.|localhost|users\.noreply|noreply)[a-z0-9.-]+\.[a-z]{2,}\b'
scan HIGH user_home       -E  '(/home/[a-z]+|/mnt/[a-z]|~/[A-Za-z]|C:\\\\Users\\\\[A-Za-z]+)'
scan HIGH secrets         -iE '(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*["'"'"']?[A-Za-z0-9_\-/+]{12,}'
scan HIGH sha256          -E  '\b[0-9a-f]{64}\b'
scan HIGH uuid            -E  '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'

# ---- HIGH: organisation-specific terms supplied out-of-band -----------------
PRIV_TERMS=${IP_SCAN_PRIVATE_TERMS:-}
if [ -f "$PRIVATE" ]; then
    FILE_TERMS=$(grep -v '^\s*#' "$PRIVATE" | grep -v '^\s*$' | paste -sd '|')
    PRIV_TERMS="${PRIV_TERMS:+$PRIV_TERMS|}$FILE_TERMS"
fi
if [ -n "$PRIV_TERMS" ]; then
    scan HIGH private_terms -iE "($PRIV_TERMS)"
else
    printf '%-5s %-22s (skipped: no %s and IP_SCAN_PRIVATE_TERMS unset)\n' HIGH private_terms "$PRIVATE"
fi

# ---- MED: needs context to be harmless --------------------------------------
scan MED  rfc1918         -E  '\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})\b'
scan MED  internal_domains -iE '\b[a-z0-9-]+\.(corp|local|internal|lan|intra|priv|dmz)\b'
scan MED  domain_user     -P  '\b[A-Z][A-Z0-9-]{2,}\\\\[A-Za-z][A-Za-z0-9._-]{2,}\b'
scan MED  hostnames       -E  '\b(DESKTOP|LAPTOP|WKS|WS|PC|SRV|DC|EXCH|SQL|FS|APP|WEB|VM|HV|LT|WIN)[0-9]*-[A-Z0-9]{3,}\b'

# ---- LOW: informational -----------------------------------------------------
scan LOW  public_ip       -P  '\b(?!10\.|127\.|0\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|172\.(1[6-9]|2[0-9]|3[01])\.)([1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b'
scan LOW  realdata_words  -iE '(real[- ]?(data|telemetry|incident|case|customer|alert)|from prod|production data)'

if [ "$FAIL" -ne 0 ]; then
    echo "FAIL: HIGH/MED hits found — see $OUT/<pattern>.txt"
    grep -H . "$OUT"/{case_ids,tenant,vendor_urls,corp_hostnames,private_terms,emails,user_home,secrets,sha256,uuid,rfc1918,internal_domains,domain_user,hostnames}.txt 2>/dev/null | head -50
    exit 1
fi
echo "PASS: zero HIGH/MED hits"
