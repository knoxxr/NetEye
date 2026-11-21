#!/bin/sh
# Update the IP-to-organization database and threat blocklist on macOS.
# Run: sudo /Library/NetEye/update-intel.sh && sudo launchctl kickstart -k system/com.neteye.sensor
set -eu

DATA_DIR="/Library/Application Support/NetEye"
[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo $0" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl 이 필요합니다" >&2; exit 1; }

tmp_asn=$(mktemp "$DATA_DIR/.ip2asn.XXXXXX")
tmp_bl=$(mktemp "$DATA_DIR/.blocklist.XXXXXX")
trap 'rm -f "$tmp_asn" "$tmp_bl"' EXIT

if curl -fsSL --max-time 120 -A "NetEye" https://iptoasn.com/data/ip2asn-v4.tsv.gz -o "$tmp_asn" \
   && gzip -t "$tmp_asn" 2>/dev/null \
   && [ "$(wc -c < "$tmp_asn")" -gt 1000000 ]; then
    chmod 0644 "$tmp_asn"
    mv -f "$tmp_asn" "$DATA_DIR/ip2asn-v4.tsv.gz"
    echo "IP 조직 DB 갱신 완료: $DATA_DIR/ip2asn-v4.tsv.gz"
else
    echo "IP 조직 DB 내려받기 실패 (기존 파일 유지)" >&2
fi

{
    echo "# NetEye threat blocklist (updated $(date -u +%Y-%m-%d))"
    curl -fsSL --max-time 60 -A "NetEye" https://feodotracker.abuse.ch/downloads/ipblocklist.txt 2>/dev/null \
        | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1 " # Feodo Tracker C2" }' || true
    curl -fsSL --max-time 60 -A "NetEye" https://www.spamhaus.org/drop/drop_v4.json 2>/dev/null \
        | grep -o '"cidr"[[:space:]]*:[[:space:]]*"[0-9./]*"' \
        | sed 's/.*"cidr"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1 # Spamhaus DROP/' || true
    if [ -f "$DATA_DIR/blocklist_custom.txt" ]; then
        cat "$DATA_DIR/blocklist_custom.txt"
    fi
} > "$tmp_bl"

count=$(grep -vc '^#' "$tmp_bl" || true)
if [ "$count" -gt 0 ]; then
    chmod 0644 "$tmp_bl"
    mv -f "$tmp_bl" "$DATA_DIR/blocklist.txt"
    echo "위협 목록 갱신 완료 ($count 건): $DATA_DIR/blocklist.txt"
else
    echo "위협 목록 내려받기 실패 (기존 파일 유지)" >&2
fi
