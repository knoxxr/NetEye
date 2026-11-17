#!/bin/sh
# NetEye: refresh the IP-to-organisation database and the threat list (run as root or the neteye user).
#   IP-to-ASN: iptoasn.com (Public Domain, PDDL v1.0)
#   Threat list: abuse.ch Feodo Tracker C2 (CC0) + Spamhaus DROP, plus /etc/neteye/blocklist_custom.txt
# The service reads the files at start: systemctl restart neteye
set -eu
# The data folder belongs to the service account: never write into it as root (a planted link
# could redirect a root-owned write). Root re-runs this script as the neteye user.
if [ "$(id -u)" -eq 0 ] && id neteye >/dev/null 2>&1; then
    if command -v runuser >/dev/null; then exec runuser -u neteye -- /bin/sh "$0" "$@"; fi
    if command -v setpriv >/dev/null; then exec setpriv --reuid=neteye --regid=neteye --init-groups /bin/sh "$0" "$@"; fi
    exec su -s /bin/sh neteye -c "/bin/sh '$0'"
fi
DATA="${NETEYE_DATA:-/var/lib/neteye}"
UA="NetEye-intel-updater"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { curl -fsSL --max-time 120 -A "$UA" -o "$2" "$1"; }
# Replace a data file atomically: copy next to it, then rename over it (rename replaces a link
# itself rather than writing through it).
replace() { cp "$1" "$DATA/.$2.new" && chmod 0644 "$DATA/.$2.new" && mv -f "$DATA/.$2.new" "$DATA/$2"; }

if fetch https://iptoasn.com/data/ip2asn-v4.tsv.gz "$TMP/asn.gz" && gzip -t "$TMP/asn.gz"; then
    replace "$TMP/asn.gz" ip2asn-v4.tsv.gz
    echo "IP 조직 DB 갱신: $DATA/ip2asn-v4.tsv.gz"
else
    echo "IP 조직 DB를 받지 못했습니다 (기존 파일 유지)" >&2
fi

{
    echo "# NetEye threat list, built $(date -u '+%Y-%m-%d %H:%M') UTC"
    echo "# address[/prefix]  # source"
    if fetch https://feodotracker.abuse.ch/downloads/ipblocklist.txt "$TMP/feodo.txt"; then
        tr -d '\r' < "$TMP/feodo.txt" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/$/  # Feodo Tracker/' || true
    fi
    if fetch https://www.spamhaus.org/drop/drop_v4.json "$TMP/drop.json"; then
        grep -o '"cidr":"[0-9./]*"' "$TMP/drop.json" | cut -d'"' -f4 | sed 's/$/  # Spamhaus DROP/'
    fi
    if [ -f /etc/neteye/blocklist_custom.txt ]; then
        grep -v '^[[:space:]]*#' /etc/neteye/blocklist_custom.txt | grep -v '^[[:space:]]*$' || true
    fi
} > "$TMP/blocklist.txt"
if [ "$(grep -vc '^#' "$TMP/blocklist.txt")" -gt 0 ]; then
    replace "$TMP/blocklist.txt" blocklist.txt
    echo "위협 목록 갱신: $DATA/blocklist.txt ($(grep -vc '^#' "$TMP/blocklist.txt")건)"
else
    echo "위협 목록을 받지 못했습니다 (기존 파일 유지)" >&2
fi
