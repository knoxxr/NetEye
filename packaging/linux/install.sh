#!/bin/sh
# NetEye installer for Linux (x86-64, glibc 2.17+: Ubuntu, Debian, RHEL/Rocky/Alma, SUSE ...).
#
#   sudo ./install.sh                       interactive: pick the capture interface
#   sudo ./install.sh -y --interface eth1   unattended
#   options: --interface IF   --listen ADDR (default 127.0.0.1)   --port N (default 8000)
#            --no-start   --no-intel (skip downloading the IP database / threat list)   -y
#
# Installs libpcap with the system package manager, the sensor under /opt/neteye, settings in
# /etc/neteye, data in /var/lib/neteye, and the "neteye" systemd service running as its own user
# with only the packet-capture capabilities.
set -eu
cd "$(dirname "$0")"

IFACE="" LISTEN="" PORT="" START=1 INTEL=1 YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --interface) IFACE="$2"; shift 2 ;;
        --listen) LISTEN="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --no-start) START=0; shift ;;
        --no-intel) INTEL=0; shift ;;
        -y|--yes) YES=1; shift ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo $0" >&2; exit 1; }
[ "$(uname -m)" = "x86_64" ] || { echo "x86-64 시스템만 지원합니다 ($(uname -m))" >&2; exit 1; }

echo "[1/5] libpcap 확인"
if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so'; then
    if command -v apt-get >/dev/null; then
        apt-get update -qq && (apt-get install -y -qq libpcap0.8t64 2>/dev/null || apt-get install -y -qq libpcap0.8)
    elif command -v dnf >/dev/null; then dnf install -y -q libpcap
    elif command -v yum >/dev/null; then yum install -y -q libpcap
    elif command -v zypper >/dev/null; then zypper --non-interactive install libpcap1
    else echo "libpcap을 직접 설치하세요 (패킷 수집에 필요)" >&2
    fi
fi
command -v curl >/dev/null || INTEL=0

echo "[2/5] 파일 설치"
if [ -d /run/systemd/system ] && systemctl is-active --quiet neteye 2>/dev/null; then
    systemctl stop neteye
fi
install -d /opt/neteye /opt/neteye/frontend /usr/share/neteye/data
install -m 0755 payload/neteye payload/bangdb payload/update-intel.sh payload/uninstall.sh /opt/neteye/
cp -R payload/frontend/. /opt/neteye/frontend/
install -m 0644 payload/README.md payload/THIRD-PARTY.txt /opt/neteye/
install -m 0644 payload/neteye.conf /usr/share/neteye/neteye.conf
install -m 0644 payload/data/* /usr/share/neteye/data/
install -m 0644 payload/setup-common.sh /usr/share/neteye/setup-common.sh
if [ -d /run/systemd/system ]; then
    install -m 0644 payload/neteye.service /etc/systemd/system/neteye.service
fi

echo "[3/5] 서비스 계정·데이터 폴더"
. /usr/share/neteye/setup-common.sh
neteye_prepare
[ -n "$LISTEN" ] && neteye_set NETEYE_HOST "$LISTEN"
[ -n "$PORT" ] && neteye_set NETEYE_PORT "$PORT"

echo "[4/5] 수집 인터페이스"
if [ -z "$IFACE" ] && [ "$YES" -eq 0 ] && [ -t 0 ]; then
    list=$(/opt/neteye/neteye interfaces 2>/dev/null | cut -f1 | grep -v '^any$' | grep -v '^lo$' || true)
    if [ -n "$list" ]; then
        echo "미러링(SPAN) 포트에 연결된 랜카드를 고르세요 (Enter: 나중에 대시보드에서 선택)"
        i=1; for n in $list; do echo "  $i) $n"; i=$((i + 1)); done
        printf "번호: "; read -r pick || pick=""
        if [ -n "$pick" ]; then IFACE=$(echo "$list" | sed -n "${pick}p"); fi
    fi
fi
[ -n "$IFACE" ] && neteye_set NETEYE_INTERFACE "$IFACE" && echo "  수집 인터페이스: $IFACE"

if [ "$INTEL" -eq 1 ]; then
    echo "  IP 조직 DB·위협 목록 내려받는 중 (실패해도 설치는 계속됩니다)"
    /opt/neteye/update-intel.sh || true
fi

echo "[5/5] 서비스 시작"
if [ "$START" -eq 1 ]; then
    fresh=""
    [ -f /var/lib/neteye/neteye.bdb ] || fresh=wait
    neteye_start
    neteye_show_password $fresh
else
    echo "서비스를 시작하지 않았습니다: sudo systemctl enable --now neteye"
fi
