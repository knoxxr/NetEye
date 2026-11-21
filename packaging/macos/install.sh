#!/bin/sh
# NetEye tarball installer for macOS (Apple Silicon & Intel Universal).
#   sudo ./install.sh
set -eu
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo $0" >&2; exit 1; }

launchctl bootout system/com.neteye.sensor 2>/dev/null || true

install -d /Library/NetEye /Library/NetEye/frontend /Library/NetEye/defaults
install -m 0755 payload/neteye payload/bangdb payload/update-intel.sh payload/uninstall.sh /Library/NetEye/
cp -R payload/frontend/. /Library/NetEye/frontend/
install -m 0644 payload/README.md payload/THIRD-PARTY.txt /Library/NetEye/
install -m 0644 payload/neteye.conf /Library/NetEye/defaults/neteye.conf
install -m 0644 payload/data/* /Library/NetEye/defaults/
install -m 0644 payload/com.neteye.sensor.plist /Library/LaunchDaemons/com.neteye.sensor.plist

sh scripts/postinstall

f="/Library/Application Support/NetEye/initial-admin-password.txt"
i=0
while [ ! -f "$f" ] && [ $i -lt 20 ]; do sleep 1; i=$((i + 1)); done

echo
echo "================================================================"
echo " NetEye macOS 설치 완료:  http://127.0.0.1:8000/"
if [ -f "$f" ]; then
    echo " 초기 관리자 계정 (첫 로그인 때 비밀번호를 바꿔야 합니다):"
    sed -n 's/^/   /;1,2p' "$f"
    echo " (파일 위치: $f)"
fi
echo " 설정: /Library/Application Support/NetEye/neteye.conf"
echo " 로그: /Library/Logs/NetEye/neteye.log"
echo "================================================================"
