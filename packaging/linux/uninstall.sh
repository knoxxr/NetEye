#!/bin/sh
# Remove NetEye installed by install.sh.  --purge also deletes the data, settings and service account.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo $0" >&2; exit 1; }
if command -v dpkg >/dev/null && dpkg -s neteye >/dev/null 2>&1; then
    echo "deb 패키지로 설치되었습니다: sudo apt remove neteye (데이터까지: sudo apt purge neteye)" >&2
    exit 1
fi
if [ -d /run/systemd/system ]; then
    systemctl disable --now neteye.service 2>/dev/null || true
    rm -f /etc/systemd/system/neteye.service
    systemctl daemon-reload
fi
rm -rf /opt/neteye /usr/share/neteye
if [ "${1:-}" = "--purge" ]; then
    rm -rf /var/lib/neteye /etc/neteye
    userdel neteye 2>/dev/null || true
    groupdel neteye 2>/dev/null || true
    echo "NetEye와 데이터를 모두 지웠습니다."
else
    echo "NetEye를 지웠습니다. 데이터(/var/lib/neteye)와 설정(/etc/neteye)은 남겨 두었습니다 (--purge 로 삭제)."
fi
