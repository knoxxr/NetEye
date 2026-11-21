#!/bin/sh
# Uninstall NetEye on macOS. Pass --purge to also remove database, settings, and logs.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo $0" >&2; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

launchctl bootout system/com.neteye.sensor 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.neteye.sensor.plist
rm -rf /Library/NetEye

if [ "$PURGE" -eq 1 ]; then
    rm -rf "/Library/Application Support/NetEye" /Library/Logs/NetEye
    echo "NetEye 프로그램과 모든 데이터를 삭제했습니다."
else
    echo "NetEye 프로그램을 삭제했습니다 (데이터·설정은 '/Library/Application Support/NetEye' 에 남아 있습니다)."
fi
