# Shared by install.sh and the .deb maintainer scripts (sourced, POSIX sh).
# Creates the service account, data folder and settings, and starts the service.

neteye_as_service() {  # run a command as the neteye account
    if command -v runuser >/dev/null; then runuser -u neteye -- "$@"
    elif command -v setpriv >/dev/null; then setpriv --reuid=neteye --regid=neteye --init-groups "$@"
    else su -s /bin/sh neteye -c "$*"
    fi
}

neteye_prepare() {
    if ! getent group neteye >/dev/null; then
        groupadd --system neteye
    fi
    if ! getent passwd neteye >/dev/null; then
        useradd --system --gid neteye --home-dir /var/lib/neteye --no-create-home \
                --shell /usr/sbin/nologin --comment "NetEye sensor" neteye
    fi
    install -d -m 0750 -o neteye -g neteye /var/lib/neteye
    install -d -m 0770 -o root -g neteye /etc/neteye
    if [ ! -f /etc/neteye/neteye.conf ]; then
        install -m 0660 -o root -g neteye /usr/share/neteye/neteye.conf /etc/neteye/neteye.conf
    fi
    # Offline data shipped with the package; never replaces newer files (updated by update-intel).
    # Written as the service account: root never writes into the folder neteye controls.
    for f in vulndb.json ip2asn-v4.tsv.gz; do
        if [ -f "/usr/share/neteye/data/$f" ]; then
            neteye_as_service sh -c "[ -e '/var/lib/neteye/$f' ] || { cp '/usr/share/neteye/data/$f' '/var/lib/neteye/.$f.new' && mv -f '/var/lib/neteye/.$f.new' '/var/lib/neteye/$f'; }"
        fi
    done
}

neteye_set() {  # neteye_set KEY VALUE: set one key in the settings file
    if grep -q "^$1=" /etc/neteye/neteye.conf; then
        sed -i "s|^$1=.*|$1=$2|" /etc/neteye/neteye.conf
    else
        printf '%s=%s\n' "$1" "$2" >> /etc/neteye/neteye.conf
    fi
}

neteye_start() {
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable neteye.service >/dev/null 2>&1 || true
        systemctl restart neteye.service
    else
        echo "systemd가 없어 서비스를 등록하지 않았습니다. 직접 실행: sudo -u neteye NETEYE_CONFIG=/etc/neteye/neteye.conf /opt/neteye/neteye serve"
    fi
}

neteye_show_password() {  # neteye_show_password [wait]: wait for the first-start password file
    f=/var/lib/neteye/initial-admin-password.txt
    i=0
    while [ "${1:-}" = "wait" ] && [ ! -f "$f" ] && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
    port=$(sed -n 's/^NETEYE_PORT=//p' /etc/neteye/neteye.conf); port=${port:-8000}
    echo
    echo "================================================================"
    echo " NetEye 설치 완료:  http://127.0.0.1:${port}/"
    if [ -f "$f" ]; then
        echo " 초기 관리자 계정 (첫 로그인 때 비밀번호를 바꿔야 합니다):"
        sed -n 's/^/   /;1,2p' "$f"
        echo " (이 내용은 $f 에도 있습니다. root만 읽을 수 있습니다)"
    fi
    echo " 설정: /etc/neteye/neteye.conf   로그: journalctl -u neteye"
    echo "================================================================"
}
