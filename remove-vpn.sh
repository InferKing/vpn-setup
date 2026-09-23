#!/usr/bin/env bash
# Removes the installation created by setup-vpn.sh. Ubuntu/Linux only.
# DOES NOT run x-ui uninstall, source saved state, purge packages, or flush iptables.
set -Eeuo pipefail
umask 077
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RESET_UFW=0
DRY_RUN=0
STEP='проверка системы'
declare -a TARGETS=(
    /usr/local/x-ui
    /etc/x-ui
    /usr/bin/x-ui
    /etc/default/x-ui
    /etc/systemd/system/x-ui.service
    /etc/systemd/system/x-ui.service.d
    /etc/systemd/system/multi-user.target.wants/x-ui.service
    /etc/systemd/system/vpn-cert-renew.timer
    /etc/systemd/system/vpn-cert-renew.service
    /etc/systemd/system/timers.target.wants/vpn-cert-renew.timer
    /var/lib/systemd/timers/stamp-vpn-cert-renew.timer
    /var/log/x-ui
    /opt/vpn-bootstrap
    /etc/vpn-bootstrap
)

say() { printf '\n%s\n' "$*"; }
die() { printf '\nОШИБКА: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Удаление 3x-ui и данных моего setup-vpn.sh. Все VPN-клиенты, ключи,
подписки, сертификаты и настройки 3x-ui будут удалены без резервной копии.

  bash remove-vpn.sh --reset-ufw
      Удалить VPN, полностью сбросить и ОТКЛЮЧИТЬ UFW.
      Подходит для изначально пустого VPS, выделенного под этот VPN.
      Все прочие правила UFW тоже будут удалены.

  bash remove-vpn.sh
      Удалить VPN и только помеченные VPN-правила UFW.
      Состояние UFW и его политики сохраняются; SSH-правила сохраняются.

  bash remove-vpn.sh --dry-run --reset-ufw
      Показать действия, ничего не менять.

Не удаляются пакеты Ubuntu, SSH, настройки сети, общий журнал systemd,
файлы клонированного репозитория и firewall в личном кабинете хостинга.
EOF
}

valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }

allowed_path() {
    case "$1" in
        /usr/local/x-ui|/etc/x-ui|/usr/bin/x-ui|/etc/default/x-ui|\
        /etc/systemd/system/x-ui.service|/etc/systemd/system/x-ui.service.d|\
        /etc/systemd/system/multi-user.target.wants/x-ui.service|\
        /etc/systemd/system/vpn-cert-renew.timer|/etc/systemd/system/vpn-cert-renew.service|\
        /etc/systemd/system/timers.target.wants/vpn-cert-renew.timer|\
        /var/lib/systemd/timers/stamp-vpn-cert-renew.timer|\
        /var/log/x-ui|/opt/vpn-bootstrap|/etc/vpn-bootstrap) return 0 ;;
    esac
    # Only the exact mktemp naming scheme of our installer is accepted.
    [[ "$1" =~ ^/tmp/vpn-bootstrap\.[A-Za-z0-9]{8}$ ]]
}

check_path() {
    local target=$1 parent canonical mounted mounts
    allowed_path "$target" || die "Путь вне списка очистки: $target"
    parent=${target%/*}
    canonical=$(realpath -m -- "$parent")
    [[ "$canonical" == "$parent" ]] || die "Родитель пути перенаправлен через ссылку: $parent -> $canonical"
    # The final component may itself be a symlink: rm unlinks it, never its target.
    if [[ ! -L "$target" ]]; then
        mounts=$(findmnt --raw --noheadings --output TARGET) || die 'Не удалось проверить точки монтирования.'
        while IFS= read -r mounted; do
            [[ "$mounted" != "$target" && "$mounted" != "$target/"* ]] \
                || die "Внутри удаляемого пути есть точка монтирования: $mounted"
        done <<< "$mounts"
    fi
}

remove_path() {
    local target=$1
    check_path "$target"
    if [[ -e "$target" || -L "$target" ]]; then
        printf 'Удаление: %s\n' "$target"
        rm -rf --one-file-system -- "$target"
        [[ ! -e "$target" && ! -L "$target" ]] || die "Не удалось удалить $target"
    fi
}

stop_unit() {
    local unit=$1 state
    if ! state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null); then
        [[ "$state" == not-found ]] || die "Не удалось проверить состояние службы $unit"
    fi
    if [[ "$state" != not-found && -n "$state" ]]; then
        systemctl stop "$unit"
        systemctl disable "$unit"
        if systemctl is-active --quiet "$unit"; then die "Не удалось остановить $unit"; fi
        # A failed unit may have exited processes; stopping must still complete first.
        systemctl reset-failed "$unit" 2>/dev/null || true
    fi
}

is_owned_executable() {
    local executable=${1% (deleted)}
    [[ "$executable" == /usr/local/x-ui/x-ui || \
       "$executable" =~ ^/usr/local/x-ui/bin/xray-linux-(amd64|arm64|386|arm32)$ ]]
}

stop_leftover_processes() {
    local proc exe pid iteration
    local -a pids=()
    for proc in /proc/[0-9]*/exe; do
        exe=$(readlink -- "$proc" 2>/dev/null) || continue
        if is_owned_executable "$exe"; then
            pid=${proc#/proc/}; pid=${pid%/exe}
            pids+=("$pid")
            # Check again immediately before signalling, to reduce PID reuse risk.
            exe=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || continue
            is_owned_executable "$exe" && { kill -TERM "$pid" 2>/dev/null || true; }
        fi
    done
    for ((iteration=0; iteration<5; iteration++)); do
        local alive=0
        for pid in "${pids[@]}"; do
            exe=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || continue
            if is_owned_executable "$exe"; then alive=1; fi
        done
        (( alive == 1 )) || return 0
        sleep 1
    done
    for pid in "${pids[@]}"; do
        exe=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || continue
        if is_owned_executable "$exe"; then kill -KILL "$pid"; fi
    done
}

vpn_rule_port() {
    local line=$1 matched_port
    local rule_pattern="^ufw[[:space:]]+allow[[:space:]]+([0-9]{1,5})/tcp[[:space:]]+comment[[:space:]]+'(VPN bootstrap|ACME IP certificate renewal)'$"
    if [[ "$line" =~ $rule_pattern ]]; then
        matched_port=${BASH_REMATCH[1]}
        if valid_port "$matched_port"; then printf '%s\n' "$matched_port"; fi
    fi
    return 0
}

clean_firewall() {
    command -v ufw > /dev/null || return 0
    if (( RESET_UFW )); then
        # Disable first: resetting an active default-deny firewall without SSH
        # exceptions could prevent reconnection. Never flush other rule managers.
        ufw --force disable
        ufw --force reset
        ufw status
        return
    fi
    local port line ssh_server ssh_port ssh_config rules preserved keep
    local -a ssh_ports=()
    read -r _ _ ssh_server ssh_port <<< "${SSH_CONNECTION:-}"
    # Preserve both the actual SSH session port and effective sshd ports.
    if [[ -n "$ssh_server" ]] && valid_port "${ssh_port:-}"; then
        ssh_ports+=("$ssh_port")
        ufw insert 1 allow "$ssh_port/tcp" comment 'SSH retained after VPN cleanup'
    fi
    if [[ -x /usr/sbin/sshd ]]; then
        ssh_config=$(/usr/sbin/sshd -T 2>/dev/null) || die 'Не удалось прочитать SSH-порты. Правила UFW не удалены.'
        while read -r port; do
            if valid_port "$port"; then
                ssh_ports+=("$port")
                ufw insert 1 allow "$port/tcp" comment 'SSH retained after VPN cleanup'
            fi
        done < <(printf '%s\n' "$ssh_config" | awk '$1 == "port" {print $2}')
    fi
    # show added also works when UFW is inactive. Never eval its output.
    rules=$(ufw show added)
    while IFS= read -r line; do
        port=$(vpn_rule_port "$line")
        if [[ -n "$port" ]]; then
            keep=0
            for preserved in "${ssh_ports[@]}"; do
                if [[ "$port" == "$preserved" ]]; then keep=1; fi
            done
            if (( ! keep )); then ufw --force delete allow "$port/tcp"; fi
        fi
    done <<< "$rules"
    ufw status
}

main() {
    local arg target os_id
    for arg in "$@"; do
        case "$arg" in
            --reset-ufw) RESET_UFW=1 ;;
            --dry-run) DRY_RUN=1 ;;
            --help|-h) usage; return ;;
            *) die "Неизвестный параметр: $arg" ;;
        esac
    done
    [[ $(uname -s) == Linux ]] || die 'Запускайте на Linux VPS, не на Windows.'
    (( EUID == 0 )) || die 'Запускайте из SSH как root.'
    [[ -f /etc/os-release && -d /run/systemd/system ]] || die 'Нужна Ubuntu с systemd.'
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release; printf '%s' "$ID")
    [[ "$os_id" == ubuntu ]] || die 'Скрипт рассчитан на Ubuntu.'
    for arg in systemctl findmnt realpath flock find readlink rm; do
        command -v "$arg" > /dev/null || die "Не найдена команда $arg"
    done
    # Use the installer's existing lock inode. Do not delete a held lock file:
    # another process could recreate it and acquire an independent lock.
    if (( ! DRY_RUN )); then
        exec 9>/run/vpn-bootstrap.lock
        flock -n 9 || die 'Установщик ещё запущен. Дождитесь завершения или остановите его в исходном SSH-сеансе.'
    fi
    while IFS= read -r -d '' target; do
        allowed_path "$target" && TARGETS+=("$target")
    done < <(find /tmp -maxdepth 1 -mindepth 1 -user root -name 'vpn-bootstrap.????????' \
        \( -type d -o -type l \) -print0)
    # Validate EVERY target before stopping services or modifying any file.
    for target in "${TARGETS[@]}"; do check_path "$target"; done
    say 'Будут удалены все данные 3x-ui: клиенты, ключи, подписки, сертификаты и настройки.'
    for target in "${TARGETS[@]}"; do printf '  %s\n' "$target"; done
    if (( RESET_UFW )); then
        say 'UFW: полное отключение и сброс ВСЕХ его правил.'
    else
        say 'UFW: удалить только помеченные VPN-правила; сохранить SSH, политики и состояние UFW.'
    fi
    if (( DRY_RUN )); then say 'Предварительный просмотр завершён. Ничего не изменено.'; return; fi
    STEP='остановка служб'
    # Stop the timer and its running job before x-ui to prevent a renewal from
    # restarting the panel while its files are being removed.
    stop_unit vpn-cert-renew.timer
    stop_unit vpn-cert-renew.service
    stop_unit x-ui.service
    stop_leftover_processes
    STEP='firewall'
    clean_firewall
    STEP='удаление файлов'
    cd /
    for target in "${TARGETS[@]}"; do remove_path "$target"; done
    STEP='перечитывание systemd'
    systemctl daemon-reload
    for arg in x-ui.service vpn-cert-renew.timer vpn-cert-renew.service; do
        systemctl reset-failed "$arg" 2>/dev/null || true
        if systemctl is-active --quiet "$arg"; then die "Служба осталась активна: $arg"; fi
    done
    say 'Готово: 3x-ui, база клиентов, ключи, сертификаты и состояние установщика удалены.'
    say 'SSH и системные пакеты сохранены. Для новой установки используется обычный запуск, без --resume.'
    say 'Общие журналы Ubuntu, APT-кэш и файлы репозитория не удалялись.'
    if (( RESET_UFW )); then say 'UFW отключён. Внешний firewall хостинга этим скриптом не меняется.'; fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap 'printf "\nОчистка остановлена на этапе: %s (строка %s). Не все действия завершены.\n" "$STEP" "$LINENO" >&2' ERR
    main "$@"
fi
