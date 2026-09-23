#!/usr/bin/env bash
# Ubuntu 22.04/24.04, fresh VPS, root, public IPv4; UTF-8, LF.
# 3x-ui v3.8.5 + VLESS/TCP/REALITY. No VPN users are created.
set -Eeuo pipefail
umask 077
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

VERSION='v3.8.5'
ACME_VERSION='3.1.6'
STATE='/etc/vpn-bootstrap'
ACME_HOME='/opt/vpn-bootstrap/acme'
ACME_CONF='/etc/vpn-bootstrap/acme'
CERT='/etc/vpn-bootstrap/cert'
MODE="${1:-install}"
STEP='preflight'
WORK=''
API_CONFIG=''

say() { printf '\n%s\n' "$*"; }
die() { printf '\nОШИБКА: %s\n' "$*" >&2; exit 1; }
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n "$WORK" && "$WORK" == /tmp/vpn-bootstrap.* && -d "$WORK" ]]; then
        rm -rf -- "$WORK"
    fi
    if (( rc != 0 )); then
        printf '\nУстановка/проверка остановлена. Этап: %s.\n' "$STEP" >&2
        printf 'Ваш SSH не перенастраивался. Не удаляйте /etc/vpn-bootstrap.\n' >&2
        if [[ -f "$STATE/state.env" ]]; then
            printf 'Исправьте причину ошибки и запустите: bash setup-vpn.sh --resume\n' >&2
        else
            printf 'Настройки ещё не сохранены. Повторите: bash setup-vpn.sh\n' >&2
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'printf "Ошибка команды на строке %s (этап %s).\n" "$LINENO" "$STEP" >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

help_text() {
    cat <<'EOF'
Запускайте на каждом новом сервере отдельно:
  bash setup-vpn.sh            установка с вопросами
  bash setup-vpn.sh --resume   продолжение прерванной установки этого скрипта
  bash setup-vpn.sh --check    локальная проверка без изменения настроек

Нужны Ubuntu 22.04/24.04, root и собственный публичный IPv4 сервера.
Порты TCP: 80 (сертификат), 443 (VPN), 2053 (панель), 2096 (подписки).
Порты 443/2053/2096 можно выбрать при установке; SSH-порт сохраняется.
В firewall провайдера откройте эти порты самостоятельно.
Пользователи и объединение подписок настраиваются затем в 3x-ui.
EOF
}

valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    ip = ipaddress.IPv4Address(sys.argv[1])
    assert ip.is_global and not ip.is_multicast
except (ValueError, AssertionError):
    sys.exit(1)
PY
}
valid_domain() {
    python3 - "$1" <<'PY'
import re, sys
s = sys.argv[1]
ok = len(s) <= 253 and '.' in s and all(
    re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x)
    for x in s.split('.'))
sys.exit(0 if ok and not s.replace('.', '').isdigit() else 1)
PY
}
ask() {
    local name=$1 prompt=$2 default=$3 _ask_input
    printf '%s [%s]: ' "$prompt" "$default" > /dev/tty
    IFS= read -r _ask_input < /dev/tty || die 'Ввод прерван.'
    printf -v "$name" '%s' "${_ask_input:-$default}"
}
ask_port() {
    local name=$1 prompt=$2 default=$3 value
    while true; do
        ask value "$prompt" "$default"
        if valid_port "$value"; then printf -v "$name" '%s' "$value"; return; fi
        say 'Введите целое число от 1 до 65535, без ведущих нулей.'
    done
}
listening() { [[ -n "$(ss -H -ltn "sport = :$1")" ]]; }
download() {
    local url=$1 dest=$2 digest=$3
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 600 --retry 3 --output "$dest" "$url"
    printf '%s  %s\n' "$digest" "$dest" | sha256sum --check --status || die "Не совпала SHA256: $dest"
}
save_state() {
    local name
    {
        for name in VERSION ARCH PUBLIC_IP SERVER_NAME SNI SSH_PORT VPN_PORT PANEL_PORT SUB_PORT USERNAME PASSWORD BASE_PATH SUB_PATH; do
            printf '%s=%q\n' "$name" "${!name}"
        done
    } > "$STATE/state.env.tmp"
    mv "$STATE/state.env.tmp" "$STATE/state.env"
}
load_state() {
    [[ -f "$STATE/state.env" && ! -L "$STATE/state.env" ]] || die 'Нет сохранённых настроек этого скрипта.'
    [[ $(stat -c '%u:%a' "$STATE/state.env") == '0:600' ]] || die 'state.env должен принадлежать root и иметь права 600.'
    # Root-owned file generated exclusively by save_state using printf %q.
    # shellcheck disable=SC1091
    source "$STATE/state.env"
    [[ "$VERSION" == 'v3.8.5' ]] || die 'Сохранена другая версия установщика.'
}
done_stage() { [[ -f "$STATE/$1.done" ]]; }
mark_stage() { touch "$STATE/$1.done"; }

prepare_firewall() {
    STEP='firewall'
    # Preserve all ports on which sshd currently accepts connections, as well as
    # the port used by this session. Put these rules ahead of possible denies.
    local p
    while read -r p; do
        if valid_port "$p"; then ufw prepend allow "$p/tcp" comment 'SSH preserved by vpn-bootstrap'; fi
    done < <({ printf '%s\n' "$SSH_PORT"; /usr/sbin/sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'; } | sort -un)
    ufw allow 80/tcp comment 'ACME IP certificate renewal'
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
}

probe_sni() {
    STEP='проверка TLS-сайта Reality'
    valid_domain "$SNI" || die 'Target/SNI должен быть именем сайта без https://, порта или пути.'
    local target_ip
    target_ip=$(getent ahostsv4 "$SNI" | awk 'NR == 1 {print $1}')
    valid_ipv4 "$target_ip" || die 'Target/SNI не разрешается в публичный IPv4.'
    [[ "$target_ip" != "$PUBLIC_IP" ]] || die 'Target/SNI не должен указывать на этот VPN-сервер.'
    if ! timeout 20 openssl s_client -connect "$target_ip:443" -servername "$SNI" \
        -tls1_3 -alpn h2 -verify_hostname "$SNI" -verify_return_error \
        -CApath /etc/ssl/certs < /dev/null > "$WORK/tls-probe.txt" 2>&1; then
        die "TLS-проверка $SNI не прошла. Выберите другой доступный TLS 1.3 сайт."
    fi
    grep -q 'ALPN protocol: h2' "$WORK/tls-probe.txt" || die "Сайт $SNI не согласовал HTTP/2. Выберите другой Target/SNI."
}

install_panel() {
    STEP='установка 3x-ui'
    local digest
    case "$ARCH" in
        amd64) digest=6a85c110a04a727613c933c54ae602b8d37dab8876c6e20a6d46623010dd9d3c ;;
        arm64) digest=2dd601a32426fb19b0eafdffaead374a9cdb66be4dfb39407f9f50fa4e7234e7 ;;
        *) die 'Неподдерживаемая архитектура.' ;;
    esac
    download "https://github.com/MHSanaei/3x-ui/releases/download/$VERSION/x-ui-linux-$ARCH.tar.gz" "$WORK/panel.tar.gz" "$digest"
    tar -xzf "$WORK/panel.tar.gz" -C "$WORK"
    [[ -s "$WORK/x-ui/x-ui" && -s "$WORK/x-ui/bin/xray-linux-$ARCH" ]] || die 'Неожиданная структура архива 3x-ui.'
    install -d -m 755 /usr/local/x-ui
    cp -a "$WORK/x-ui/." /usr/local/x-ui/
    chmod 755 /usr/local/x-ui/x-ui "/usr/local/x-ui/bin/xray-linux-$ARCH"
    download "https://raw.githubusercontent.com/MHSanaei/3x-ui/$VERSION/x-ui.sh" "$WORK/x-ui.sh" \
        7f64543f783b0939dbf803bb24b835c80edb04daca70dbcb3ecf69e2a5ce3ab5
    install -m 755 "$WORK/x-ui.sh" /usr/bin/x-ui
    download "https://raw.githubusercontent.com/MHSanaei/3x-ui/$VERSION/x-ui.service.debian" "$WORK/x-ui.service" \
        513f84fd2be16e3eec41e61acdd72c32cc639715eb4105e6dd9dc5ff190e5aec
    install -m 644 "$WORK/x-ui.service" /etc/systemd/system/x-ui.service
    install -d -m 755 /etc/systemd/system/x-ui.service.d
    cat > /etc/systemd/system/x-ui.service.d/vpn-bootstrap.conf <<'EOF'
[Service]
UMask=0077
Environment=XUI_DB_TYPE=sqlite
Environment=XUI_DB_FOLDER=/etc/x-ui
Environment=XUI_LOG_LEVEL=warning
LogRateLimitIntervalSec=30s
LogRateLimitBurst=100
EOF
    [[ "$(/usr/local/x-ui/x-ui -v)" == "${VERSION#v}" || "$(/usr/local/x-ui/x-ui -v)" == "$VERSION" ]] || die 'Версия бинарного файла не совпала.'
    systemctl daemon-reload
    mark_stage installed
}

init_panel() {
    STEP='учётные данные панели'
    cd /usr/local/x-ui
    ./x-ui setting -username "$USERNAME" -password "$PASSWORD" -port "$PANEL_PORT" \
        -webBasePath "$BASE_PATH" -listenIP 127.0.0.1 > "$STATE/cli-init.log" 2>&1
    # CLI may return zero on an internal error; API authentication below verifies it.
    mark_stage credentials
}

acme() { "$ACME_HOME/acme.sh" --home "$ACME_HOME" --config-home "$ACME_CONF" "$@"; }
install_certificate() {
    STEP='HTTPS-сертификат по IP'
    install -d -m 700 "$CERT" "$ACME_CONF"
    if [[ ! -x "$ACME_HOME/acme.sh" ]]; then
        download "https://github.com/acmesh-official/acme.sh/archive/refs/tags/$ACME_VERSION.tar.gz" "$WORK/acme.tar.gz" \
            0d3f9000ac44a6331314742a88c475f79134e24fc991997883652adc59efc486
        tar -xzf "$WORK/acme.tar.gz" -C "$WORK"
        (cd "$WORK/acme.sh-$ACME_VERSION" && ./acme.sh --install --nocron --no-profile \
            --home "$ACME_HOME" --config-home "$ACME_CONF") >> "$STATE/acme-install.log" 2>&1
    fi
    if [[ ! -s "$CERT/fullchain.pem" ]] || ! openssl x509 -in "$CERT/fullchain.pem" -noout -checkend 86400 > /dev/null; then
        listening 80 && die 'TCP 80 занят. Освободите его для выдачи сертификата.'
        say 'Получаю сертификат. TCP 80 должен быть открыт также в firewall хостинга.'
        # No --force: resume must not force repeated certificate issuance.
        local rc=0
        acme --issue --server letsencrypt --certificate-profile shortlived --days 1 \
            --keylength ec-256 -d "$PUBLIC_IP" --standalone --httpport 80 >> "$STATE/acme-install.log" 2>&1 || rc=$?
        # acme.sh exit 2 means an existing certificate is not due for renewal.
        # Still run install-cert when resuming after an interrupted copy step.
        [[ "$rc" == 0 || "$rc" == 2 ]] || die "Сертификат не получен. Проверьте TCP 80, IP и время сервера. Подробности: $STATE/acme-install.log"
        acme --install-cert -d "$PUBLIC_IP" --ecc --key-file "$CERT/privkey.pem" \
            --fullchain-file "$CERT/fullchain.pem" \
            --reloadcmd 'if systemctl is-active --quiet x-ui; then systemctl restart x-ui; fi' >> "$STATE/acme-install.log" 2>&1
    fi
    chmod 600 "$CERT/privkey.pem"
    openssl x509 -in "$CERT/fullchain.pem" -noout -checkip "$PUBLIC_IP" > /dev/null
    /usr/local/x-ui/x-ui cert -webCert "$CERT/fullchain.pem" -webCertKey "$CERT/privkey.pem" >> "$STATE/cli-init.log" 2>&1
    cat > /etc/systemd/system/vpn-cert-renew.service <<EOF
[Unit]
Description=Renew VPN panel IP certificate
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=$ACME_HOME/acme.sh --cron --home $ACME_HOME --config-home $ACME_CONF
EOF
    cat > /etc/systemd/system/vpn-cert-renew.timer <<'EOF'
[Unit]
Description=Check VPN certificate renewal twice a day
[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now vpn-cert-renew.timer
    mark_stage certificate
}

api() {
    local method=$1 path=$2
    shift 2
    curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 30 \
        --connect-to "$PUBLIC_IP:$PANEL_PORT:127.0.0.1:$PANEL_PORT" \
        --config "$API_CONFIG" --request "$method" "$@" \
        "https://$PUBLIC_IP:$PANEL_PORT${BASE_PATH}panel/api/$path" > "$WORK/response.json"
    if ! jq -e '.success == true' "$WORK/response.json" > /dev/null; then
        jq -r '.msg // "API вернул неожиданный ответ"' "$WORK/response.json" >&2
        die "Ошибка API: $path"
    fi
}
prepare_api() {
    STEP='доступ к API'
    local token i
    cd /usr/local/x-ui
    ./x-ui setting -getApiToken -tokenName vpn-bootstrap > "$WORK/token.txt" 2>&1
    token=$(awk '$1 == "apiToken:" {print $2}' "$WORK/token.txt")
    [[ "$token" =~ ^[A-Za-z0-9_-]+$ ]] || die 'Не удалось создать токен API.'
    API_CONFIG="$WORK/curl.conf"
    printf 'header = "Authorization: Bearer %s"\n' "$token" > "$API_CONFIG"
    systemctl enable x-ui
    systemctl restart x-ui
    for ((i=0; i<30; i++)); do
        if curl --silent --fail --noproxy '*' --connect-timeout 2 --max-time 3 \
            --connect-to "$PUBLIC_IP:$PANEL_PORT:127.0.0.1:$PANEL_PORT" \
            --config "$API_CONFIG" "https://$PUBLIC_IP:$PANEL_PORT${BASE_PATH}panel/api/inbounds/list" \
            -o "$WORK/ready.json" && jq -e '.success == true' "$WORK/ready.json" > /dev/null; then return; fi
        sleep 2
    done
    die 'Панель не ответила по HTTPS. Проверьте: journalctl -u x-ui -n 50 --no-pager'
}

configure_panel() {
    STEP='настройка панели и подписочного сервиса'
    api POST setting/all
    jq --arg ip "$PUBLIC_IP" --arg cert "$CERT/fullchain.pem" --arg key "$CERT/privkey.pem" \
        --arg path "$SUB_PATH" --argjson port "$SUB_PORT" \
        '.obj | .webListen="0.0.0.0" | .webDomain="" |
        .subEnable=true | .subListen="0.0.0.0" | .subPort=$port | .subDomain="" |
        .subPath=$path | .subCertFile=$cert | .subKeyFile=$key |
        .subURI=("https://"+$ip+":"+($port|tostring)+$path) |
        .subJsonEnable=false | .subJsonAutoDetect=false | .subClashEnable=false |
        .remarkTemplate="{{INBOUND}}"' "$WORK/response.json" > "$WORK/settings.json"
    api POST setting/update -H 'Content-Type: application/json' --data-binary "@$WORK/settings.json"
    mark_stage settings
}

configure_inbound() {
    STEP='VLESS + Reality'
    api GET inbounds/list
    local existing
    existing=$(jq '[.obj[] | select(.tag == "vpn-bootstrap-reality")] | length' "$WORK/response.json")
    if (( existing > 0 )); then
        [[ "$existing" == 1 ]] || die 'Найдено несколько входящих подключений с меткой установщика.'
        say 'Входящее подключение уже существует; сохраняю его ключи и клиентов.'
        mark_stage inbound
        return
    fi
    if [[ ! -s "$STATE/reality-keys.json" ]]; then
        api GET server/getNewX25519Cert
        jq -e '.obj | select(.privateKey != null and .publicKey != null)' "$WORK/response.json" > "$STATE/reality-keys.json.tmp"
        mv "$STATE/reality-keys.json.tmp" "$STATE/reality-keys.json"
    fi
    [[ -s "$STATE/short-id" ]] || openssl rand -hex 8 > "$STATE/short-id"
    jq -n --arg name "$SERVER_NAME" --argjson port "$VPN_PORT" --arg sni "$SNI" \
        --arg sid "$(cat "$STATE/short-id")" --slurpfile keys "$STATE/reality-keys.json" \
        '{remark:$name, enable:true, listen:"0.0.0.0", port:$port, protocol:"vless",
        tag:"vpn-bootstrap-reality", total:0, expiryTime:0,
        settings:{clients:[], decryption:"none", fallbacks:[]},
        streamSettings:{network:"tcp", security:"reality",
          realitySettings:{show:false, xver:0, target:($sni+":443"), serverNames:[$sni],
            privateKey:$keys[0].privateKey, shortIds:[$sid],
            settings:{publicKey:$keys[0].publicKey, fingerprint:"chrome", serverName:$sni, spiderX:"/"}},
          tcpSettings:{acceptProxyProtocol:false, header:{type:"none"}}},
        sniffing:{enabled:true, destOverride:["http","tls"], metadataOnly:false, routeOnly:true}}' > "$WORK/inbound.json"
    api POST inbounds/add -H 'Content-Type: application/json' --data-binary "@$WORK/inbound.json"
    mark_stage inbound
}

configure_logs() {
    STEP='логи Xray'
    api POST xray/
    # This API returns obj as a JSON-encoded string containing xraySetting.
    jq '.obj | if type == "string" then fromjson else . end | .xraySetting |
        .log = {access:"none", error:"", loglevel:"warning", dnsLog:false}' \
        "$WORK/response.json" > "$WORK/xray-template.json"
    jq -e 'type == "object" and (.inbounds | type == "array")' "$WORK/xray-template.json" > /dev/null
    api POST xray/update --data-urlencode "xraySetting@$WORK/xray-template.json"
    mark_stage logs
}

check_install() {
    STEP='локальная проверка'
    local p
    systemctl is-active --quiet x-ui || die 'Служба x-ui не запущена.'
    systemctl is-active --quiet vpn-cert-renew.timer || die 'Таймер обновления сертификата не запущен.'
    openssl x509 -in "$CERT/fullchain.pem" -noout -checkend 86400 > /dev/null || die 'Сертификат истёк или истекает менее чем через сутки.'
    openssl x509 -in "$CERT/fullchain.pem" -noout -checkip "$PUBLIC_IP" > /dev/null
    for p in "$VPN_PORT" "$PANEL_PORT" "$SUB_PORT"; do
        listening "$p" || die "TCP $p не прослушивается. Проверьте журнал x-ui."
    done
    curl --silent --show-error --fail --noproxy '*' --connect-timeout 5 --max-time 10 \
        --connect-to "$PUBLIC_IP:$PANEL_PORT:127.0.0.1:$PANEL_PORT" \
        "https://$PUBLIC_IP:$PANEL_PORT$BASE_PATH" -o /dev/null
    # A random subscription ID must not disclose data. 404 is the expected result.
    local code
    code=$(curl --silent --show-error --noproxy '*' --connect-timeout 5 --max-time 10 \
        --connect-to "$PUBLIC_IP:$SUB_PORT:127.0.0.1:$SUB_PORT" \
        "https://$PUBLIC_IP:$SUB_PORT${SUB_PATH}bootstrap-nonexistent" -o /dev/null -w '%{http_code}')
    [[ "$code" == 404 ]] || die "Проверка сервиса подписок вернула HTTP $code вместо 404."
    (cd /usr/local/x-ui && "./bin/xray-linux-$ARCH" run -test -config ./bin/config.json) > "$WORK/xray-test.log" 2>&1 \
        || die 'Xray отклонил конфигурацию. Проверьте journalctl -u x-ui.'
    say 'Локальные проверки пройдены. Доступность из вашей сети проверьте в HAPP после создания клиента.'
}

delete_setup_token() {
    api POST "setting/apiTokens/delete/$1" --data-urlencode 'expectedScope=admin'
}

write_summary() {
    cat > "$STATE/access.txt" <<EOF
Сервер: $SERVER_NAME
3x-ui: $VERSION
Панель: https://$PUBLIC_IP:$PANEL_PORT$BASE_PATH
Логин: $USERNAME
Пароль: $PASSWORD
VPN: $PUBLIC_IP:$VPN_PORT — VLESS + TCP/RAW + REALITY
Target/SNI: $SNI
При создании клиента выберите Flow: xtls-rprx-vision.
Пользователи пока не созданы. Ссылку подписки копируйте из карточки клиента.
Основа подписки (сама по себе НЕ является подпиской): https://$PUBLIC_IP:$SUB_PORT$SUB_PATH
TCP 80 должен оставаться доступен для автоматического продления сертификата.
Повторный просмотр: cat $STATE/access.txt
Проверка: bash setup-vpn.sh --check
EOF
    chmod 600 "$STATE/access.txt"
    cat "$STATE/access.txt"
}

main() {
    case "$MODE" in --help|-h) help_text; return ;; install|--resume|--check) ;; *) help_text; exit 2 ;; esac
    (( EUID == 0 )) || die 'Подключитесь по SSH как root.'
    [[ "$(uname -s)" == Linux && -f /etc/os-release ]] || die 'Этот скрипт запускают на Ubuntu-сервере, не на Windows.'
    local os_id os_version
    # Use subshells: os-release defines VERSION and must not overwrite the pin.
    # shellcheck disable=SC1091
    os_id=$(. /etc/os-release; printf '%s' "$ID")
    # shellcheck disable=SC1091
    os_version=$(. /etc/os-release; printf '%s' "$VERSION_ID")
    [[ "$os_id" == ubuntu && ( "$os_version" == 22.04 || "$os_version" == 24.04 ) ]] || die 'Поддерживаются только Ubuntu 22.04 и 24.04.'
    [[ -d /run/systemd/system ]] || die 'Нужен сервер с systemd.'
    exec 9>/run/vpn-bootstrap.lock
    flock -n 9 || die 'Другой экземпляр установщика уже работает.'
    WORK=$(mktemp -d /tmp/vpn-bootstrap.XXXXXXXX)
    if [[ -f "$STATE/state.env" ]]; then
        load_state
        if done_stage complete || [[ "$MODE" == --check ]]; then
            check_install
            say "Данные доступа: cat $STATE/access.txt"
            return
        fi
        [[ "$MODE" == --resume ]] || die 'Найдена незавершённая установка. Используйте --resume.'
    else
        [[ "$MODE" == install ]] || die 'Нет установки этого скрипта для продолжения/проверки.'
        for p in /usr/local/x-ui /etc/x-ui /usr/bin/x-ui /etc/default/x-ui /etc/systemd/system/x-ui.service "$STATE" "$ACME_HOME"; do
            [[ ! -e "$p" ]] || die "Найден $p. Скрипт рассчитан на пустой сервер и не перезаписывает существующую установку."
        done
        [[ -t 0 && -t 1 ]] || die 'Сначала сохраните скрипт в файл, затем запустите bash setup-vpn.sh в SSH-терминале.'
    fi
    STEP='зависимости Ubuntu'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl jq openssl python3 \
        tar gzip socat ufw iproute2 util-linux tzdata
    if [[ ! -f "$STATE/state.env" ]]; then
        case "$(uname -m)" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die 'Нужна архитектура amd64 или arm64.' ;; esac
        local ssh_server detected_ssh_port p answer
        read -r _ _ ssh_server detected_ssh_port <<< "${SSH_CONNECTION:-}"
        say "Настройка 3x-ui $VERSION. Свой домен не нужен. Откройте нужные TCP-порты в firewall хостинга."
        ask SERVER_NAME 'Название сервера, например Germany' 'Server-1'
        [[ ${#SERVER_NAME} -le 80 && ! "$SERVER_NAME" =~ [[:cntrl:]] ]] || die 'Название должно быть короче 81 символа и без управляющих символов.'
        ask PUBLIC_IP 'Публичный IPv4 именно этого сервера' "${ssh_server:-}"
        valid_ipv4 "$PUBLIC_IP" || die 'Нужен публичный IPv4. IPv6-only и общий NAT этой версией скрипта не поддерживаются.'
        ask_port SSH_PORT 'Действующий SSH-порт (скрипт его не меняет)' "${detected_ssh_port:-22}"
        if [[ -n "${detected_ssh_port:-}" && "$SSH_PORT" != "$detected_ssh_port" ]]; then
            die "Эта SSH-сессия использует порт $detected_ssh_port. Укажите именно его."
        fi
        ask_port VPN_PORT 'Порт VPN' 443
        ask_port PANEL_PORT 'Порт панели' 2053
        ask_port SUB_PORT 'Порт подписок' 2096
        [[ $(printf '%s\n' 80 "$SSH_PORT" "$VPN_PORT" "$PANEL_PORT" "$SUB_PORT" | sort -u | wc -l) == 5 ]] || die 'Порты SSH, VPN, панели, подписок и 80 должны различаться.'
        [[ "$PANEL_PORT" != 2096 ]] || die 'Для панели выберите порт, отличный от 2096: он нужен при первом запуске подписочного сервиса.'
        for p in "$VPN_PORT" "$PANEL_PORT" "$SUB_PORT"; do
            [[ "$p" != 62789 && "$p" != 11111 ]] || die 'Порты 62789 и 11111 зарезервированы для внутренних служб Xray.'
        done
        for p in 80 2096 62789 11111 "$VPN_PORT" "$PANEL_PORT" "$SUB_PORT"; do
            listening "$p" && die "TCP $p уже занят. Выберите свободный порт (80 требуется для сертификата)."
        done
        while true; do
            ask SNI 'Внешний TLS-сайт для Reality (Target/SNI)' 'www.microsoft.com'
            # Run the probe in a subshell so a failed candidate does not abort the wizard.
            if (trap - EXIT ERR; probe_sni); then break; fi
            say 'Проверка сайта не прошла. Введите другой сайт или нажмите Ctrl+C.'
        done
        say "Будут установлены 3x-ui и UFW. Разрешён SSH $SSH_PORT, TCP 80, $VPN_PORT, $PANEL_PORT, $SUB_PORT."
        ask answer 'Начать установку? yes/no' yes
        [[ "$answer" == yes ]] || die 'Установка отменена.'
        install -d -m 700 "$STATE"
        USERNAME="admin_$(openssl rand -hex 4)"
        PASSWORD=$(openssl rand -hex 18)
        BASE_PATH="/$(openssl rand -hex 12)/"
        SUB_PATH="/sub/$(openssl rand -hex 8)/"
        save_state
    fi
    if ! done_stage firewall; then prepare_firewall; mark_stage firewall; fi
    if ! done_stage installed; then install_panel; fi
    if ! done_stage credentials; then init_panel; fi
    if ! done_stage certificate; then install_certificate; fi
    prepare_api
    if ! done_stage settings; then
        configure_panel
        # Apply changed listener ports before adding the VPN inbound.
        prepare_api
    fi
    if ! done_stage inbound; then configure_inbound; fi
    if ! done_stage logs; then configure_logs; fi
    STEP='запуск VPN'
    systemctl restart x-ui
    local i
    for ((i=0; i<30; i++)); do
        if listening "$VPN_PORT" && listening "$SUB_PORT"; then break; fi
        sleep 2
    done
    check_install
    for p in "$VPN_PORT" "$PANEL_PORT" "$SUB_PORT"; do ufw allow "$p/tcp" comment 'VPN bootstrap'; done
    # Revoke the setup-only admin token. The panel password remains available.
    STEP='удаление временного API-токена'
    api GET setting/apiTokens
    local token_id
    token_id=$(jq -r '.obj[] | select(.name == "vpn-bootstrap") | .id' "$WORK/response.json")
    if [[ "$token_id" =~ ^[0-9]+$ ]]; then delete_setup_token "$token_id"; fi
    write_summary
    mark_stage complete
    say 'Готово. Теперь создайте пользователей в панели; этот же скрипт запустите на втором сервере.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main; fi
