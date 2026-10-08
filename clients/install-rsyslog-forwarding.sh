#!/usr/bin/env bash
# install-rsyslog-forwarding.sh - configure a Linux host to forward its logs to Graylog over TLS.
#
# Dry-run by default: prints the rendered configuration and the steps. With --apply it
# installs the CA (and optional client certificate), writes /etc/rsyslog.d/60-graylog-tls.conf
# and the journald drop-in, validates the configuration with "rsyslogd -N1" and restarts
# rsyslog. On a validation failure the previous configuration is restored.
set -euo pipefail
umask 022

VERSION="1.0.0"
SHOW_BANNER=1
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=${GCL_ROOT:-}            # alternative filesystem root (tests, image builds)
TARGET="" PORT=6514 CA="" CERT="" KEY="" QUEUE_SIZE=1g
APPLY=0 JOURNALD=1 RESTART=1

# ---- banner (cosmetic: stderr only, interactive terminals only) -----------
# Bastion Ops Toolkit banner. Disable with --no-banner or NO_BANNER=1. Not shown when
# stderr is not a terminal (cron, pipes, systemd, monitoring agents).
banner_enabled() {
  (( SHOW_BANNER )) || return 1
  [[ -z ${NO_BANNER:-} || ${NO_BANNER} == 0 ]] || return 1
  [[ -t 2 ]]
}

print_banner() {
  banner_enabled || return 0
  {
    cat <<'WORDMARK'
                      _                          _            _
   __ _ _ _ __ _ _  _| |___  __ _ ___ __ ___ _ _| |_ _ _ __ _| |
  / _` | '_/ _` | || | / _ \/ _` |___/ _/ -_) ' \  _| '_/ _` | |
  \__, |_| \__,_|\_, |_\___/\__, |   \__\___|_||_\__|_| \__,_|_|
  |___/          |__/       |___/
   _                _
  | |___  __ _ __ _(_)_ _  __ _
  | / _ \/ _` / _` | | ' \/ _` |
  |_\___/\__, \__, |_|_||_\__, |
         |___/|___/       |___/

+====================================================================+
|  GRAYLOG CENTRAL LOGGING  ::  Log Collection & Security Alerts     |
+--------------------------------------------------------------------+
|  Graylog stack, TLS syslog forwarding, streams and alert rules     |
WORDMARK
    printf '|  %-64s  |\n' "v$VERSION  -  Bastion Ops Toolkit  -  by int3erlud3"
    printf '%s\n\n' '+====================================================================+'
  } >&2 || true
}

usage() {
  cat <<'USAGE'
Usage: install-rsyslog-forwarding.sh --target HOST --ca CA.pem [options]

  --target HOST         Graylog host name (must match the server certificate)
  --ca FILE             CA certificate that signed the Graylog server certificate
  --port N              TLS syslog port (default 6514)
  --client-cert FILE    client certificate (when the input requires client auth)
  --client-key FILE     client private key
  --queue-size SIZE     max disk queue while Graylog is unreachable (default 1g)
  --no-journald         do not install the journald ForwardToSyslog drop-in
  --no-restart          write and validate, but do not restart rsyslog
  --apply               make the changes (default: dry-run)
  --no-banner           do not print the banner (or set NO_BANNER=1)
  -h, --help | -V, --version

Exit codes: 0 success, 1 validation or restart failed (changes rolled back), 2 usage error
USAGE
}

die() { printf 'install-rsyslog-forwarding: error: %s\n' "$*" >&2; exit 2; }
fail() { printf 'install-rsyslog-forwarding: error: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case $1 in
    --target|--ca|--port|--client-cert|--client-key|--queue-size)
      [[ $# -ge 2 ]] || die "$1 needs a value"
      case $1 in
        --target) TARGET=$2 ;; --ca) CA=$2 ;; --port) PORT=$2 ;;
        --client-cert) CERT=$2 ;; --client-key) KEY=$2 ;; --queue-size) QUEUE_SIZE=$2 ;;
      esac
      shift 2 ;;
    --apply) APPLY=1; shift ;;
    --no-journald) JOURNALD=0; shift ;;
    --no-restart) RESTART=0; shift ;;
    --no-banner) SHOW_BANNER=0; shift ;;
    -h|--help) print_banner; usage; exit 0 ;;
    -V|--version) print_banner; echo "install-rsyslog-forwarding $VERSION"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

print_banner

[[ $TARGET =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "--target must be a host name"
if [[ ! $PORT =~ ^[0-9]{1,5}$ ]] || ((PORT < 1 || PORT > 65535)); then die "--port must be 1-65535"; fi
[[ $QUEUE_SIZE =~ ^[0-9]+[kmg]?$ ]] || die "--queue-size must look like 512m or 2g"
[[ -n $CA && -r $CA ]] || die "--ca must be a readable CA certificate"
grep -q 'BEGIN CERTIFICATE' "$CA" || die "--ca does not contain a PEM certificate"
if [[ -n $CERT || -n $KEY ]]; then
  [[ -r $CERT && -r $KEY ]] || die "--client-cert and --client-key must both be readable files"
  grep -q 'BEGIN CERTIFICATE' "$CERT" || die "--client-cert does not contain a PEM certificate"
  grep -q 'PRIVATE KEY' "$KEY" || die "--client-key does not contain a PEM private key"
fi
if ((APPLY)) && [[ -z $ROOT && $EUID -ne 0 ]]; then
  die "--apply needs root (run with sudo)"
fi

PKI_DIR=/etc/pki/graylog
CONF=/etc/rsyslog.d/60-graylog-tls.conf
JOURNALD_CONF=/etc/systemd/journald.conf.d/90-forward-to-syslog.conf
# Debian/Ubuntu confine rsyslogd with AppArmor; the profile only allows /etc/rsyslog.d/**,
# so the TLS material needs an explicit read rule (RHEL/SUSE SELinux already allows /etc/pki).
AA_PROFILE=/etc/apparmor.d/usr.sbin.rsyslogd
AA_SNIPPET=/etc/apparmor.d/rsyslog.d/graylog-tls
AA_LOCAL=/etc/apparmor.d/local/usr.sbin.rsyslogd
AA_RULES="# graylog-central-logging: let rsyslogd read the TLS material for forwarding
$PKI_DIR/ r,
$PKI_DIR/** r,"

render() {
  local cert_lines=""
  if [[ -n $CERT ]]; then
    cert_lines="  DefaultNetstreamDriverCertFile=\"$PKI_DIR/client.pem\"
  DefaultNetstreamDriverKeyFile=\"$PKI_DIR/client.key\"
"
  fi
  local line
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == '@CLIENT_CERT_LINES@)' ]]; then
      printf '%s)\n' "$cert_lines"
      continue
    fi
    line=${line//@CA_FILE@/$PKI_DIR/ca.pem}
    line=${line//@TARGET@/$TARGET}
    line=${line//@PORT@/$PORT}
    line=${line//@QUEUE_SIZE@/$QUEUE_SIZE}
    printf '%s\n' "$line"
  done <"$SCRIPT_DIR/rsyslog/60-graylog-tls.conf.template"
}

rendered=$(render)

if ((APPLY == 0)); then
  echo "# dry-run: the following would be installed (use --apply to make the changes)"
  echo "# $PKI_DIR/ca.pem  <- $CA"
  [[ -n $CERT ]] && echo "# $PKI_DIR/client.pem, client.key (0600)  <- $CERT, $KEY"
  ((JOURNALD)) && echo "# $JOURNALD_CONF  <- clients/journald/90-forward-to-syslog.conf"
  [[ -f $ROOT$AA_PROFILE ]] && echo "# AppArmor: read access to $PKI_DIR for rsyslogd (profile reloaded)"
  echo "# $CONF:"
  printf '%s\n' "$rendered"
  exit 0
fi

R=$ROOT
backup=$(mktemp -d)
trap 'rm -rf "$backup"' EXIT
MANAGED=("$CONF" "$JOURNALD_CONF" "$AA_SNIPPET" "$AA_LOCAL")
for f in "${MANAGED[@]}"; do
  if [[ -e $R$f ]]; then mkdir -p "$backup$(dirname "$f")"; cp -p "$R$f" "$backup$f"; fi
done

reload_apparmor() {
  [[ -f $R$AA_PROFILE && -z $ROOT ]] || return 0
  if command -v apparmor_parser >/dev/null; then
    apparmor_parser -r "$AA_PROFILE" || echo "warning: could not reload the rsyslogd AppArmor profile" >&2
  fi
}

rollback() {
  for f in "${MANAGED[@]}"; do
    if [[ -e $backup$f ]]; then cp -p "$backup$f" "$R$f"; else rm -f "$R$f"; fi
  done
  reload_apparmor
}

install -d -m 0755 "$R$PKI_DIR" "$R/etc/rsyslog.d"
install -m 0644 "$CA" "$R$PKI_DIR/ca.pem"
if [[ -n $CERT ]]; then
  install -m 0644 "$CERT" "$R$PKI_DIR/client.pem"
  install -m 0600 "$KEY" "$R$PKI_DIR/client.key"
fi
printf '%s\n' "$rendered" >"$R$CONF.tmp"
chmod 0644 "$R$CONF.tmp"
mv -f "$R$CONF.tmp" "$R$CONF"
echo "installed $CONF"
if ((JOURNALD)); then
  install -d -m 0755 "$R$(dirname "$JOURNALD_CONF")"
  install -m 0644 "$SCRIPT_DIR/journald/90-forward-to-syslog.conf" "$R$JOURNALD_CONF"
  echo "installed $JOURNALD_CONF"
fi

if [[ -f $R$AA_PROFILE ]]; then
  if grep -q 'include if exists <rsyslog.d>' "$R$AA_PROFILE"; then
    install -d -m 0755 "$R$(dirname "$AA_SNIPPET")"
    printf '%s\n' "$AA_RULES" >"$R$AA_SNIPPET"
    chmod 0644 "$R$AA_SNIPPET"
    echo "installed $AA_SNIPPET"
  elif ! grep -qF "$PKI_DIR/** r," "$R$AA_LOCAL" 2>/dev/null; then
    install -d -m 0755 "$R$(dirname "$AA_LOCAL")"
    printf '%s\n' "$AA_RULES" >>"$R$AA_LOCAL"
    echo "updated $AA_LOCAL"
  fi
  reload_apparmor
fi

if command -v rsyslogd >/dev/null; then
  if ! out=$(rsyslogd -N1 -f "${R:-}/etc/rsyslog.conf" 2>&1); then
    rollback
    printf '%s\n' "$out" >&2
    fail "rsyslogd -N1 rejected the configuration; previous files restored (is rsyslog-gnutls installed?)"
  fi
  echo "rsyslogd -N1: configuration OK"
else
  echo "warning: rsyslogd not found; install rsyslog and rsyslog-gnutls" >&2
fi

if ((RESTART)) && [[ -z $ROOT ]]; then
  ((JOURNALD)) && systemctl restart systemd-journald
  if ! systemctl restart rsyslog; then
    rollback
    systemctl restart rsyslog || true
    fail "rsyslog failed to restart; previous files restored"
  fi
  echo "rsyslog restarted; test with: logger -t gcl-test 'hello graylog'"
fi
