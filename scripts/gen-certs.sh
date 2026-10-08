#!/usr/bin/env bash
# gen-certs.sh - small private CA for the Graylog TLS inputs and (optional) client certificates.
#
#   scripts/gen-certs.sh ca
#   scripts/gen-certs.sh server graylog.example.com [more SANs...]
#   scripts/gen-certs.sh client web01.example.com
#
# Output below ./certs (git-ignored): ca/ (CA key stays here), server/ (mounted into Graylog
# read-only), clients/<name>/. Private keys are created with mode 0600 (server key 0640 so the
# graylog container user can read it after: sudo chown root:1100 certs/server/graylog.key).
set -euo pipefail
umask 077

VERSION="1.0.0"
SHOW_BANNER=1
DIR=${GCL_CERT_DIR:-certs}
DAYS_CA=3650
DAYS_LEAF=825

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
Usage: scripts/gen-certs.sh [--dir DIR] [--no-banner] ca
       scripts/gen-certs.sh [--dir DIR] [--no-banner] server DNS-NAME [SAN...]
       scripts/gen-certs.sh [--dir DIR] [--no-banner] client NAME

  ca      create the CA (ECDSA P-256, 10 years); done automatically by server/client
  server  certificate for the Graylog TLS inputs; SANs may be host names or IP addresses
          (localhost and 127.0.0.1 are always added for local tests)
  client  client certificate for rsyslog when the inputs require client authentication
USAGE
}

die() { printf 'gen-certs: error: %s\n' "$*" >&2; exit 2; }
valid_name() { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }

while (($#)); do
  case $1 in
    --dir) [[ $# -ge 2 ]] || die "--dir needs a value"; DIR=$2; shift 2 ;;
    --no-banner) SHOW_BANNER=0; shift ;;
    -h|--help) print_banner; usage; exit 0 ;;
    -V|--version) print_banner; echo "gen-certs $VERSION"; exit 0 ;;
    *) break ;;
  esac
done
(($#)) || { usage >&2; exit 2; }
cmd=$1; shift
print_banner
command -v openssl >/dev/null || die "openssl is required"

ensure_ca() {
  mkdir -p "$DIR/ca"
  [[ -s $DIR/ca/ca.key ]] && return 0
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$DIR/ca/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$DIR/ca/ca.key" -sha256 -days "$DAYS_CA" \
    -subj "/CN=Graylog central logging CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$DIR/ca/ca.pem"
  chmod 600 "$DIR/ca/ca.key"; chmod 644 "$DIR/ca/ca.pem"
  echo "gen-certs: created CA $DIR/ca/ca.pem" >&2
}

issue() { # issue OUTDIR BASENAME CN EKU SAN-LIST
  local out=$1 base=$2 cn=$3 eku=$4 san=$5
  mkdir -p "$out"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/$base.key" 2>/dev/null
  openssl req -new -key "$out/$base.key" -subj "/CN=$cn" -out "$out/$base.csr"
  openssl x509 -req -in "$out/$base.csr" -CA "$DIR/ca/ca.pem" -CAkey "$DIR/ca/ca.key" \
    -CAcreateserial -days "$DAYS_LEAF" -sha256 -out "$out/$base.pem" \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$eku" "$san") 2>/dev/null
  rm -f "$out/$base.csr"
  chmod 644 "$out/$base.pem"
  openssl verify -CAfile "$DIR/ca/ca.pem" "$out/$base.pem" >/dev/null
}

san_list() {
  local list="" n
  for n in "$@" localhost 127.0.0.1; do
    if [[ $n =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then list+="IP:$n,"; else list+="DNS:$n,"; fi
  done
  printf '%s' "${list%,}"
}

case $cmd in
  ca) ensure_ca ;;
  server)
    (($#)) || die "server needs at least one DNS name"
    for n in "$@"; do valid_name "$n" || die "invalid name: $n"; done
    ensure_ca
    issue "$DIR/server" graylog "$1" serverAuth "$(san_list "$@")"
    install -m 644 "$DIR/ca/ca.pem" "$DIR/server/ca.pem"
    chmod 640 "$DIR/server/graylog.key"
    # The directory is bind-mounted into the container as-is: the graylog user (uid 1100)
    # must be able to traverse it (it holds only the public cert, the CA and the 0640 key).
    chmod 755 "$DIR/server"
    echo "gen-certs: server certificate $DIR/server/graylog.pem for: $*" >&2
    echo "gen-certs: let the graylog container (uid 1100) read the key: sudo chown root:1100 $DIR/server/graylog.key" >&2
    ;;
  client)
    [[ $# -eq 1 ]] || die "client needs exactly one name"
    valid_name "$1" || die "invalid name: $1"
    ensure_ca
    issue "$DIR/clients/$1" client "$1" clientAuth "DNS:$1"
    chmod 600 "$DIR/clients/$1/client.key"
    echo "gen-certs: client certificate in $DIR/clients/$1/ (copy client.pem, client.key and ca.pem to the host)" >&2
    ;;
  *) usage >&2; exit 2 ;;
esac
