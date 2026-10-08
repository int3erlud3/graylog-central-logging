#!/usr/bin/env bash
# End-to-end test against the running docker compose stack (used by CI):
#   provisioning, syslog over TLS, GELF over TLS, stream routing, pipeline field
#   extraction, a real rsyslog client (optional) and the security alert definitions.
#
# Requires: GRAYLOG_PASSWORD_FILE (admin password, mode 0600), certs/ from gen-certs.sh,
# curl, jq, openssl. Set GCL_TEST_RSYSLOG=1 to also check a local rsyslog forwarder.
set -euo pipefail

URL=${GRAYLOG_URL:-http://127.0.0.1:9000}
CA=${GCL_TEST_CA:-certs/ca/ca.pem}
RUN_ID="it$(date +%s)"
: "${GRAYLOG_PASSWORD_FILE:?set GRAYLOG_PASSWORD_FILE}"
export GRAYLOG_PASSWORD_FILE

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }

gl() { # gl METHOD PATH [JSON]
  local auth args=(-fsS --max-time 30 -X "$1" -H 'Accept: application/json' -H 'X-Requested-By: integration-test')
  [[ $# -ge 3 ]] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  auth=$(head -n1 "$GRAYLOG_PASSWORD_FILE")
  curl "${args[@]}" -K <(printf 'user = "admin:%s"\n' "$auth") "$URL$2"
}

stream_id() { gl GET /api/streams | jq -r --arg t "$1" '.streams[] | select(.title == $t) | .id'; }

# search QUERY STREAM_ID FIELDS... -> prints matching rows as JSON objects (one per line)
search() {
  local query=$1 stream=$2; shift 2
  local fields
  fields=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  gl POST /api/search/messages "$(jq -nc --arg q "$query" --arg s "$stream" --argjson f "$fields" \
    '{query: $q, streams: (if $s == "" then [] else [$s] end), fields: $f, size: 50,
      timerange: {type: "relative", range: 900}}')" |
    jq -c '.schema as $s | .datarows[] | [$s, .] | transpose | map({key: .[0].field, value: .[1]}) | from_entries'
}

wait_for() { # wait_for DESCRIPTION SECONDS COMMAND...
  local desc=$1 secs=$2; shift 2
  local deadline=$((SECONDS + secs))
  until "$@"; do
    ((SECONDS < deadline)) || fail "$desc (timeout ${secs}s)"
    sleep 5
  done
  pass "$desc"
}

tls_send() { # tls_send PORT  (payload on stdin)
  timeout 20 openssl s_client -connect "127.0.0.1:$1" -servername localhost -verify_hostname localhost \
    -CAfile "$CA" -verify_return_error -quiet -no_ign_eof >/dev/null 2>"/tmp/s_client.$1.err" ||
    { cat "/tmp/s_client.$1.err" >&2; fail "TLS connection to port $1 failed"; }
}

# 0. Graylog silently falls back to a self-signed certificate when it cannot read the
#    mounted key, so check access from inside the container first.
if command -v docker >/dev/null && docker compose ps --status running graylog 2>/dev/null | grep -q graylog; then
  docker compose exec -T graylog sh -c 'test -r /usr/share/graylog/certs/graylog.pem && test -r /usr/share/graylog/certs/graylog.key' ||
    fail "graylog container cannot read certs/server (run gen-certs.sh server ... and chown root:1100 the key)"
  pass "graylog container can read the TLS certificate and key"
fi

# 1. Provision (inputs must come up RUNNING with the mounted certificates)
scripts/provision.sh --wait 300 --verify --no-banner
scripts/provision.sh --no-banner | grep -q '0 created' || fail "second provisioning run was not idempotent"
pass "provisioning is idempotent"

# 2. A plain-text client must not be able to talk to the TLS input
if printf 'plain\n' | timeout 5 openssl s_client -connect 127.0.0.1:6514 -servername wrong.example \
    -verify_hostname wrong.example -CAfile "$CA" -verify_return_error -quiet -no_ign_eof >/dev/null 2>&1; then
  fail "TLS input accepted a certificate name mismatch"
fi
pass "TLS input: certificate name is verified by clients"

# 3. Syslog over TLS (RFC 5424, newline framed)
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
{
  for i in 1 2 3 4 5 6; do
    printf '<38>1 %s web01 sshd 41%02d - - Failed password for invalid user %s-%d from 203.0.113.7 port 5%04d ssh2\n' \
      "$(ts)" "$i" "$RUN_ID" "$i" "$i"
  done
  printf '<85>1 %s web01 sudo - - - alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart %s\n' "$(ts)" "$RUN_ID"
  printf '<86>1 %s web01 useradd 4242 - - new user: name=%s, UID=1001, GID=1001, home=/home/%s, shell=/bin/bash\n' "$(ts)" "$RUN_ID" "$RUN_ID"
} | tls_send 6514
pass "sent 8 syslog messages over TLS"

# 4. GELF over TLS (null-byte framed)
printf '{"version":"1.1","host":"app01","short_message":"gelf over tls %s","level":6,"_run_id":"%s"}\0' "$RUN_ID" "$RUN_ID" |
  tls_send 12201
pass "sent 1 GELF message over TLS"

SSH=$(stream_id "Security: SSH authentication")
SUDO=$(stream_id "Security: privilege escalation")
ACCT=$(stream_id "Security: account management")
[[ -n $SSH && -n $SUDO && -n $ACCT ]] || fail "security streams missing"

ssh_ok() { [[ $(search "message:\"$RUN_ID\"" "$SSH" source ssh_src_ip ssh_user | jq -s 'map(select(.ssh_src_ip == "203.0.113.7" and .source == "web01")) | length') -ge 6 ]]; }
wait_for "SSH stream routing + pipeline extraction (ssh_src_ip, ssh_user)" 120 ssh_ok

sudo_ok() { search "message:\"$RUN_ID\"" "$SUDO" sudo_user sudo_command | jq -e --arg r "$RUN_ID" 'select(.sudo_user == "alice" and (.sudo_command | endswith($r)))' >/dev/null; }
wait_for "sudo stream routing + pipeline extraction (sudo_user, sudo_command)" 60 sudo_ok

acct_ok() { search "message:\"$RUN_ID\"" "$ACCT" application_name | jq -e 'select(.application_name == "useradd")' >/dev/null; }
wait_for "account management stream routing" 60 acct_ok

gelf_ok() { search "run_id:$RUN_ID" "" source | jq -e 'select(.source == "app01")' >/dev/null; }
wait_for "GELF message searchable with custom field" 60 gelf_ok

# 5. Optional: real rsyslog client forwarding over TLS (installed by CI with install-rsyslog-forwarding.sh)
if [[ ${GCL_TEST_RSYSLOG:-0} == 1 ]]; then
  logger -t sshd "Failed password for invalid user rsyslog-$RUN_ID from 198.51.100.9 port 4242 ssh2"
  rsyslog_ok() { search "message:\"rsyslog-$RUN_ID\"" "$SSH" ssh_src_ip application_name | jq -e 'select(.ssh_src_ip == "198.51.100.9")' >/dev/null; }
  wait_for "rsyslog client -> TLS -> Graylog -> SSH stream" 120 rsyslog_ok
fi

# 6. Alert events from the event definitions
defs=$(gl GET '/api/events/definitions?page=1&per_page=500' | jq -c '[.event_definitions[] | {(.id): .title}] | add')
event_titles() {
  gl POST /api/events/search '{"query":"","page":1,"per_page":200,"filter":{"alerts":"include"},"timerange":{"type":"relative","range":900}}' |
    jq -r --argjson d "$defs" '.events[].event.event_definition_id | $d[.] // empty' | sort -u
}
for want in "SSH brute force: 5+ failed logins on one host in 5 minutes" "sudo: command executed" "Account: new local user created"; do
  has_event() { event_titles | grep -Fxq -- "$want"; }
  wait_for "alert event: $want" 240 has_event
done

echo "integration: all checks passed"
