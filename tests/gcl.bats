#!/usr/bin/env bats
# Tests for the helper scripts. The Graylog API is simulated by tests/mocks/curl;
# the real stack is exercised by the integration job in CI (tests/integration.sh).

setup() {
  ROOT="$BATS_TEST_DIRNAME/.."
  PROVISION="$ROOT/scripts/provision.sh"
  SECRETS="$ROOT/scripts/init-env.sh"
  CERTS="$ROOT/scripts/gen-certs.sh"
  INSTALL="$ROOT/clients/install-rsyslog-forwarding.sh"
  MOCKS="$BATS_TEST_DIRNAME/mocks"
  export MOCK_STATE="$BATS_TEST_TMPDIR/state"
  mkdir -p "$MOCK_STATE"
  unset NO_BANNER GRAYLOG_URL GRAYLOG_API_TOKEN GRAYLOG_API_TOKEN_FILE GRAYLOG_USERNAME \
    GRAYLOG_PASSWORD GRAYLOG_PASSWORD_FILE GRAYLOG_CA_FILE MOCK_EXISTING_INPUT MOCK_FAILED_INPUT \
    MOCK_AUTH_FAIL MOCK_FAIL_INPUT MOCK_RSYSLOG_FAIL MOCK_REQUIRE_ENTITY GCL_ROOT
  PWFILE="$BATS_TEST_TMPDIR/graylog.pw"
  printf 'Sup3r"Secret\\Pass\n' >"$PWFILE"
  chmod 600 "$PWFILE"
}

provision() { run env PATH="$MOCKS:$PATH" GRAYLOG_PASSWORD_FILE="$PWFILE" "$PROVISION" "$@" </dev/null; }
body() { cat "$MOCK_STATE/bodies/$1.json"; }

# ---- provision.sh ----------------------------------------------------------------------
@test "provision: dry-run validates definitions and prints the plan without API calls" {
  run env PATH="$MOCKS:$PATH" "$PROVISION" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"plan     input     Syslog TCP/TLS (6514)"* ]]
  [[ "$output" == *"plan     stream    Security: SSH authentication"* ]]
  [[ "$output" == *"plan     event     [P3] Account: new local user created"* ]]
  [ ! -e "$MOCK_STATE/argv.log" ]
}

@test "provision: creates inputs, streams, pipeline and event definitions" {
  provision
  [ "$status" -eq 0 ]
  [[ "$output" == *"ok       graylog   version 7.1.10+mock"* ]]
  [[ "$output" == *"provision: 16 created, 0 already present"* ]]
  [ "$(jq length "$MOCK_STATE/input.json")" -eq 4 ]
  [ "$(jq length "$MOCK_STATE/stream.json")" -eq 3 ]
  [ "$(jq length "$MOCK_STATE/rule.json")" -eq 2 ]
  [ "$(jq length "$MOCK_STATE/event.json")" -eq 6 ]
  # every stream is started
  [ "$(wc -l <"$MOCK_STATE/resumed")" -eq 3 ]
}

@test "provision: input bodies merge API defaults with our TLS settings" {
  provision --tls-client-auth required
  [ "$status" -eq 0 ]
  run body input-1
  [ "$(jq -r .type <<<"$output")" = org.graylog2.inputs.syslog.tcp.SyslogTCPInput ]
  [ "$(jq -r .global <<<"$output")" = true ]
  [ "$(jq -r .configuration.port <<<"$output")" = 6514 ]
  [ "$(jq -r .configuration.tls_enable <<<"$output")" = true ]
  [ "$(jq -r .configuration.tls_client_auth <<<"$output")" = required ]
  [ "$(jq -r .configuration.recv_buffer_size <<<"$output")" = 1048576 ]
  [ "$(jq -r '.configuration | has("override_source")' <<<"$output")" = false ]
  # UDP inputs have no TLS settings to override
  run body input-3
  [ "$(jq -r '.configuration | has("tls_enable")' <<<"$output")" = false ]
}

@test "provision: streams use the default index set and keep their rules" {
  provision --only streams
  [ "$status" -eq 0 ]
  run body stream-1
  [ "$(jq -r .index_set_id <<<"$output")" = ix-default ]
  [ "$(jq -r '.rules[0].field + "=" + .rules[0].value' <<<"$output")" = "application_name=sshd" ]
  [ ! -e "$MOCK_STATE/input.json" ]
}

@test "provision: event definitions resolve stream titles and build threshold / filter configs" {
  provision
  [ "$status" -eq 0 ]
  run body event-1
  [ "$(jq -r '.config.streams[0]' <<<"$output")" = stream-1 ]
  [ "$(jq -r '.config.series[0].type' <<<"$output")" = count ]
  [ "$(jq -r '.config.conditions.expression.expr' <<<"$output")" = ">=" ]
  [ "$(jq -r '.config.conditions.expression.right.value' <<<"$output")" = 5 ]
  [ "$(jq -r '.config.group_by[0]' <<<"$output")" = source ]
  [ "$(jq -r '.config.search_within_ms' <<<"$output")" = 300000 ]
  run body event-5
  [ "$(jq -r '.config.streams[0]' <<<"$output")" = stream-3 ]
  [ "$(jq -c '.config.series' <<<"$output")" = "[]" ]
  [ "$(jq -c '.config.conditions' <<<"$output")" = '{"expression":null}' ]
  [ "$(jq -r '.priority' <<<"$output")" = 3 ]
}

@test "provision: pipeline is built from the rule files and connected to its streams" {
  provision
  [ "$status" -eq 0 ]
  run jq -r .source "$MOCK_STATE/bodies/pipeline-1.json"
  [[ "$output" == *'pipeline "Security field extraction"'* ]]
  [[ "$output" == *'rule "extract ssh failed login fields"'* ]]
  [ "$(jq -r '.pipeline_ids[0]' "$MOCK_STATE/bodies/connection-stream-1.json")" = pipeline-1 ]
  [ "$(jq -r '.pipeline_ids[0]' "$MOCK_STATE/bodies/connection-stream-2.json")" = pipeline-1 ]
}

@test "provision: wraps shareable entities for Graylog 6+ when the server requires it" {
  MOCK_REQUIRE_ENTITY=1 provision
  [ "$status" -eq 0 ]
  [[ "$output" == *"provision: 16 created, 0 already present"* ]]
  [ "$(jq -r .index_set_id "$MOCK_STATE/bodies/stream-1.json")" = ix-default ]
  [ "$(jq -r '.config.streams[0]' "$MOCK_STATE/bodies/event-1.json")" = stream-1 ]
}

@test "provision: second run is idempotent" {
  provision
  provision
  [ "$status" -eq 0 ]
  [[ "$output" == *"provision: 0 created, 16 already present"* ]]
  [ "$(jq length "$MOCK_STATE/input.json")" -eq 4 ]
}

@test "provision: existing inputs are skipped" {
  MOCK_EXISTING_INPUT="GELF UDP (12201, local only)" provision --only inputs
  [ "$status" -eq 0 ]
  [[ "$output" == *"exists   input     GELF UDP (12201, local only)"* ]]
  [ "$(jq length "$MOCK_STATE/input.json")" -eq 3 ]
}

@test "provision: credentials go through a curl config file, never the command line" {
  provision --only streams
  [ "$status" -eq 0 ]
  [ "$(grep -c 'Secret' "$MOCK_STATE/argv.log")" -eq 0 ]
  # quotes and backslashes are escaped for curl's config syntax
  [ "$(cat "$MOCK_STATE/last-auth")" = 'user = "admin:Sup3r\"Secret\\Pass"' ]
}

@test "provision: API token is sent as <token>:token" {
  printf 'abc123token\n' >"$BATS_TEST_TMPDIR/token"; chmod 600 "$BATS_TEST_TMPDIR/token"
  run env PATH="$MOCKS:$PATH" GRAYLOG_API_TOKEN_FILE="$BATS_TEST_TMPDIR/token" "$PROVISION" --only streams
  [ "$status" -eq 0 ]
  [ "$(cat "$MOCK_STATE/last-auth")" = 'user = "abc123token:token"' ]
}

@test "provision: refuses plain http to a remote host" {
  run env PATH="$MOCKS:$PATH" GRAYLOG_URL=http://graylog.example.com:9000 GRAYLOG_PASSWORD_FILE="$PWFILE" "$PROVISION"
  [ "$status" -eq 2 ]
  [[ "$output" == *"refusing to send credentials over plain http"* ]]
  [ ! -e "$MOCK_STATE/argv.log" ]
}

@test "provision: refuses a group/world-readable secret file" {
  chmod 644 "$PWFILE"
  provision
  [ "$status" -eq 2 ]
  [[ "$output" == *"chmod 600"* ]]
}

@test "provision: no credentials and no terminal -> exit 2" {
  run env PATH="$MOCKS:$PATH" "$PROVISION" </dev/null
  [ "$status" -eq 2 ]
  [[ "$output" == *"no credentials"* ]]
}

@test "provision: credentials are not accepted as arguments" {
  run "$PROVISION" --password secret
  [ "$status" -eq 2 ]
  [[ "$output" == *"credentials are read from the environment"* ]]
}

@test "provision: authentication failure -> exit 1" {
  MOCK_AUTH_FAIL=1 provision
  [ "$status" -eq 1 ]
  [[ "$output" == *"authentication failed (HTTP 401)"* ]]
}

@test "provision: API errors are reported with the Graylog message" {
  MOCK_FAIL_INPUT=1 provision --only inputs
  [ "$status" -eq 1 ]
  [[ "$output" == *"POST /api/system/inputs failed with HTTP 400: Missing configuration field"* ]]
}

@test "provision: --verify fails when an input is not RUNNING" {
  MOCK_FAILED_INPUT="GELF TCP/TLS (12201)" GCL_VERIFY_RETRIES=1 run env PATH="$MOCKS:$PATH" GRAYLOG_PASSWORD_FILE="$PWFILE" \
    "$PROVISION" --only inputs --verify
  [ "$status" -eq 1 ]
  [[ "$output" == *"FAILED   input     GELF TCP/TLS (12201)"* ]]
}

@test "provision: --verify passes when all inputs run" {
  provision --only inputs --verify
  [ "$status" -eq 0 ]
  [[ "$output" == *"verify: all inputs RUNNING"* ]]
}

@test "provision: invalid options" {
  run "$PROVISION" --tls-client-auth maybe
  [ "$status" -eq 2 ]
  run "$PROVISION" --only inputs,dashboards
  [ "$status" -eq 2 ]
}

# ---- init-env.sh --------------------------------------------------------------------
@test "init-env: writes a 0600 .env with a SHA-256 of the admin password only" {
  printf 'correct horse battery staple\n' | "$SECRETS" --env-file "$BATS_TEST_TMPDIR/.env"
  f="$BATS_TEST_TMPDIR/.env"
  [ "$(stat -c %a "$f")" = 600 ]
  expected=$(printf '%s' 'correct horse battery staple' | sha256sum | cut -d' ' -f1)
  grep -qx "GRAYLOG_ROOT_PASSWORD_SHA2=$expected" "$f"
  [ "$(grep -c 'correct horse' "$f")" -eq 0 ]
  [ "$(sed -n 's/^GRAYLOG_PASSWORD_SECRET=//p' "$f" | tr -d '\n' | wc -c)" -eq 96 ]
  grep -Eq '^MONGODB_GRAYLOG_PASSWORD=[A-Za-z0-9]{40}$' "$f"
  # every variable from .env.example is present
  while IFS= read -r var; do grep -q "^$var=" "$f"; done < <(sed -n 's/^\([A-Z_]*\)=.*/\1/p' "$ROOT/.env.example")
}

@test "init-env: refuses to overwrite and rejects short passwords" {
  printf 'correct horse battery staple\n' | "$SECRETS" --env-file "$BATS_TEST_TMPDIR/.env"
  run bash -c "printf 'another long password\n' | '$SECRETS' --env-file '$BATS_TEST_TMPDIR/.env'"
  [ "$status" -eq 2 ]
  [[ "$output" == *"already exists"* ]]
  run bash -c "printf 'short\n' | '$SECRETS' --env-file '$BATS_TEST_TMPDIR/new.env'"
  [ "$status" -eq 2 ]
  [ ! -e "$BATS_TEST_TMPDIR/new.env" ]
}

# ---- gen-certs.sh ----------------------------------------------------------------------
@test "gen-certs: server and client certificates chain to the CA with the right SANs and EKUs" {
  d="$BATS_TEST_TMPDIR/certs"
  run "$CERTS" --dir "$d" server graylog.example.test 192.0.2.10
  [ "$status" -eq 0 ]
  openssl verify -CAfile "$d/ca/ca.pem" "$d/server/graylog.pem"
  run openssl x509 -in "$d/server/graylog.pem" -noout -ext subjectAltName,extendedKeyUsage
  [[ "$output" == *"DNS:graylog.example.test"* ]]
  [[ "$output" == *"IP Address:192.0.2.10"* ]]
  [[ "$output" == *"TLS Web Server Authentication"* ]]
  [ "$(stat -c %a "$d/ca/ca.key")" = 600 ]
  [ "$(stat -c %a "$d/server/graylog.key")" = 640 ]
  [ ! -e "$d/server/ca.key" ]
  "$CERTS" --dir "$d" client web01.example.test
  run openssl x509 -in "$d/clients/web01.example.test/client.pem" -noout -ext extendedKeyUsage
  [[ "$output" == *"TLS Web Client Authentication"* ]]
  [ "$(stat -c %a "$d/clients/web01.example.test/client.key")" = 600 ]
  # the key is PKCS#8 as Graylog requires
  openssl pkey -in "$d/server/graylog.key" -noout
  head -n1 "$d/server/graylog.key" | grep -q 'BEGIN PRIVATE'
}

@test "gen-certs: rejects invalid names" {
  run "$CERTS" --dir "$BATS_TEST_TMPDIR/c" server 'bad name;rm'
  [ "$status" -eq 2 ]
  run "$CERTS" --dir "$BATS_TEST_TMPDIR/c" client
  [ "$status" -eq 2 ]
}

# ---- install-rsyslog-forwarding.sh -----------------------------------------------------
make_pki() {
  "$CERTS" --dir "$BATS_TEST_TMPDIR/pki" server graylog.example.test >/dev/null 2>&1
  "$CERTS" --dir "$BATS_TEST_TMPDIR/pki" client web01 >/dev/null 2>&1
  CA="$BATS_TEST_TMPDIR/pki/ca/ca.pem"
}

@test "client installer: dry-run renders a verified TLS forwarding config" {
  make_pki
  run "$INSTALL" --target graylog.example.test --ca "$CA" --port 6514
  [ "$status" -eq 0 ]
  [[ "$output" == *"dry-run"* ]]
  [[ "$output" == *'target="graylog.example.test"'* ]]
  [[ "$output" == *'StreamDriverMode="1"'* ]]
  [[ "$output" == *'StreamDriverAuthMode="x509/name"'* ]]
  [[ "$output" == *'StreamDriverPermittedPeers="graylog.example.test"'* ]]
  [[ "$output" == *'DefaultNetstreamDriverCAFile="/etc/pki/graylog/ca.pem"'* ]]
  [[ "$output" != *"DefaultNetstreamDriverCertFile"* ]]
  [[ "$output" != *"@"[A-Z_]*"@"* ]]
}

@test "client installer: client certificate lines for mutual TLS" {
  make_pki
  run "$INSTALL" --target graylog.example.test --ca "$CA" \
    --client-cert "$BATS_TEST_TMPDIR/pki/clients/web01/client.pem" --client-key "$BATS_TEST_TMPDIR/pki/clients/web01/client.key"
  [ "$status" -eq 0 ]
  [[ "$output" == *'DefaultNetstreamDriverCertFile="/etc/pki/graylog/client.pem"'* ]]
  [[ "$output" == *'DefaultNetstreamDriverKeyFile="/etc/pki/graylog/client.key"'* ]]
}

@test "client installer: --apply installs files with safe modes and validates with rsyslogd -N1" {
  make_pki
  r="$BATS_TEST_TMPDIR/root"
  run env PATH="$MOCKS:$PATH" GCL_ROOT="$r" "$INSTALL" --target graylog.example.test --ca "$CA" \
    --client-cert "$BATS_TEST_TMPDIR/pki/clients/web01/client.pem" --client-key "$BATS_TEST_TMPDIR/pki/clients/web01/client.key" --apply
  [ "$status" -eq 0 ]
  [[ "$output" == *"rsyslogd -N1: configuration OK"* ]]
  [ "$(stat -c %a "$r/etc/rsyslog.d/60-graylog-tls.conf")" = 644 ]
  [ "$(stat -c %a "$r/etc/pki/graylog/client.key")" = 600 ]
  grep -q '^ForwardToSyslog=yes' "$r/etc/systemd/journald.conf.d/90-forward-to-syslog.conf"
  grep -q -- '-N1' "$MOCK_STATE/rsyslogd.log"
}

@test "client installer: failed validation restores the previous configuration" {
  make_pki
  r="$BATS_TEST_TMPDIR/root"
  mkdir -p "$r/etc/rsyslog.d"
  echo "# previous config" >"$r/etc/rsyslog.d/60-graylog-tls.conf"
  run env PATH="$MOCKS:$PATH" GCL_ROOT="$r" MOCK_RSYSLOG_FAIL=1 "$INSTALL" --target graylog.example.test --ca "$CA" --apply
  [ "$status" -eq 1 ]
  [[ "$output" == *"previous files restored"* ]]
  [ "$(cat "$r/etc/rsyslog.d/60-graylog-tls.conf")" = "# previous config" ]
  [ ! -e "$r/etc/systemd/journald.conf.d/90-forward-to-syslog.conf" ]
}

@test "client installer: AppArmor read rule for the TLS material on Debian/Ubuntu" {
  make_pki
  r="$BATS_TEST_TMPDIR/root"
  mkdir -p "$r/etc/apparmor.d"
  printf 'profile rsyslogd /usr/sbin/rsyslogd {\n  include if exists <rsyslog.d>\n}\n' >"$r/etc/apparmor.d/usr.sbin.rsyslogd"
  run env PATH="$MOCKS:$PATH" GCL_ROOT="$r" "$INSTALL" --target graylog.example.test --ca "$CA" --apply
  [ "$status" -eq 0 ]
  grep -qx '/etc/pki/graylog/\*\* r,' "$r/etc/apparmor.d/rsyslog.d/graylog-tls"
  # failed validation removes the rule again
  rm -rf "$r/etc/rsyslog.d" "$r/etc/apparmor.d/rsyslog.d"
  run env PATH="$MOCKS:$PATH" GCL_ROOT="$r" MOCK_RSYSLOG_FAIL=1 "$INSTALL" --target graylog.example.test --ca "$CA" --apply
  [ "$status" -eq 1 ]
  [ ! -e "$r/etc/apparmor.d/rsyslog.d/graylog-tls" ]
}

@test "client installer: older AppArmor profiles get the rule in local/ once" {
  make_pki
  r="$BATS_TEST_TMPDIR/root"
  mkdir -p "$r/etc/apparmor.d"
  printf 'profile rsyslogd /usr/sbin/rsyslogd {\n  #include <local/usr.sbin.rsyslogd>\n}\n' >"$r/etc/apparmor.d/usr.sbin.rsyslogd"
  for _ in 1 2; do
    run env PATH="$MOCKS:$PATH" GCL_ROOT="$r" "$INSTALL" --target graylog.example.test --ca "$CA" --apply
    [ "$status" -eq 0 ]
  done
  [ "$(grep -c '/etc/pki/graylog/\*\* r,' "$r/etc/apparmor.d/local/usr.sbin.rsyslogd")" -eq 1 ]
}

@test "client installer: input validation" {
  make_pki
  run "$INSTALL" --target 'x;y' --ca "$CA"
  [ "$status" -eq 2 ]
  run "$INSTALL" --target graylog.example.test --ca /nonexistent
  [ "$status" -eq 2 ]
  run "$INSTALL" --target graylog.example.test --ca "$CA" --port 70000
  [ "$status" -eq 2 ]
  run "$INSTALL" --target graylog.example.test --ca "$CA" --client-cert "$CA"
  [ "$status" -eq 2 ]
}

# ---- banner ----------------------------------------------------------------------------
on_tty() {
  command -v script >/dev/null || skip "script(1) not available"
  run script -qefc "$(printf '%q ' "$@")" /dev/null </dev/null
}

@test "banner is printed on an interactive terminal, by every script" {
  for s in "$PROVISION" "$SECRETS" "$CERTS" "$INSTALL"; do
    on_tty "$s" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"Bastion Ops Toolkit"* ]]
    [[ "$output" == *"GRAYLOG CENTRAL LOGGING"* ]]
  done
}

@test "banner is not printed when stderr is not a terminal" {
  run "$PROVISION" --dry-run
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
}

@test "--no-banner and NO_BANNER=1 suppress the banner on a terminal" {
  on_tty "$PROVISION" --dry-run --no-banner
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty env NO_BANNER=1 "$PROVISION" --dry-run
  [[ "$output" != *"Bastion Ops Toolkit"* ]]
  on_tty env NO_BANNER=0 "$PROVISION" --dry-run
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
}

@test "--help shows the banner on a terminal; --version is plain otherwise" {
  on_tty "$PROVISION" --help
  [[ "$output" == *"Bastion Ops Toolkit"* ]]
  run "$PROVISION" --version
  [ "$output" = "provision 1.0.0" ]
}

@test "README banner matches the runtime banner" {
  on_tty "$PROVISION" --version
  expected=$(awk -v fence='```' '$0 == fence "text" { on = 1; next } on && $0 == fence { exit } on' "$ROOT/README.md")
  actual=$(printf '%s\n' "$output" | tr -d '\r')
  [ -n "$expected" ]
  [[ "$actual" == "$expected"* ]]
}
