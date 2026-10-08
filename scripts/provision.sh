#!/usr/bin/env bash
# provision.sh - create Graylog inputs, streams, pipelines and security alert definitions
# from the JSON definitions in provisioning/ through the Graylog REST API.
#
# Idempotent: objects that already exist (same title) are left untouched.
# Credentials come from the environment only (never from arguments):
#   GRAYLOG_API_TOKEN_FILE / GRAYLOG_API_TOKEN               (preferred), or
#   GRAYLOG_USERNAME + GRAYLOG_PASSWORD_FILE / GRAYLOG_PASSWORD (username defaults to admin);
#   with neither set and a terminal attached, the password is prompted for.
set -euo pipefail
umask 077

VERSION="1.0.0"
SHOW_BANNER=1
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEFS=${GCL_DEFS_DIR:-$SCRIPT_DIR/../provisioning}
URL=${GRAYLOG_URL:-http://127.0.0.1:9000}
DRY_RUN=0
WAIT=0
VERIFY=0
TLS_CLIENT_AUTH=disabled
ONLY="inputs,streams,pipelines,events"
REQUESTED_BY="graylog-central-logging"

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
Usage: scripts/provision.sh [options]

Options:
  --dry-run                 validate the definitions and show the plan; no API calls
  --only LIST               comma-separated subset of: inputs,streams,pipelines,events
  --tls-client-auth MODE    disabled (default) | optional | required  (TLS inputs)
  --wait SECONDS            wait up to SECONDS for Graylog to report ALIVE first
  --verify                  after provisioning, check that every input is RUNNING
  --no-banner               do not print the banner (or set NO_BANNER=1)
  -h, --help | -V, --version

Environment:
  GRAYLOG_URL               default http://127.0.0.1:9000 (plain http only for localhost)
  GRAYLOG_CA_FILE           CA bundle for a private CA (TLS verification is always on)
  GRAYLOG_API_TOKEN_FILE, GRAYLOG_API_TOKEN
  GRAYLOG_USERNAME, GRAYLOG_PASSWORD_FILE, GRAYLOG_PASSWORD

Exit codes: 0 success, 1 API or verification error, 2 usage or configuration error
USAGE
}

die() { printf 'provision: error: %s\n' "$*" >&2; exit 2; }
fail() { printf 'provision: error: %s\n' "$*" >&2; exit 1; }
log() { printf '%-8s %-9s %s\n' "$1" "$2" "$3"; }

while (($#)); do
  case $1 in
    --dry-run) DRY_RUN=1; shift ;;
    --verify) VERIFY=1; shift ;;
    --only) [[ $# -ge 2 ]] || die "--only needs a value"; ONLY=$2; shift 2 ;;
    --tls-client-auth) [[ $# -ge 2 ]] || die "--tls-client-auth needs a value"; TLS_CLIENT_AUTH=$2; shift 2 ;;
    --wait) [[ $# -ge 2 ]] || die "--wait needs a value"; WAIT=$2; shift 2 ;;
    --no-banner) SHOW_BANNER=0; shift ;;
    -h|--help) print_banner; usage; exit 0 ;;
    -V|--version) print_banner; echo "provision $VERSION"; exit 0 ;;
    *) die "unknown argument: $1 (credentials are read from the environment, see --help)" ;;
  esac
done

print_banner

[[ $TLS_CLIENT_AUTH =~ ^(disabled|optional|required)$ ]] || die "--tls-client-auth must be disabled, optional or required"
[[ $WAIT =~ ^[0-9]+$ ]] || die "--wait needs a number of seconds"
IFS=',' read -r -a PARTS <<<"$ONLY"
for p in "${PARTS[@]}"; do
  [[ $p =~ ^(inputs|streams|pipelines|events)$ ]] || die "unknown part in --only: $p"
done
want() { [[ ",$ONLY," == *",$1,"* ]]; }
command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

# ---- definitions ---------------------------------------------------------------------
for f in inputs streams pipelines event-definitions; do
  [[ -r $DEFS/$f.json ]] || die "missing definition file: $DEFS/$f.json"
  jq -e . "$DEFS/$f.json" >/dev/null 2>&1 || die "invalid JSON: $DEFS/$f.json"
done

rule_title() { sed -n 's/^rule "\(.*\)"[[:space:]]*$/\1/p' "$1" | head -n1; }

if ((DRY_RUN)); then
  want inputs && jq -r '.inputs[] | "plan     input     \(.title) [\(.type | split(".") | last), port \(.configuration.port)]"' "$DEFS/inputs.json"
  want streams && jq -r '.streams[] | "plan     stream    \(.title) (\(.rules | length) rule(s))"' "$DEFS/streams.json"
  if want pipelines; then
    while IFS= read -r rf; do
      [[ -r $DEFS/pipelines/$rf ]] || die "missing rule file: pipelines/$rf"
      t=$(rule_title "$DEFS/pipelines/$rf"); [[ -n $t ]] || die "no rule title in pipelines/$rf"
      log plan rule "$t"
    done < <(jq -r '.pipelines[].rules[]' "$DEFS/pipelines.json")
    jq -r '.pipelines[] | "plan     pipeline  \(.title) -> \(.streams | join(", "))"' "$DEFS/pipelines.json"
  fi
  want events && jq -r '.event_definitions[] | "plan     event     [P\(.priority)] \(.title)"' "$DEFS/event-definitions.json"
  echo "dry-run: no changes made"
  exit 0
fi

# ---- connection and credentials ---------------------------------------------------------
[[ $URL =~ ^(https?)://([^/:]+|\[[0-9a-fA-F:]+\])(:[0-9]+)?/?$ ]] || die "GRAYLOG_URL must look like https://host[:port]"
scheme=${BASH_REMATCH[1]} host=${BASH_REMATCH[2]}
URL=${URL%/}
if [[ $scheme == http && ! $host =~ ^(127\.0\.0\.1|localhost|\[::1\])$ ]]; then
  die "refusing to send credentials over plain http to $host; use https"
fi
CURL_TLS=()
if [[ -n ${GRAYLOG_CA_FILE:-} ]]; then
  [[ -r $GRAYLOG_CA_FILE ]] || die "GRAYLOG_CA_FILE is not readable"
  CURL_TLS=(--cacert "$GRAYLOG_CA_FILE")
fi

read_secret_file() {
  local f=$1 mode
  [[ -f $f && -r $f ]] || die "secret file not readable: $f"
  mode=$(stat -c '%a' "$f")
  [[ $mode =~ ^[0-7]?[0-7]00$ ]] || die "secret file $f must not be accessible by group/others (chmod 600)"
  head -n1 "$f" | tr -d '\r\n'
}

AUTH_USER="" AUTH_PASS=""
if [[ -n ${GRAYLOG_API_TOKEN_FILE:-} ]]; then
  AUTH_USER=$(read_secret_file "$GRAYLOG_API_TOKEN_FILE"); AUTH_PASS=token
elif [[ -n ${GRAYLOG_API_TOKEN:-} ]]; then
  AUTH_USER=$GRAYLOG_API_TOKEN; AUTH_PASS=token
else
  AUTH_USER=${GRAYLOG_USERNAME:-admin}
  if [[ -n ${GRAYLOG_PASSWORD_FILE:-} ]]; then
    AUTH_PASS=$(read_secret_file "$GRAYLOG_PASSWORD_FILE")
  elif [[ -n ${GRAYLOG_PASSWORD:-} ]]; then
    AUTH_PASS=$GRAYLOG_PASSWORD
  elif [[ -t 0 ]]; then
    read -r -s -p "Graylog password for $AUTH_USER: " AUTH_PASS; echo >&2
  else
    die "no credentials: set GRAYLOG_API_TOKEN_FILE or GRAYLOG_PASSWORD_FILE (see --help)"
  fi
fi
[[ -n $AUTH_USER && -n $AUTH_PASS ]] || die "empty credentials"
unset GRAYLOG_API_TOKEN GRAYLOG_PASSWORD

curl_escape() { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
RESP=$WORK/resp.json
HTTP_CODE=000

# api METHOD PATH [JSON-FILE]  ->  body in $RESP, status in $HTTP_CODE
# Credentials are passed to curl through a process-substitution config file, so they
# never appear in the process list or in shell traces.
api() {
  local method=$1 path=$2 data=${3:-}
  local args=(-sS --max-time 30 -o "$RESP" -w '%{http_code}' -X "$method"
    -H 'Accept: application/json' -H "X-Requested-By: $REQUESTED_BY" "${CURL_TLS[@]}")
  [[ -n $data ]] && args+=(-H 'Content-Type: application/json' --data-binary "@$data")
  HTTP_CODE=$(curl "${args[@]}" -K <(printf 'user = "%s:%s"\n' "$(curl_escape "$AUTH_USER")" "$(curl_escape "$AUTH_PASS")") \
    "$URL$path") || HTTP_CODE=000
}

api_ok() { # api_ok METHOD PATH [JSON] ; fails with the API message on non-2xx
  api "$@"
  if [[ ! $HTTP_CODE =~ ^2 ]]; then
    local msg
    msg=$(jq -r '.message // .type // empty' "$RESP" 2>/dev/null | head -c 500 || true)
    fail "$1 $2 failed with HTTP $HTTP_CODE${msg:+: $msg}"
  fi
}

# api_create PATH JSON-FILE: POST a new object. Graylog 6+ expects shareable entities
# (streams, event definitions) wrapped as {"entity": ..., "share_request": ...}; older
# versions take the plain object. Try plain first and wrap when the server asks for it.
api_create() {
  api POST "$1" "$2"
  if [[ $HTTP_CODE == 400 ]] && jq -e '(.message // "") | test("entity cannot be null")' "$RESP" >/dev/null 2>&1; then
    jq '{entity: ., share_request: {selected_grantee_capabilities: {}}}' "$2" >"$2.wrapped"
    api POST "$1" "$2.wrapped"
  fi
  if [[ ! $HTTP_CODE =~ ^2 ]]; then
    local msg
    msg=$(jq -r '.message // .type // empty' "$RESP" 2>/dev/null | head -c 500 || true)
    fail "POST $1 failed with HTTP $HTTP_CODE${msg:+: $msg}"
  fi
}

if ((WAIT > 0)); then
  deadline=$((SECONDS + WAIT))
  until curl -fsS --max-time 5 "${CURL_TLS[@]}" "$URL/api/system/lbstatus" 2>/dev/null | grep -q ALIVE; do
    ((SECONDS < deadline)) || fail "Graylog at $URL did not become ALIVE within ${WAIT}s"
    sleep 5
  done
fi

api GET /api/system
[[ $HTTP_CODE == 401 || $HTTP_CODE == 403 ]] && fail "authentication failed (HTTP $HTTP_CODE)"
[[ $HTTP_CODE =~ ^2 ]] || fail "cannot reach the Graylog API at $URL (HTTP $HTTP_CODE)"
log ok graylog "$(jq -r '"version \(.version) at '"$URL"'"' "$RESP")"

created=0 existing=0

# ---- inputs ----------------------------------------------------------------------------
if want inputs; then
  api_ok GET /api/system/inputs
  jq -r '.inputs[].title' "$RESP" >"$WORK/have"
  n=$(jq '.inputs | length' "$DEFS/inputs.json")
  for ((i = 0; i < n; i++)); do
    jq ".inputs[$i]" "$DEFS/inputs.json" >"$WORK/def"
    title=$(jq -r .title "$WORK/def") type=$(jq -r .type "$WORK/def")
    if grep -Fxq -- "$title" "$WORK/have"; then log exists input "$title"; existing=$((existing + 1)); continue; fi
    api_ok GET "/api/system/inputs/types/$type"
    jq --slurpfile def "$WORK/def" --arg auth "$TLS_CLIENT_AUTH" '
      (.requested_configuration | with_entries(select(.value.default_value != null) | .value = .value.default_value))
      + $def[0].configuration
      | if has("tls_client_auth") then .tls_client_auth = $auth else . end
      | {title: $def[0].title, type: $def[0].type, global: true, configuration: .}' "$RESP" >"$WORK/body"
    api_ok POST /api/system/inputs "$WORK/body"
    log created input "$title"; created=$((created + 1))
  done
fi

# ---- streams ---------------------------------------------------------------------------
stream_ids() { api_ok GET /api/streams; jq -r '.streams[] | [.title, .id] | @tsv' "$RESP" >"$WORK/streams"; }
stream_id() { awk -F'\t' -v t="$1" '$1 == t { print $2; exit }' "$WORK/streams"; }

if want streams; then
  stream_ids
  api_ok GET '/api/system/indices/index_sets?skip=0&limit=0&stats=false'
  index_set=$(jq -r '[.index_sets[] | select(.default == true)][0].id // empty' "$RESP")
  [[ -n $index_set ]] || fail "no default index set found"
  n=$(jq '.streams | length' "$DEFS/streams.json")
  for ((i = 0; i < n; i++)); do
    title=$(jq -r ".streams[$i].title" "$DEFS/streams.json")
    if [[ -n $(stream_id "$title") ]]; then log exists stream "$title"; existing=$((existing + 1)); continue; fi
    jq --arg ix "$index_set" ".streams[$i] | {title, description, matching_type, rules,
        remove_matches_from_default_stream, index_set_id: \$ix}" "$DEFS/streams.json" >"$WORK/body"
    api_create /api/streams "$WORK/body"
    id=$(jq -r '.stream_id // .id' "$RESP")
    api_ok POST "/api/streams/$id/resume"
    log created stream "$title"; created=$((created + 1))
  done
fi

# ---- pipelines -------------------------------------------------------------------------
if want pipelines; then
  stream_ids
  api_ok GET /api/system/pipelines/rule
  jq -r '.[].title' "$RESP" >"$WORK/rules"
  while IFS= read -r rf; do
    src=$DEFS/pipelines/$rf
    [[ -r $src ]] || die "missing rule file: pipelines/$rf"
    title=$(rule_title "$src")
    if grep -Fxq -- "$title" "$WORK/rules"; then log exists rule "$title"; existing=$((existing + 1)); continue; fi
    jq -n --rawfile s "$src" '{title: "", description: "Provisioned by graylog-central-logging", source: $s}' >"$WORK/body"
    api_ok POST /api/system/pipelines/rule "$WORK/body"
    log created rule "$title"; created=$((created + 1))
  done < <(jq -r '[.pipelines[].rules[]] | unique[]' "$DEFS/pipelines.json")

  api_ok GET /api/system/pipelines/pipeline
  cp "$RESP" "$WORK/pipelines"
  n=$(jq '.pipelines | length' "$DEFS/pipelines.json")
  for ((i = 0; i < n; i++)); do
    title=$(jq -r ".pipelines[$i].title" "$DEFS/pipelines.json")
    pid=$(jq -r --arg t "$title" '[.[] | select(.title == $t)][0].id // empty' "$WORK/pipelines")
    if [[ -n $pid ]]; then
      log exists pipeline "$title"; existing=$((existing + 1))
    else
      {
        printf 'pipeline "%s"\nstage 0 match either\n' "$title"
        while IFS= read -r rf; do printf 'rule "%s"\n' "$(rule_title "$DEFS/pipelines/$rf")"; done \
          < <(jq -r ".pipelines[$i].rules[]" "$DEFS/pipelines.json")
        printf 'end\n'
      } >"$WORK/pipeline.src"
      jq -n --rawfile s "$WORK/pipeline.src" --arg d "$(jq -r ".pipelines[$i].description" "$DEFS/pipelines.json")" \
        '{title: "", description: $d, source: $s}' >"$WORK/body"
      api_ok POST /api/system/pipelines/pipeline "$WORK/body"
      pid=$(jq -r .id "$RESP")
      log created pipeline "$title"; created=$((created + 1))
    fi
    while IFS= read -r st; do
      sid=$(stream_id "$st"); [[ -n $sid ]] || fail "pipeline '$title': stream not found: $st (provision streams first)"
      api GET "/api/system/pipelines/connections/$sid"
      if [[ $HTTP_CODE =~ ^2 ]]; then jq -c '.pipeline_ids // []' "$RESP" >"$WORK/conn"; else echo '[]' >"$WORK/conn"; fi
      if jq -e --arg p "$pid" 'index($p)' "$WORK/conn" >/dev/null; then continue; fi
      jq -n --arg s "$sid" --arg p "$pid" --slurpfile c "$WORK/conn" '{stream_id: $s, pipeline_ids: ($c[0] + [$p])}' >"$WORK/body"
      api_ok POST /api/system/pipelines/connections/to_stream "$WORK/body"
      log created connect "$title -> $st"
    done < <(jq -r ".pipelines[$i].streams[]" "$DEFS/pipelines.json")
  done
fi

# ---- event definitions -----------------------------------------------------------------
if want events; then
  stream_ids
  api_ok GET '/api/events/definitions?page=1&per_page=500'
  jq -r '.event_definitions[].title' "$RESP" >"$WORK/have"
  n=$(jq '.event_definitions | length' "$DEFS/event-definitions.json")
  for ((i = 0; i < n; i++)); do
    jq ".event_definitions[$i]" "$DEFS/event-definitions.json" >"$WORK/def"
    title=$(jq -r .title "$WORK/def")
    if grep -Fxq -- "$title" "$WORK/have"; then log exists event "$title"; existing=$((existing + 1)); continue; fi
    ids="[]"
    while IFS= read -r st; do
      sid=$(stream_id "$st"); [[ -n $sid ]] || fail "event '$title': stream not found: $st (provision streams first)"
      ids=$(jq -c --arg s "$sid" '. + [$s]' <<<"$ids")
    done < <(jq -r '.streams[]' "$WORK/def")
    jq --argjson streams "$ids" '
      def series: if .threshold == null then [] else [{id: "count-", type: "count", field: null}] end;
      def conditions:
        if .threshold == null then {expression: null}
        else {expression: {expr: .threshold.operator,
                           left: {expr: "number-ref", ref: "count-"},
                           right: {expr: "number", value: .threshold.value}}} end;
      {title, description, priority, alert,
       config: {type: "aggregation-v1", query, query_parameters: [], filters: [], streams: $streams,
                group_by, series: series, conditions: conditions,
                search_within_ms: (.search_within_minutes * 60000),
                execute_every_ms: (.execute_every_minutes * 60000),
                use_cron_scheduling: false, event_limit: 100},
       field_spec: {}, key_spec: [],
       notification_settings: {grace_period_ms: 300000, backlog_size: 20},
       notifications: [],
       storage: [{type: "persist-to-streams-v1", streams: ["000000000000000000000002"]}]}' "$WORK/def" >"$WORK/body"
    api_create '/api/events/definitions?schedule=true' "$WORK/body"
    log created event "$title"; created=$((created + 1))
  done
fi

echo "provision: $created created, $existing already present"

# ---- verification ----------------------------------------------------------------------
if ((VERIFY)); then
  expected=$(jq -r '.inputs[].title' "$DEFS/inputs.json")
  retries=${GCL_VERIFY_RETRIES:-12}
  [[ $retries =~ ^[1-9][0-9]*$ ]] || die "GCL_VERIFY_RETRIES must be a positive number"
  for ((try = 1; try <= retries; try++)); do
    api_ok GET /api/system/inputstates
    jq -r '.states[] | [.message_input.title, .state] | @tsv' "$RESP" >"$WORK/states"
    bad=0
    while IFS= read -r t; do
      st=$(awk -F'\t' -v t="$t" '$1 == t { print $2; exit }' "$WORK/states")
      [[ $st == RUNNING ]] || bad=1
    done <<<"$expected"
    ((bad)) || break
    ((try < retries)) && sleep 5
  done
  while IFS= read -r t; do
    st=$(awk -F'\t' -v t="$t" '$1 == t { print $2; exit }' "$WORK/states")
    log "${st:-MISSING}" input "$t"
  done <<<"$expected"
  ((bad == 0)) || fail "not all inputs are RUNNING (check the TLS certificate paths and permissions)"
  echo "verify: all inputs RUNNING"
fi
