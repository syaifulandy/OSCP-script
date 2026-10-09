#!/usr/bin/env bash

# WordPress assessment automation:
# - WPScan JSON output
# - Heartbeat selama WPScan berjalan
# - Findings CSV
# - Plugin inventory
# - SearchSploit correlation
# - Sensitive file checks
# - User extraction
#
# Usage:
#   ./tes.sh http://target [fast|full] [custom_output_directory]
#
# Examples:
#   ./tes.sh http://10.1.138.166 fast
#   ./tes.sh https://example.com full
#   ./tes.sh https://example.com full hasil_example
#
# Optional:
#   Simpan WPScan API token pada tokenwp.txt
#   di direktori yang sama dengan script.

set -uo pipefail

TARGET="${1:-}"
MODE="${2:-full}"
CUSTOM_OUTDIR="${3:-}"

# =============================================
# Colors
# =============================================
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[0;33m'
  BLUE=$'\033[0;34m'
  RESET=$'\033[0m'
else
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  RESET=""
fi

info() {
  echo "${BLUE}[*]${RESET} $*"
}

success() {
  echo "${GREEN}[+]${RESET} $*"
}

warning() {
  echo "${YELLOW}[!]${RESET} $*" >&2
}

error() {
  echo "${RED}[-]${RESET} $*" >&2
}

# =============================================
# Usage
# =============================================
usage() {
  cat <<EOF
Usage:
  $0 http://target [fast|full] [custom_output_directory]

Examples:
  $0 http://10.1.138.166 fast
  $0 https://example.com full
  $0 https://example.com full output_example
EOF
}

if [[ -z "$TARGET" ]]; then
  usage
  exit 1
fi

case "$MODE" in
  fast|full)
    ;;
  *)
    error "Invalid mode: $MODE"
    echo "Use: fast or full"
    exit 1
    ;;
esac

# =============================================
# Dependency check
# =============================================
REQUIRED_COMMANDS=(
  wpscan
  jq
  curl
  timeout
)

MISSING_COMMANDS=()

for command_name in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    MISSING_COMMANDS+=("$command_name")
  fi
done

if (( ${#MISSING_COMMANDS[@]} > 0 )); then
  error "Missing required commands: ${MISSING_COMMANDS[*]}"
  echo
  echo "Install the missing dependencies, for example:"
  echo "  apt update"
  echo "  apt install -y jq curl coreutils"
  echo
  echo "WPScan and SearchSploit may require separate installation."
  exit 1
fi

if ! command -v searchsploit >/dev/null 2>&1; then
  warning "searchsploit not found. Exploit correlation will be skipped."
  SEARCHSPLOIT_AVAILABLE=false
else
  SEARCHSPLOIT_AVAILABLE=true
fi

# =============================================
# Normalize target
# =============================================
# Remove trailing slash to prevent double slash:
# http://target//wp-config.php.bak
TARGET="${TARGET%/}"

if [[ ! "$TARGET" =~ ^https?:// ]]; then
  error "Target must start with http:// or https://"
  exit 1
fi

# Host extraction:
# http://10.1.138.166:8080/path -> 10.1.138.166_8080
HOST="$(
  printf '%s' "$TARGET" |
    awk -F/ '{print $3}' |
    sed 's/:/_/g'
)"

if [[ -z "$HOST" ]]; then
  error "Unable to extract hostname from target: $TARGET"
  exit 1
fi

TS="$(date '+%F_%H-%M-%S')"

if [[ -n "$CUSTOM_OUTDIR" ]]; then
  OUTDIR="$CUSTOM_OUTDIR"
else
  OUTDIR="wpscan_${HOST}_${TS}"
fi

mkdir -p "$OUTDIR" || {
  error "Unable to create output directory: $OUTDIR"
  exit 1
}


if [[ "$MODE" == "fast" ]]; then
  PLUGIN_DETECTION="passive"

  run_wpscan 15m \
    --enumerate ap,u

else
  PLUGIN_DETECTION="aggressive"

  run_wpscan 30m \
    --enumerate ap,at,u,cb,dbe
fi

# =============================================
# Optional WPScan API token
# =============================================
SCRIPT_DIR="$(
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
)"

TOKEN_FILE="$SCRIPT_DIR/tokenwp.txt"
WPSCAN_TOKEN_ARGS=()

if [[ -f "$TOKEN_FILE" ]]; then
  API_TOKEN="$(
    head -n 1 "$TOKEN_FILE" |
      tr -d '\r\n'
  )"

  if [[ -n "$API_TOKEN" ]]; then
    info "WPScan API token loaded."
    WPSCAN_TOKEN_ARGS=(--api-token "$API_TOKEN")
  else
    warning "tokenwp.txt exists but is empty. Running without API token."
  fi
else
  warning "tokenwp.txt not found. Running without API token."
fi


# =============================================
# Output filenames
# =============================================
JSON_OUT="$OUTDIR/${HOST}.json"
RAW_LOG="$OUTDIR/${HOST}_wpscan.log"
PLUGINS_TXT="$OUTDIR/${HOST}_plugins.txt"
PLUGINS_CSV="$OUTDIR/${HOST}_plugins.csv"
EXPLOIT_LOG="$OUTDIR/${HOST}_exploits.txt"
LOOT_LOG="$OUTDIR/${HOST}_loot.txt"
USERS_TXT="$OUTDIR/${HOST}_users_details.txt"
USERS_ONLY_TXT="$OUTDIR/users.txt"
REPORT_CSV="$OUTDIR/${HOST}_findings.csv"

printf '%s\n' \
  'target,type,name,version,latest_version,status,vulnerability,fixed_in,url,cve,ref_url,ref_lainnya' \
  > "$REPORT_CSV"

# Initialize files
: > "$RAW_LOG"
: > "$EXPLOIT_LOG"
: > "$LOOT_LOG"
: > "$USERS_TXT"

echo
info "Target : $TARGET"
info "Mode   : $MODE"
info "Output : $OUTDIR"
echo

# =============================================
# Heartbeat functions
# =============================================
HEARTBEAT_PID=""

start_heartbeat() {
  local interval="${1:-10}"
  local start_time
  local now
  local elapsed
  local minutes
  local seconds

  start_time="$(date +%s)"

  (
    while true; do
      now="$(date +%s)"
      elapsed=$((now - start_time))
      minutes=$((elapsed / 60))
      seconds=$((elapsed % 60))

      printf '[*] WPScan is still running... elapsed %02d:%02d\n' \
        "$minutes" "$seconds"

      sleep "$interval"
    done
  ) &

  HEARTBEAT_PID=$!
}

stop_heartbeat() {
  if [[ -n "${HEARTBEAT_PID:-}" ]]; then
    if kill -0 "$HEARTBEAT_PID" 2>/dev/null; then
      kill "$HEARTBEAT_PID" 2>/dev/null || true
      wait "$HEARTBEAT_PID" 2>/dev/null || true
    fi

    HEARTBEAT_PID=""
  fi
}

cleanup() {
  stop_heartbeat
}

trap cleanup EXIT INT TERM

# =============================================
# Run WPScan
# =============================================
run_wpscan() {
  local scan_timeout="$1"
  shift

  local -a enumerate_args=("$@")
  local scan_start
  local scan_end
  local scan_duration
  local scan_status

  scan_start="$(date +%s)"

  info "WPScan JSON is being written to:"
  echo "    $JSON_OUT"
  info "A status message will appear every 10 seconds."
  echo

  start_heartbeat 10
  WP_CMD=(
    wpscan
    --url "$TARGET"
    "${WPSCAN_TOKEN_ARGS[@]}"
    "${enumerate_args[@]}"
    --plugins-detection "$PLUGIN_DETECTION"
    --request-timeout 10
    --connect-timeout 10
    --max-threads 20
    --no-banner --no-update
    --format json
    --output "$JSON_OUT"
  )

  info "Running command:"
  printf ' %q' "${WP_CMD[@]}"
  echo
  echo

  # WPScan JSON mode does not normally show detailed CLI progress.
  # stdout and stderr are logged to RAW_LOG.
  #
  # --output writes valid JSON directly to JSON_OUT.
  # timeout limits total scan duration.
  timeout --signal=TERM --kill-after=30s "$scan_timeout" \
    wpscan \
      --url "$TARGET" \
      "${WPSCAN_TOKEN_ARGS[@]}" \
      "${enumerate_args[@]}" \
      --plugins-detection "$PLUGIN_DETECTION"\
      --request-timeout 10 \
      --connect-timeout 10 \
      --max-threads 20 \
      --no-banner --no-update \
      --format json \
      --output "$JSON_OUT" \
      > "$RAW_LOG" 2>&1

  scan_status=$?

  stop_heartbeat

  scan_end="$(date +%s)"
  scan_duration=$((scan_end - scan_start))

  echo

  case "$scan_status" in
    0)
      success "WPScan completed in ${scan_duration} seconds."
      ;;

    124)
      error "WPScan reached the time limit: $scan_timeout"
      warning "A partial JSON file may exist, but it may be incomplete."
      ;;

    137)
      error "WPScan was forcefully terminated after the timeout."
      warning "Check target response time and WPScan log."
      ;;

    130)
      error "WPScan was interrupted by the user."
      return 130
      ;;

    *)
      error "WPScan exited with status: $scan_status"
      warning "Review log: $RAW_LOG"
      ;;
  esac

  return "$scan_status"
}

if [[ "$MODE" == "fast" ]]; then
  info "Running FAST scan: plugins and users"

  # Increase timeout if the target is slow.
  run_wpscan 15m \
    --enumerate ap,u

  WPSCAN_STATUS=$?

else
  info "Running FULL scan."

  # Full mode can require substantially more time because all
  # plugins and themes are enumerated aggressively.
  run_wpscan 30m \
    --enumerate ap,at,u,cb,dbe

  WPSCAN_STATUS=$?
fi

# =============================================
# Display log if WPScan failed
# =============================================
if (( WPSCAN_STATUS != 0 )); then
  echo
  warning "Last 30 lines of WPScan log:"
  echo "----------------------------------------"
  tail -n 30 "$RAW_LOG" 2>/dev/null || true
  echo "----------------------------------------"
fi

# =============================================
# Validate WPScan JSON and scan result
# =============================================
if [[ ! -s "$JSON_OUT" ]]; then
  SCAN_RESULT="FAILED"
  SCAN_ABORT_REASON="WPScan JSON was not generated or is empty."

  error "$SCAN_ABORT_REASON"
  error "Log file: $RAW_LOG"
else
  if ! jq empty "$JSON_OUT" 2>/dev/null; then
    SCAN_RESULT="FAILED"
    SCAN_ABORT_REASON="WPScan output is not valid JSON."

    error "$SCAN_ABORT_REASON"
    error "JSON file: $JSON_OUT"
    error "Log file : $RAW_LOG"
  else
    # JSON valid, tetapi scan belum tentu berhasil
    SCAN_ABORT_REASON="$(
      jq -r '.scan_aborted // empty' "$JSON_OUT" 2>/dev/null
    )"

    if [[ -n "$SCAN_ABORT_REASON" ]]; then
      SCAN_RESULT="ABORTED"

      error "WPScan scan was aborted."
      error "Reason: $SCAN_ABORT_REASON"
    else
      SCAN_RESULT="COMPLETED"
      success "Valid WPScan JSON generated."
      success "WPScan scan completed."
    fi
  fi
fi

if [[ "$SCAN_RESULT" != "COMPLETED" ]]; then
  warning "Skipping findings, plugin, exploit, and user processing because the scan did not complete."
else

  # =============================================
  # Build Findings CSV
  # =============================================
  info "Generating findings CSV..."

  if ! jq -r --arg target "$TARGET" '

  # WORDPRESS CORE VULNERABILITIES
  (
    .version as $wpver
    | select($wpver != null)
    | $wpver.vulnerabilities[]?
    | [
        $target,
        "wordpress-core",
        "WordPress",
        ($wpver.number // ""),
        "",
        ($wpver.status // ""),
        (.title // ""),
        (.fixed_in // ""),
        $target,
        ((.references.cve // []) | join(" ; ")),
        ((.references.url // []) | join(" ; ")),
        (
          .references // {}
          | to_entries
          | map(select(.key != "url" and .key != "cve"))
          | map(
              .key + ":" +
              (
                if (.value | type) == "array"
                then (.value | join(" ; "))
                else (.value | tostring)
                end
              )
            )
          | join(" ; ")
        )
      ]
    | @csv
  ),

  # PLUGIN VULNERABILITIES
  (
    (.plugins // {})
    | to_entries[]?
    | .key as $plugin
    | .value as $p
    | $p.vulnerabilities[]?
    | [
        $target,
        "plugin",
        $plugin,
        ($p.version.number? // ""),
        ($p.latest_version // ""),
        (
          if $p.outdated == true then
            "Outdated"
          else
            "Installed"
          end
        ),
        (.title // ""),
        (.fixed_in // ""),
        ($p.location // ""),
        ((.references.cve // []) | join(" ; ")),
        ((.references.url // []) | join(" ; ")),
        (
          .references // {}
          | to_entries
          | map(select(.key != "url" and .key != "cve"))
          | map(
              .key + ":" +
              (
                if (.value | type) == "array"
                then (.value | join(" ; "))
                else (.value | tostring)
                end
              )
            )
          | join(" ; ")
        )
      ]
    | @csv
  ),

  # MAIN THEME
  (
    .main_theme as $t
    | select($t != null and $t.slug != null)
    | [
        $target,
        "theme",
        ($t.slug // ""),
        ($t.version.number? // ""),
        ($t.latest_version // ""),
        (
          if $t.outdated == true then
            "Outdated"
          else
            "Installed"
          end
        ),
        "Theme Detected",
        "",
        ($t.location // ""),
        "",
        "",
        ""
      ]
    | @csv
  ),

  # THEME VULNERABILITIES
  (
    .main_theme as $t
    | select($t != null)
    | $t.vulnerabilities[]?
    | [
        $target,
        "theme-vulnerability",
        ($t.slug // "unknown-theme"),
        ($t.version.number? // ""),
        ($t.latest_version // ""),
        (
          if $t.outdated == true then
            "Outdated"
          else
            "Installed"
          end
        ),
        (.title // ""),
        (.fixed_in // ""),
        ($t.location // ""),
        ((.references.cve // []) | join(" ; ")),
        ((.references.url // []) | join(" ; ")),
        (
          .references // {}
          | to_entries
          | map(select(.key != "url" and .key != "cve"))
          | map(
              .key + ":" +
              (
                if (.value | type) == "array"
                then (.value | join(" ; "))
                else (.value | tostring)
                end
              )
            )
          | join(" ; ")
        )
      ]
    | @csv
  ),

  # INTERESTING FINDINGS
  (
    .interesting_findings[]?
    | select(
        .type == "xmlrpc" or
        .type == "debug_log" or
        .type == "readme" or
        .type == "wp_cron"
      )
    | [
        $target,
        "finding",
        (.type // ""),
        "",
        "",
        "Detected",
        (.to_s // ""),
        "",
        (.url // ""),
        "",
        ((.references.url // []) | join(" ; ")),
        (
          .references // {}
          | to_entries
          | map(select(.key != "url"))
          | map(
              .key + ":" +
              (
                if (.value | type) == "array"
                then (.value | join(" ; "))
                else (.value | tostring)
                end
              )
            )
          | join(" ; ")
        )
      ]
    | @csv
  )

  ' "$JSON_OUT" >> "$REPORT_CSV"; then
    error "Failed to generate findings CSV."
    exit 1
  fi

  success "Findings CSV generated: $REPORT_CSV"
fi

# =============================================
# Extract Plugins
# =============================================
info "Extracting plugins..."

if ! jq -r '
  (.plugins // {})
  | to_entries[]?
  | [
      .key,
      (.value.version.number? // "")
    ]
  | @tsv
' "$JSON_OUT" > "$PLUGINS_TXT"; then
  error "Failed to create plugin inventory."
  exit 1
fi

printf '%s\n' \
  'plugin,installed_version,latest_version,outdated' \
  > "$PLUGINS_CSV"

if ! jq -r '
  (.plugins // {})
  | to_entries[]?
  | [
      .key,
      (.value.version.number? // ""),
      (.value.latest_version // ""),
      (.value.outdated // false)
    ]
  | @csv
' "$JSON_OUT" >> "$PLUGINS_CSV"; then
  error "Failed to create plugin CSV."
  exit 1
fi

PLUGIN_COUNT="$(
  jq '(.plugins // {}) | length' "$JSON_OUT" 2>/dev/null ||
    echo 0
)"

success "Plugins detected: $PLUGIN_COUNT"

# =============================================
# SearchSploit Correlation
# =============================================
info "Searching public exploit references..."
: > "$EXPLOIT_LOG"

if [[ "$SEARCHSPLOIT_AVAILABLE" != true ]]; then
  warning "Skipping SearchSploit because it is not installed."

  printf '%s\n' \
    "[!] SearchSploit is not installed." \
    > "$EXPLOIT_LOG"

elif [[ ! -s "$PLUGINS_TXT" ]]; then
  warning "No plugins found or plugin enumeration was incomplete."

  printf '%s\n' \
    "[!] No plugins found or plugin enumeration was incomplete." \
    > "$EXPLOIT_LOG"

else
  while IFS=$'\t' read -r plugin version; do
    [[ -z "$plugin" ]] && continue

    if [[ -n "$version" ]]; then
      SEARCH_TERM="WordPress $plugin $version"
      DISPLAY_NAME="$plugin $version"
    else
      SEARCH_TERM="WordPress $plugin"
      DISPLAY_NAME="$plugin"
    fi

    echo
    echo "[+] $DISPLAY_NAME" | tee -a "$EXPLOIT_LOG"
    echo "[*] Search term: $SEARCH_TERM" | tee -a "$EXPLOIT_LOG"

    # Do not let a SearchSploit failure terminate the entire script.
    searchsploit "$SEARCH_TERM" 2>&1 |
      tee -a "$EXPLOIT_LOG" ||
      true

    echo "------------------------------------------------------------" |
      tee -a "$EXPLOIT_LOG"
  done < "$PLUGINS_TXT"
fi

# =============================================
# Full mode extra checks
# =============================================
if [[ "$MODE" == "full" ]]; then
  info "Checking potentially sensitive files..."

  : > "$LOOT_LOG"

  URLS=(
    "/wp-config.php.bak"
    "/wp-config.php.backup"
    "/wp-config.php.old"
    "/wp-config.php.save"
    "/wp-config.php.swp"
    "/wp-config.txt"
    "/backup.sql"
    "/database.sql"
    "/db.sql"
    "/dump.sql"
    "/wordpress.sql"
    "/.env"
    "/readme.html"
    "/wp-content/debug.log"
    "/wp-content/uploads/"
    "/wp-content/backups/"
    "/wp-snapshots/"
  )

  for path in "${URLS[@]}"; do
    FULL_URL="${TARGET}${path}"

    CURL_RESULT="$(
      curl \
        --silent \
        --show-error \
        --location \
        --insecure \
        --max-time 15 \
        --connect-timeout 5 \
        --output /dev/null \
        --write-out '%{http_code} %{size_download} %{content_type}' \
        "$FULL_URL" 2>/dev/null ||
        printf '000 0 unknown'
    )"

    read -r HTTP_CODE BODY_SIZE CONTENT_TYPE <<< "$CURL_RESULT"

    # Record all checked endpoints for auditability.
    printf '[%s] %s | size=%s | type=%s\n' \
      "$HTTP_CODE" \
      "$FULL_URL" \
      "${BODY_SIZE:-0}" \
      "${CONTENT_TYPE:-unknown}" \
      >> "$LOOT_LOG"

    case "$HTTP_CODE" in
      200)
        success "Potentially accessible: $FULL_URL"
        ;;

      301|302|307|308)
        warning "Redirect detected: $FULL_URL (HTTP $HTTP_CODE)"
        ;;

      401|403)
        info "Protected endpoint: $FULL_URL (HTTP $HTTP_CODE)"
        ;;
    esac
  done
fi

# =============================================
# Extract enumerated users
# Berlaku untuk FAST dan FULL mode
# =============================================
info "Extracting enumerated users..."

# File pertama: informasi detail user
printf 'username\tid\tconfidence\tfound_by\tconfirmed_by\n' > "$USERS_TXT"

jq -r '
  (.users // {})
  | to_entries[]?
  | [
      .key,
      (.value.id // ""),
      (.value.confidence // ""),
      (.value.found_by // ""),
      (
        (.value.confirmed_by // {})
        | keys
        | join(" ; ")
      )
    ]
  | @tsv
' "$JSON_OUT" >> "$USERS_TXT"

# File kedua: username saja, tanpa header
jq -r '
  (.users // {})
  | to_entries[]?
  | .key
' "$JSON_OUT" > "$USERS_ONLY_TXT"

USER_COUNT="$(
  jq -r '(.users // {}) | length' "$JSON_OUT" 2>/dev/null ||
  echo 0
)"

if (( USER_COUNT > 0 )); then
  success "Users detected: $USER_COUNT"
  success "User details saved to: $USERS_TXT"
  success "Username list saved to: $USERS_ONLY_TXT"

  echo
  echo "Discovered usernames:"
  cat "$USERS_ONLY_TXT"
  echo
else
  warning "No users were identified by WPScan."
fi

# =============================================
# Summary
# =============================================
FINDINGS_COUNT="$(
  awk 'END {print (NR > 0 ? NR - 1 : 0)}' "$REPORT_CSV"
)"

# =============================================
# Summary
# =============================================
FINDINGS_COUNT="${FINDINGS_COUNT:-0}"
PLUGIN_COUNT="${PLUGIN_COUNT:-0}"
USER_COUNT="${USER_COUNT:-0}"

echo
echo "============================================================"
echo "                         SUMMARY"
echo "============================================================"
printf '[+] Target       : %s\n' "$TARGET"
printf '[+] Mode         : %s\n' "$MODE"

if [[ "$SCAN_RESULT" == "COMPLETED" ]]; then
  printf '[+] Scan status  : %s\n' "$SCAN_RESULT"
else
  printf '[-] Scan status  : %s\n' "$SCAN_RESULT"
fi

if [[ -n "$SCAN_ABORT_REASON" ]]; then
  printf '[-] Abort reason : %s\n' "$SCAN_ABORT_REASON"
fi

printf '[+] Output dir   : %s\n' "$OUTDIR"
printf '[+] Findings     : %s\n' "$FINDINGS_COUNT"
printf '[+] Plugins      : %s\n' "$PLUGIN_COUNT"
printf '[+] User count   : %s\n' "$USER_COUNT"

echo
printf '[+] JSON         : %s\n' "$JSON_OUT"
printf '[+] WPScan log   : %s\n' "$RAW_LOG"
printf '[+] Plugins TXT  : %s\n' "$PLUGINS_TXT"
printf '[+] Plugins CSV  : %s\n' "$PLUGINS_CSV"
printf '[+] Exploits     : %s\n' "$EXPLOIT_LOG"
printf '[+] Findings CSV : %s\n' "$REPORT_CSV"
printf '[+] Users detail : %s\n' "$USERS_TXT"
printf '[+] Users only   : %s\n' "$USERS_ONLY_TXT"

if [[ "$MODE" == "full" ]]; then
  printf '[+] Loot         : %s\n' "$LOOT_LOG"
fi

echo "============================================================"

if [[ "$SCAN_RESULT" == "COMPLETED" ]]; then
  success "Done!"
else
  error "Scan did not complete successfully."
fi
