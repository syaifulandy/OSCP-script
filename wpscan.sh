#!/bin/bash
# Buat file tokenwp.txt dulu, daftar di https://wpscan.com/

TARGET="$1"
MODE="$2"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 http://target [fast|full]"
  exit 1
fi

# default mode = full
MODE=${MODE:-full}

# ===== Extract Host =====
HOST=$(echo "$TARGET" | awk -F/ '{print $3}' | sed 's/:/_/g')
TS=$(date +%F_%H-%M-%S)

OUTDIR="wpscan_${HOST}_$TS"
mkdir -p "$OUTDIR"


# ===== Optional API Token =====
TOKEN_FILE="$(dirname "$0")/tokenwp.txt"
WPSCAN_TOKEN_ARGS=()

if [ -f "$TOKEN_FILE" ]; then
  API_TOKEN=$(head -n 1 "$TOKEN_FILE" | tr -d '\r\n')

  if [ -n "$API_TOKEN" ]; then
    echo "[*] WPScan API token loaded."
    WPSCAN_TOKEN_ARGS=(--api-token "$API_TOKEN")
  fi
else
  echo "[*] tokenwp.txt not found. Running without API token."
fi

# ===== Dynamic filenames =====
JSON_OUT="$OUTDIR/${HOST}.json"
PLUGINS_TXT="$OUTDIR/${HOST}_plugins.txt"
PLUGINS_CSV="$OUTDIR/${HOST}_plugins.csv"
EXPLOIT_LOG="$OUTDIR/${HOST}_exploits.txt"
LOOT_LOG="$OUTDIR/${HOST}_loot.txt"
USERS_TXT="$OUTDIR/${HOST}_users.txt"
REPORT_CSV="$OUTDIR/${HOST}_findings.csv"
echo "target,type,name,version,latest_version,status,vulnerability,fixed_in,url,cve,ref_url,ref_lainnya" > "$REPORT_CSV"


echo "[*] Target: $TARGET"
echo "[*] Mode  : $MODE"
echo "[*] Output: $OUTDIR"
echo ""

# ===== MODE LOGIC =====
if [ "$MODE" == "fast" ]; then
  echo "[*] Running FAST scan (plugins only)..."

  wpscan --url "$TARGET" \
    "${WPSCAN_TOKEN_ARGS[@]}" \
    --enumerate p \
    --plugins-detection aggressive \
    --request-timeout 10 \
    --connect-timeout 10 \
    --max-threads 20 \
    --format json \
    -o "$JSON_OUT"

elif [ "$MODE" == "full" ]; then
  echo "[*] Running FULL scan..."

  timeout 10m wpscan --url "$TARGET" \
    "${WPSCAN_TOKEN_ARGS[@]}" \
    --enumerate ap,at,u,cb,dbe \
    --plugins-detection aggressive \
    --request-timeout 5 \
    --connect-timeout 5 \
    --max-threads 20 \
    --format json \
    -o "$JSON_OUT"

else
  echo "[!] Invalid mode: $MODE"
  echo "Use: fast or full"
  exit 1
fi

# ===== Validate JSON =====
if [ ! -s "$JSON_OUT" ]; then
  echo "[!] WPScan JSON not generated"
  exit 1
fi

jq empty "$JSON_OUT" 2>/dev/null || {
  echo "[!] Invalid JSON from WPScan"
  exit 1
}


# ===== Build Findings CSV =====
echo "[*] Generating findings CSV..."

jq -r --arg target "$TARGET" '

# =========================
# WORDPRESS CORE VULNS
# =========================

(
  .version as $wpver
  | .version.vulnerabilities[]?
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
        .references
        | to_entries
        | map(select(.key != "url" and .key != "cve"))
        | map(.key + ":" + (.value|join(" ; ")))
        | join(" ; ")
      )
    ] | @csv
),

# =========================
# PLUGIN VULNS
# =========================
(
  .plugins
  | to_entries[]
  | .key as $plugin
  | .value as $p
  | $p.vulnerabilities[]?
  | [
      $target,
      "plugin",
      $plugin,
      ($p.version.number? // ""),
      ($p.latest_version // ""),
      (if $p.outdated then "Outdated" else "Installed" end),
      (.title // ""),
      (.fixed_in // ""),
      ($p.location // ""),
      ((.references.cve // []) | join(" ; ")),
      ((.references.url // []) | join(" ; ")),
      (
        .references
        | to_entries
        | map(select(.key != "url" and .key != "cve"))
        | map(.key + ":" + (.value|join(" ; ")))
        | join(" ; ")
      )
    ] | @csv
),

(
  .main_theme as $t
  | select($t.slug != null)
  | [
      $target,
      "theme",
      ($t.slug // ""),
      ($t.version.number // ""),
      ($t.latest_version // ""),
      (if $t.outdated then "Outdated" else "Installed" end),
      "Theme Detected",

      "",
      ($t.location // ""),
      "",
      "",
      ""
    ] | @csv
),

(
  .interesting_findings[]
  | select(.type=="xmlrpc" or .type=="debug_log" or .type=="readme" or .type=="wp_cron")
  | [
      $target,
      "finding",
      .type,
      "",
      "",
      "Detected",
      (.to_s // ""),
      "",
      (.url // ""),
      "",
      ((.references.url // []) | join(" ; ")),
      (
        .references
        | to_entries
        | map(select(.key != "url"))
        | map(.key + ":" + (.value|join(" ; ")))
        | join(" ; ")
      )

    ] | @csv
)

' "$JSON_OUT" >> "$REPORT_CSV"


# ===== Extract Plugins =====
echo "[*] Extracting plugins..."


jq -r '
.plugins
| to_entries[]
| "\(.key) \(.value.version.number? // "")"
' "$JSON_OUT" 2>/dev/null > "$PLUGINS_TXT"

echo "plugin,installed_version,latest_version,outdated" > "$PLUGINS_CSV"

jq -r '
.plugins
| to_entries[]
| "\(.key),\(.value.version.number? // ""),\(.value.latest_version // ""),\(.value.outdated // false)"
' "$JSON_OUT" 2>/dev/null >> "$PLUGINS_CSV"


# ===== Exploit Search =====
echo "[*] Searching exploits..."
> "$EXPLOIT_LOG"

if [ -s "$PLUGINS_TXT" ]; then
  while read -r plugin version; do

    [[ -z "$plugin" ]] && continue

    echo "[+] $plugin $version" | tee -a "$EXPLOIT_LOG"
    searchsploit "$plugin $version" | tee -a "$EXPLOIT_LOG"
    echo "-------------------------" | tee -a "$EXPLOIT_LOG"

  done < "$PLUGINS_TXT"

else
  echo "[!] No plugins found or scan incomplete"
fi

# ===== ONLY FULL MODE: extra checks =====
if [ "$MODE" == "full" ]; then

  echo "[*] Checking sensitive files..."
  > "$LOOT_LOG"

  URLS=(
    "/wp-config.php.bak"
    "/wp-config.php.save"
    "/backup.sql"
    "/database.sql"
    "/db.sql"
    "/wp-content/uploads/"
    "/wp-content/backups/"
    "/wp-snapshots/"
  )

  for path in "${URLS[@]}"; do
    FULL="$TARGET$path"
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$FULL")

    if [[ "$CODE" == "200" ]]; then
      echo "[+] FOUND: $FULL (HTTP $CODE)" | tee -a "$LOOT_LOG"
    fi
  done

  echo "[*] Extracting users..."
  jq -r '.users | keys[]' "$JSON_OUT" 2>/dev/null > "$USERS_TXT"

fi

# ===== Summary =====
echo ""
echo "========= SUMMARY ========="
echo "[+] JSON: $JSON_OUT"
echo "[+] Plugins TXT: $PLUGINS_TXT"
echo "[+] Plugins CSV: $PLUGINS_CSV"
echo "[+] Exploits: $EXPLOIT_LOG"
echo "[+] Findings CSV: $REPORT_CSV"

if [ "$MODE" == "full" ]; then
  echo "[+] Loot: $LOOT_LOG"
  echo "[+] Users: $USERS_TXT"
fi

echo "==========================="
echo "[*] Done!"
