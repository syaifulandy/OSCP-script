#!/bin/bash

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

# ===== Dynamic filenames =====
JSON_OUT="$OUTDIR/${HOST}.json"
PLUGINS_TXT="$OUTDIR/${HOST}_plugins.txt"
PLUGINS_CSV="$OUTDIR/${HOST}_plugins.csv"
EXPLOIT_LOG="$OUTDIR/${HOST}_exploits.txt"
LOOT_LOG="$OUTDIR/${HOST}_loot.txt"
USERS_TXT="$OUTDIR/${HOST}_users.txt"

echo "[*] Target: $TARGET"
echo "[*] Mode  : $MODE"
echo "[*] Output: $OUTDIR"
echo ""

# ===== MODE LOGIC =====
if [ "$MODE" == "fast" ]; then
  echo "[*] Running FAST scan (plugins only)..."

  wpscan --url "$TARGET" \
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

# ===== Extract Plugins =====
echo "[*] Extracting plugins..."

jq -r '.plugins | to_entries[] | "\(.key) \(.value.version.number)"' "$JSON_OUT" 2>/dev/null > "$PLUGINS_TXT"

echo "plugin,installed_version,latest_version,outdated" > "$PLUGINS_CSV"
jq -r '.plugins | to_entries[] | "\(.key),\(.value.version.number),\(.value.latest_version),\(.value.outdated)"' "$JSON_OUT" 2>/dev/null >> "$PLUGINS_CSV"

# ===== Exploit Search =====
echo "[*] Searching exploits..."
> "$EXPLOIT_LOG"

if [ -s "$PLUGINS_TXT" ]; then
  while read plugin version; do
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

if [ "$MODE" == "full" ]; then
  echo "[+] Loot: $LOOT_LOG"
  echo "[+] Users: $USERS_TXT"
fi

echo "==========================="
echo "[*] Done!"
