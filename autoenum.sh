#!/bin/bash

TARGETS="$1"
MODE="${2:-quick}"   # quick | full

if [ -z "$TARGETS" ]; then
  echo "Usage: $0 targets.txt [quick|full]"
  exit 1
fi

mkdir -p scans

# =========================
# DETECT WORDPRESS (FIXED)
# =========================
detect_wordpress() {

  local url="$1"

  echo "[*] Checking WordPress: $url"

  # 1. Check common WP paths (best indicator)
  if curl -s -L "$url/wp-login.php" | grep -qi "wordpress"; then
    return 0
  fi

  if curl -s -L "$url/wp-content/" | grep -qiE "wp-content|wp-includes"; then
    return 0
  fi

  if curl -s -L "$url/wp-json/" | grep -qi "rest"; then
    return 0
  fi

  # 2. Check generator meta
  if curl -s -L "$url" | grep -qi "wordpress"; then
    return 0
  fi

  return 1
}

# =========================
# PARSE NMAP
# =========================
parse_nmap_open() {
  grep -E "^[0-9]+/(tcp|udp)\s+open\s+" "$1" | awk '{
    split($1, a, "/")
    port=a[1]
    service=$3

    version=""
    for(i=4;i<=NF;i++) version=version $i " "

    gsub(/^[ \t]+|[ \t]+$/, "", version)

    print port ";" service ";" version
  }'
}

# =========================
# SEARCHSPLOIT
# =========================
search_exploit() {
  local service="$1"
  local version="$2"
  local outdir="$3"

  [[ -z "$version" ]] && return

  searchsploit "$service $version" > "$outdir/searchsploit.txt" 2>/dev/null
}

# =========================
# ENUM SERVICE
# =========================
enum_service() {

  local ip="$1"
  local port="$2"
  local service="$3"

  OUT="scans/$ip"

  echo "[*] Enum: $service $port"

  # ===== HTTP / HTTPS =====
  if [[ "$service" == http* ]]; then

    URL="http://$ip:$port"

    # follow redirect
    FINAL_URL=$(curl -s -o /dev/null -w "%{url_effective}" "$URL")

    echo "[+] Final URL: $FINAL_URL"

    # ===== WORDPRESS DETECTION (FIXED) =====
    if detect_wordpress "$FINAL_URL"; then

      echo "[+] WordPress detected"

      /opt/wpscan/wpscan.sh "$FINAL_URL" fast

    else

      echo "[+] Not WordPress → FFUF"

      /opt/ffuf/ffufscan.sh path "$FINAL_URL/FUZZ"

    fi
  fi

  # ===== SMB =====
  if [[ "$service" == smb* || "$service" == microsoft-ds* ]]; then
    enum4linux-ng -A "$ip" > "$OUT/smb.txt"
  fi

  # ===== FTP =====
  if [[ "$service" == ftp* ]]; then
    nmap -p "$port" --script ftp-anon "$ip" > "$OUT/ftp.txt"
  fi

  # ===== SSH =====
  if [[ "$service" == ssh* ]]; then
    nmap -p "$port" --script ssh-auth-methods "$ip" > "$OUT/ssh.txt"
  fi

  # ===== SNMP =====
  if [[ "$service" == snmp* ]]; then
    snmpwalk -v2c -c public "$ip" > "$OUT/snmp.txt" 2>/dev/null
  fi
}

# =========================
# NUCLEI
# =========================
run_nuclei() {

  local ip="$1"
  local outdir="$2"

  nuclei -mhe 10 -nh -ni -ss host-spray -s critical,high,medium -u "$ip" \
    -o "$outdir/nuclei.txt" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
}

# =========================
# MAIN
# =========================
for ip in $(cat "$TARGETS"); do

  echo "=============================="
  echo "[*] TARGET: $ip"
  echo "=============================="

  OUT="scans/$ip"
  mkdir -p "$OUT"

  # ===== QUICK + UDP =====
  nmap -sC -sV -Pn "$ip" -oN "$OUT/quick.txt"
  nmap -sU --top-ports 10 -Pn "$ip" -oN "$OUT/udp.txt"

  # ===== PARSE QUICK =====
  parse_nmap_open "$OUT/quick.txt" > "$OUT/parsed_quick.txt"

  # ===== ENUM QUICK =====
  echo "[*] ENUM from QUICK..."

  while IFS=';' read -r port service version; do
    enum_service "$ip" "$port" "$service"
    search_exploit "$service" "$version" "$OUT"
  done < "$OUT/parsed_quick.txt"


  # ===== NUCLEI (START EARLY) =====
  echo "[*] Running NUCLEI EARLY..."

  parsed_file="$OUT/parsed_quick.txt"

  echo "[DEBUG] parsed file: $parsed_file"

  # tetap pakai IP asli dari loop
  echo "[DEBUG] IP: $ip"

  proto_http=$(grep -q "http" "$parsed_file" && echo "http")
  proto_https=$(grep -q "https" "$parsed_file" && echo "https")

  echo "[DEBUG] HTTP: $proto_http | HTTPS: $proto_https"

  if [[ -n "$proto_https" ]]; then
    target="https://$ip"
  elif [[ -n "$proto_http" ]]; then
    target="http://$ip"
  else
    target="$ip"
  fi

  echo "[*] Target: $target"

  if [[ -z "$ip" ]]; then
    echo "[ERROR] IP kosong, skip nuclei"
  else
    run_nuclei "$target" "$OUT" &
    NUCLEI_PID=$!
    echo "[*] NUCLEI PID: $NUCLEI_PID"
  fi
  # ===== FULL SCAN (BACKGROUND) =====
  echo "[*] Starting FULL scan..."
  nmap -p- -sC -sV -Pn "$ip" -oN "$OUT/full.txt" &
  FULL_PID=$!

  # ===== WAIT FULL =====
  wait $FULL_PID

  # ===== PARSE FULL =====
  parse_nmap_open "$OUT/full.txt" > "$OUT/parsed_full.txt"

  # ===== DETECT NEW PORTS (DELTA) =====
  echo "[*] Detecting NEW ports..."

  cat "$OUT/parsed_full.txt" "$OUT/parsed_quick.txt" \
    | sort | uniq -u > "$OUT/parsed_new.txt"

  # ===== RE-ENUM ONLY NEW PORTS =====
  if [[ -s "$OUT/parsed_new.txt" ]]; then

    echo "[*] Re-enum NEW ports only..."

    while IFS=';' read -r port service version; do
      enum_service "$ip" "$port" "$service"
      search_exploit "$service" "$version" "$OUT"
    done < "$OUT/parsed_new.txt"

  fi

done
