#!/bin/bash

# ==========================================================
# OSCP AUTOMATION SCANNER (ULTIMATE REVISED)
# ==========================================================
# Fitur Utama:
# 1. Global Searchsploit Summary (No Duplicates)
# 2. Sequential Scan (Quick IPs -> Deep IPs)
# 3. Clean Directory Management
# 4. Filter Remote Only & No .txt (Specific to OSCP)
# ==========================================================

TARGETS="$1"
BASE_DIR=$(pwd)

if [ -z "$TARGETS" ] || [ ! -f "$TARGETS" ]; then
  echo -e "\e[1;31m[-] Usage: $0 targets.txt\e[0m"
  exit 1
fi

mkdir -p scans

# =========================
# PARSE NMAP
# =========================
parse_nmap_open() {
  grep -E "^[0-9]+/(tcp|udp)\s+open\s+" "$1" | awk '{
    split($1, a, "/")
    port=a[1]
    proto=$3
    product_version=""
    for(i=4;i<=NF;i++) product_version=product_version $i " "
    gsub(/^[ \t]+|[ \t]+$/, "", product_version)
    print port ";" proto ";" product_version
  }'
}

# =========================
# GENERATE EXPLOIT SUMMARY
# =========================
# Fungsi ini memproses file parsed_*.txt untuk mencari exploit secara unik
generate_exploit_summary() {
  local ip_dir="$1"
  local parsed_file="$2"
  local outfile="$ip_dir/exploit_summary.txt"
  
  local temp_specific=$(mktemp)
  local temp_broad=$(mktemp)

  [[ ! -s "$parsed_file" ]] && return

  echo -e "\e[1;33m[*] Generating unique exploit summary for $parsed_file...\e[0m"

  while IFS=';' read -r port proto product; do
    # Skip banner sampah
    [[ -z "$product" || "$product" == "unknown" || "$product" == "tcpwrapped" ]] && continue
    [[ "$product" == "microsoft-ds?" ]] && product="Microsoft Windows SMB"

    # 1. Specific Search (Full Banner)
    searchsploit -t "$product" 2>/dev/null | grep -i "Remote" | grep -v ".txt" >> "$temp_specific"

    # 2. Broad Search (Software Name Only)
    local software_only=$(echo "$product" | awk '{print $1}')
    # Filter: Jangan broad search kata "Microsoft" karena terlalu banyak noise
    if [[ -n "$software_only" && "$software_only" != "Microsoft" && "$software_only" != "$product" ]]; then
      searchsploit -t "$software_only" 2>/dev/null | grep -i "Remote" | grep -v ".txt" >> "$temp_broad"
    fi
  done < "$parsed_file"

  # Write output dengan deduplikasi
  echo "======================================================" > "$outfile"
  echo "   SUMMARY SPECIFIC EXPLOITS (Version Based)" >> "$outfile"
  echo "======================================================" >> "$outfile"
  if [ -s "$temp_specific" ]; then
    sort -u "$temp_specific" >> "$outfile"
  else
    echo "No specific exploits found." >> "$outfile"
  fi

  echo -e "\n\n======================================================" >> "$outfile"
  echo "   BROAD SEARCH RESULTS (App Based)" >> "$outfile"
  echo "======================================================" >> "$outfile"
  if [ -s "$temp_broad" ]; then
    # comm -23 menampilkan yang ada di BROAD tapi belum ada di SPECIFIC
    comm -23 <(sort -u "$temp_broad") <(sort -u "$temp_specific") >> "$outfile"
  else
    echo "No broad exploits found." >> "$outfile"
  fi

  rm "$temp_specific" "$temp_broad"
}

# =========================
# ENUM SERVICE (WITH CD)
# =========================
enum_service() {
  local ip="$1"
  local port="$2"
  local service="$3"
  local ip_dir="$BASE_DIR/scans/$ip"

  echo -e "\e[1;33m[*] Enumerating $service on port $port...\e[0m"

  # HTTP / HTTPS
  if [[ "$service" == http* ]]; then
    local url="http://$ip:$port"
    [[ "$port" == "443" ]] && url="https://$ip:$port"
    
    cd "$ip_dir" || return
    if curl -s -L --max-time 7 "$url" | grep -qi "wordpress"; then
      echo "[+] WP Detected on $url"
      /opt/wpscan/wpscan.sh "$url" fast
    else
      echo "[+] Running FFUF on $url"
      /opt/ffuf/ffufscan.sh path "$url/FUZZ"
    fi
    cd "$BASE_DIR" || return
  fi

  # SMB
  if [[ "$service" == smb* || "$service" == microsoft-ds* || "$port" == "445" ]]; then
    echo "[+] Running Enum4linux-ng..."
    enum4linux-ng -A "$ip" > "$ip_dir/smb.txt" 2>/dev/null
  fi

  # FTP
  if [[ "$service" == ftp* ]]; then
    echo "[+] Checking FTP Anonymous..."
    nmap -p "$port" --script ftp-anon "$ip" > "$ip_dir/ftp.txt" 2>/dev/null
  fi
}

# ==========================================
# TAHAP 1: QUICK SCAN (ALL IPs)
# ==========================================
echo -e "\n\e[1;32m[+] TAHAP 1: QUICK SCAN & EARLY ENUM (ALL TARGETS)\e[0m"
for ip in $(cat "$TARGETS"); do
  echo -e "\n\e[1;34m>>> PROCESSING TARGET: $ip <<<\e[0m"
  IP_DIR="$BASE_DIR/scans/$ip"
  mkdir -p "$IP_DIR"

  # Nmap Quick
  echo "[*] Nmap Quick Scan..."
  nmap -sC -sV -Pn "$ip" -oN "$IP_DIR/quick.txt" > /dev/null
  parse_nmap_open "$IP_DIR/quick.txt" > "$IP_DIR/parsed_quick.txt"

  # Generate Exploit Summary untuk hasil Quick
  generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_quick.txt"
  
  # Service Enum
  while IFS=';' read -r port proto product; do
    enum_service "$ip" "$port" "$proto"
  done < "$IP_DIR/parsed_quick.txt"
done

# ==========================================
# TAHAP 2: DEEP SCAN & NUCLEI (ALL IPs)
# ==========================================
echo -e "\n\e[1;32m[+] TAHAP 2: DEEP SCAN & NUCLEI (ALL TARGETS)\e[0m"
for ip in $(cat "$TARGETS"); do
  echo -e "\n\e[1;34m>>> DEEP SCANNING: $ip <<<\e[0m"
  IP_DIR="$BASE_DIR/scans/$ip"
  
  # Nuclei
  target_nuclei=$(grep "http" "$IP_DIR/parsed_quick.txt" | head -n 1 | awk -F';' '{print "http://'$ip':"$1}')
  [[ -z "$target_nuclei" ]] && target_nuclei="$ip"
  echo "[*] Running Nuclei..."
  nuclei -s critical,high,medium -u "$target_nuclei" -o "$IP_DIR/nuclei.txt" -nh -ni > /dev/null 2>&1

  # Full Nmap
  echo "[*] Running Nmap Full Port (-p-)..."
  nmap -p- -sV -Pn "$ip" -oN "$IP_DIR/full.txt" > /dev/null
  parse_nmap_open "$IP_DIR/full.txt" > "$IP_DIR/parsed_full.txt"

  # Delta Check (Port Baru)
  cat "$IP_DIR/parsed_full.txt" "$IP_DIR/parsed_quick.txt" | sort | uniq -u > "$IP_DIR/parsed_new.txt"

  if [[ -s "$IP_DIR/parsed_new.txt" ]]; then
    echo -e "\e[1;31m[!] New Ports Found! Updating Exploit Summary...\e[0m"
    # Update summary untuk menyertakan port baru
    generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_full.txt"
    while IFS=';' read -r port proto product; do
      enum_service "$ip" "$port" "$proto"
    done < "$IP_DIR/parsed_new.txt"
  fi
done

echo -e "\n\e[1;32m[+] DONE! Check scans/[IP]/exploit_summary.txt for clean results.\e[0m"
