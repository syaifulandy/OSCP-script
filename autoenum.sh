#!/bin/bash

# ==========================================================
# OSCP AUTOMATION SCANNER (ULTIMATE REVISED V2)
# ==========================================================
# Fitur Utama:
# 1. Dual Output Searchsploit (Remote vs Local PrivEsc)
# 2. Global Searchsploit Summary (No Duplicates)
# 3. Sequential Scan (Quick IPs -> Deep IPs)
# 4. Clean Directory Management
# 5. Script external yg digunakan: ffufscan.sh dan wpscan.sh
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

# ==========================================
# GENERATE EXPLOIT SUMMARY (REMOTE vs LOCAL)
# ==========================================
generate_exploit_summary() {
  local ip_dir="$1"
  local parsed_file="$2"
  local remote_out="$ip_dir/exploits_remote.txt"
  local local_out="$ip_dir/exploits_privesc.txt"
  
  local tmp_rem_spec=$(mktemp)
  local tmp_rem_broad=$(mktemp)
  local tmp_loc=$(mktemp)

  [[ ! -s "$parsed_file" ]] && return

  echo -e "\e[1;33m[*] Sorting Remote vs Local exploits for $parsed_file...\e[0m"

  while IFS=';' read -r port proto product; do
    # Skip banner sampah
    [[ -z "$product" || "$product" == "unknown" || "$product" == "tcpwrapped" ]] && continue
    [[ "$product" == "microsoft-ds?" ]] && product="Microsoft Windows SMB"

    # --- 1. SEARCH REMOTE EXPLOITS ---
    # Filter: Fokus pada Remote Code Execution, Overflow, dan Service Exploit
    searchsploit -t "$product" 2>/dev/null | grep -iE "Remote|RCE|Execution|Overflow" | grep -v ".txt" >> "$tmp_rem_spec"
    
    local software_only=$(echo "$product" | awk '{print $1}')
    if [[ -n "$software_only" && "$software_only" != "Microsoft" && "$software_only" != "$product" ]]; then
      searchsploit -t "$software_only" 2>/dev/null | grep -iE "Remote|RCE|Execution|Overflow" | grep -v ".txt" >> "$tmp_rem_broad"
    fi

    # --- 2. SEARCH LOCAL EXPLOITS (PrivEsc) ---
    # Filter: Fokus pada Local Privilege Escalation (LPE)
    searchsploit -t "$product" 2>/dev/null | grep -iE "Local|Privilege|Escalation|LPE" | grep -v ".txt" >> "$tmp_loc"
    if [[ -n "$software_only" && "$software_only" != "Microsoft" ]]; then
        searchsploit -t "$software_only" 2>/dev/null | grep -iE "Local|Privilege|Escalation|LPE" | grep -v ".txt" >> "$tmp_loc"
    fi

  done < "$parsed_file"

  # Tulis Output Remote
  echo "======================================================" > "$remote_out"
  echo "   SPECIFIC REMOTE EXPLOITS (High Confidence)" >> "$remote_out"
  echo "======================================================" >> "$remote_out"
  sort -u "$tmp_rem_spec" >> "$remote_out"
  
  echo -e "\n\n======================================================" >> "$remote_out"
  echo "   BROAD REMOTE SEARCH (App Based)" >> "$remote_out"
  echo "======================================================" >> "$remote_out"
  comm -23 <(sort -u "$tmp_rem_broad") <(sort -u "$tmp_rem_spec") >> "$remote_out"

  # Tulis Output Local PrivEsc
  echo "======================================================" > "$local_out"
  echo "   LOCAL PRIVILEGE ESCALATION CANDIDATES" >> "$local_out"
  echo "======================================================" >> "$local_out"
  if [ -s "$tmp_loc" ]; then
    sort -u "$tmp_loc" >> "$local_out"
  else
    echo "No obvious Local PrivEsc found in service banners." >> "$local_out"
  fi

  rm "$tmp_rem_spec" "$tmp_rem_broad" "$tmp_loc"
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
    # --- TAMBAHKAN PENGECEKAN WINRM ---
    # Jika port adalah 5985 atau 5986, lewati FFUF/WPScan
    if [[ "$port" == "5985" || "$port" == "5986" ]]; then
      echo -e "${YELLOW}[*] Skipping Web Discovery for WinRM port ($port) on $ip${NC}"
      return
    fi
    # --------------------------------

    local url="http://$ip:$port"
    [[ "$port" == "443" ]] && url="https://$ip:$port"
    
    cd "$ip_dir" || return
    
    # Logic Deteksi CMS / Fuzzing
    if curl -s -L --max-time 7 "$url" | grep -qi "wordpress"; then
      echo -e "${GREEN}[+] WP Detected on $url${NC}"
      /opt/wpscan/wpscan.sh "$url" fast
    else
      echo -e "${BLUE}[+] Running FFUF on $url${NC}"
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

  echo "[*] Nmap Quick Scan..."
  nmap -sC -sV --host-timeout 100 --version-intensity 0 -Pn "$ip" -oN "$IP_DIR/quick.txt" > /dev/null
  parse_nmap_open "$IP_DIR/quick.txt" > "$IP_DIR/parsed_quick.txt"

  generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_quick.txt"
  
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
  
  target_nuclei=$(grep "http" "$IP_DIR/parsed_quick.txt" | head -n 1 | awk -F';' '{print "http://'$ip':"$1}')
  [[ -z "$target_nuclei" ]] && target_nuclei="$ip"
  echo "[*] Running Nuclei..."
  nuclei -s critical,high,medium -u "$target_nuclei" -o "$IP_DIR/nuclei.txt" -nh -ni > /dev/null 2>&1

  echo "[*] Running Nmap Full Port (-p-)..."
  nmap -p- -sV --host-timeout 60 -Pn "$ip" -oN "$IP_DIR/full.txt" > /dev/null
  parse_nmap_open "$IP_DIR/full.txt" > "$IP_DIR/parsed_full.txt"

  cat "$IP_DIR/parsed_full.txt" "$IP_DIR/parsed_quick.txt" | sort | uniq -u > "$IP_DIR/parsed_new.txt"

  if [[ -s "$IP_DIR/parsed_new.txt" ]]; then
    echo -e "\e[1;31m[!] New Ports Found! Updating Exploit Summaries...\e[0m"
    generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_full.txt"
    while IFS=';' read -r port proto product; do
      enum_service "$ip" "$port" "$proto"
    done < "$IP_DIR/parsed_new.txt"
  fi
done

echo -e "\n\e[1;32m[+] DONE! Check scans/[IP]/exploits_remote.txt and exploits_privesc.txt\e[0m"
