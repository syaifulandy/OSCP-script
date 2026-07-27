#!/bin/bash
# ==========================================================
# OSCP AUTOMATION SCANNER - ULTIMATE REVISED V4.1
# ==========================================================
# Optimasi:
# 1. Live output + tee logging
# 2. Print semua command sebelum eksekusi
# 3. Nuclei parallel/background dengan RustScan
# 4. Fix parsed_new: enum ulang hanya port baru
# 5. Fix parser Nmap/RustScan reason: remove "syn-ack ttl xxx"
# 6. SMB enum sekali per host
# 7. FTP/SSH/RDP tidak nmap ulang karena quick/full sudah -sCV
# 8. DNS blackbox enum + AXFR candidate discovery
# 9. SNMP blackbox: onesixtyone + snmpwalk useful MIBs
# 10. UDP scan background + parse + enum UDP
# 11. Global exploit/port summary
# ==========================================================

TARGETS="$1"
BASE_DIR=$(pwd)
SCAN_DIR="$BASE_DIR/scans"

# =========================
# COLORS
# =========================
RED="\e[1;31m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
BLUE="\e[1;34m"
CYAN="\e[1;36m"
MAGENTA="\e[1;35m"
NC="\e[0m"

# =========================
# CONFIG
# =========================
QUICK_HOST_TIMEOUT="5m"
UDP_HOST_TIMEOUT="3m"
NUCLEI_TIMEOUT="10m"
RUSTSCAN_TIMEOUT="8m"
NMAP_STATS_EVERY="15s"

FFUF_SCRIPT="/opt/ffuf/ffufscan.sh"
WPSCAN_SCRIPT="/opt/wpscan/wpscan.sh"

UDP_PIDS=()
# =========================
# HELPERS
# =========================
print_cmd() {
  echo -e "${CYAN}[CMD]${NC} $*"
}

# =========================
# BASIC VALIDATION
# =========================
if [ -z "$TARGETS" ] || [ ! -f "$TARGETS" ]; then
  echo -e "${RED}[-] Usage: $0 targets.txt${NC}"
  exit 1
fi

mkdir -p "$SCAN_DIR"
echo -e "${GREEN}[+] Running Nuclei in background"
print_cmd "nohup timeout $NUCLEI_TIMEOUT nuclei -s critical,high,medium -l $TARGETS -o $SCAN_DIR/general_nuclei.txt -nh -ni -mhe 25 -duc -ept http"
nohup timeout "$NUCLEI_TIMEOUT" nuclei -s critical,high,medium \
  -l "$TARGETS" \
  -o "$SCAN_DIR/general_nuclei.txt" \
  -nh -ni -mhe 25 -duc -ept http \
  > "$SCAN_DIR/nuclei.log" 2>&1 &

# =========================
# LOGGING
# =========================
MASTER_LOG="$SCAN_DIR/master_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$MASTER_LOG") 2>&1

echo -e "${GREEN}[+] Master log: $MASTER_LOG${NC}"



section() {
  echo -e "\n${GREEN}============================================================${NC}"
  echo -e "${GREEN}[+] $*${NC}"
  echo -e "${GREEN}============================================================${NC}"
}

subsection() {
  echo -e "\n${BLUE}>>> $* <<<${NC}"
}

warn() {
  echo -e "${YELLOW}[!] $*${NC}"
}

err() {
  echo -e "${RED}[-] $*${NC}"
}

ok() {
  echo -e "${GREEN}[+] $*${NC}"
}

info() {
  echo -e "${YELLOW}[*] $*${NC}"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}


safe_target_list() {
  grep -vE '^\s*$|^\s*#' "$TARGETS" \
    | tr -d '\r' \
    | awk '!seen[$0]++'
}

sanitize_filename() {
  echo "$1" | tr -cd '[:alnum:]_.-'
}

requirement_check() {
  echo -e "${MAGENTA}[*] Checking dependencies...${NC}"

  local tools=("nmap" "searchsploit" "curl" "awk" "grep" "sort" "uniq" "tee" "timeout")

  for t in "${tools[@]}"; do
    if ! has_cmd "$t"; then
      warn "Missing command: $t"
    fi
  done

  if ! has_cmd rustscan; then
    warn "Missing rustscan. Full port deep scan will fail."
  fi

  if ! has_cmd nuclei; then
    warn "Missing nuclei. Nuclei scan will fail."
  fi

  if ! has_cmd enum4linux-ng; then
    warn "Missing enum4linux-ng. SMB enum will be skipped."
  fi

  if ! has_cmd dig; then
    warn "Missing dig. DNS reverse/AXFR fallback will be limited."
  fi

  if ! has_cmd onesixtyone; then
    warn "Missing onesixtyone. SNMP community brute force will be skipped."
  fi

  if ! has_cmd snmpwalk; then
    warn "Missing snmpwalk. SNMP MIB enumeration will be skipped."
  fi

  if [ ! -x "$FFUF_SCRIPT" ]; then
    warn "FFUF wrapper not executable/found: $FFUF_SCRIPT"
  fi

  if [ ! -x "$WPSCAN_SCRIPT" ]; then
    warn "WPScan wrapper not executable/found: $WPSCAN_SCRIPT"
  fi

  if has_cmd sudo; then
    SUDO_BIN="sudo"
  else
    SUDO_BIN=""
    warn "sudo not found. UDP scans may fail if raw socket privileges are required."
  fi
}

# =========================
# PARSE NMAP
# Output:
# port;service;product/version
#
# Aman untuk:
# 1. Normal nmap:
#    80/tcp open http Apache httpd 2.4.52
#    -> 80;http;Apache httpd 2.4.52
#
# 2. RustScan/Nmap reason output:
#    135/tcp open msrpc syn-ack ttl 125 Microsoft Windows RPC
#    -> 135;msrpc;Microsoft Windows RPC
# =========================
parse_nmap_open() {
  local input_file="$1"

  if [ ! -s "$input_file" ]; then
    return
  fi

  grep -E "^[0-9]+/(tcp|udp)\s+open\s+" "$input_file" | awk '
  {
    split($1, a, "/")
    port=a[1]
    service=$3
    start=4

    # Remove Nmap reason field if present.
    # Common reason forms:
    # syn-ack ttl 125
    # udp-response ttl 64
    # reset ttl 64
    # conn-refused
    # echo-reply ttl 64
    # arp-response ttl 64
    if ($start ~ /^(syn-ack|udp-response|reset|conn-refused|no-response|echo-reply|arp-response|localhost-response)$/) {
      start++
    }

    # Remove optional "ttl <number>" after reason.
    if ($(start) == "ttl") {
        start += 2
    }


    product_version=""
    for(i=start;i<=NF;i++) {
      product_version=product_version $i " "
    }

    gsub(/^[ \t]+|[ \t]+$/, "", product_version)

    # Do not fallback product to service.
    # Empty product is cleaner than searchsploit noise.
    print port ";" service ";" product_version
  }'
}

# ==========================================================
# 1. CORE URL PROBER FUNCTION (ROOT LEVEL)
# ==========================================================
probe_port_web() {
  local target_ip="$1"
  local target_port="$2"
  local out_file="$3"

  # Abaikan port administratif WinRM/WSMan agar hemat waktu
  [[ "$target_port" == "5985" || "$target_port" == "5986" || "$target_port" == "47001" ]] && return

  # Tembak HTTPS dulu (Timeout ketat 2s, connect timeout 1s)
  local http_code=$(curl -4 -k --max-time 2 --connect-timeout 1 -s -o /dev/null -w "%{http_code}" "https://$target_ip:$target_port")
  
  # Jika HTTPS sukses (bukan 000), catat dan exit
  if [[ -n "$http_code" && "$http_code" != "000" ]]; then
    echo "https://$target_ip:$target_port" >> "$out_file"
    return 0
  fi

  # Fallback: Tembak HTTP biasa jika HTTPS return 000
  http_code=$(curl -4 -k --max-time 2 --connect-timeout 1 -s -o /dev/null -w "%{http_code}" "http://$target_ip:$target_port")
  if [[ -n "$http_code" && "$http_code" != "000" ]]; then
    echo "http://$target_ip:$target_port" >> "$out_file"
    return 0
  fi

  return 1
}
export -f probe_port_web


# ==========================================================
# 2. BUILD WEB TARGETS RUNNER
# ==========================================================
build_web_targets() {
  local ip="$1"
  local parsed_file="$2"
  local output_file="$3"

  : > "$output_file"

  if [ ! -s "$parsed_file" ]; then
    return
  fi

  local tmp_ports=$(mktemp)
  local tmp_web_discovered=$(mktemp)

  # 1. Kumpulkan semua open ports tanpa peduli apa nama service dari Nmap
  awk -F';' '{print $1}' "$parsed_file" | sort -u > "$tmp_ports"

  # 2. Eksekusi Parallel Probing menggunakan xargs -P (Disesuaikan ke -P 5 agar aman di background)
  if [ -s "$tmp_ports" ]; then
    info "Probing hidden web services on $ip using controlled parallel xargs..."
    cat "$tmp_ports" | xargs -P 5 -I{} bash -c 'probe_port_web "$1" "$2" "$3"' _ "$ip" {} "$tmp_web_discovered"
  fi

  # 3. Ambil hasil unik dan bersihkan temporary file
  if [ -s "$tmp_web_discovered" ]; then
    sort -u "$tmp_web_discovered" > "$output_file"
    local count=$(wc -l < "$output_file")
    ok "Found $count valid web endpoints for $ip"
  fi

  rm -f "$tmp_ports" "$tmp_web_discovered"
}
export -f build_web_targets

# =========================
# BUILD NON-WEB TARGETS (ip:port)
# =========================
build_nonweb_targets() {
  local ip="$1"
  local parsed_file="$2"
  local output_file="$3"

  : > "$output_file"

  if [ ! -s "$parsed_file" ]; then
    return
  fi

  while IFS=';' read -r port service product; do
    [[ -z "$port" || -z "$service" ]] && continue

    # skip web service
    if [[ "$service" == http* || "$service" == *http* || "$service" == https* || "$service" == ssl/http* ]]; then
      continue
    fi

    # skip noise
    case "$service" in
      ""|"unknown"|"tcpwrapped")
        continue
        ;;
    esac

    echo "$ip:$port" >> "$output_file"

  done < "$parsed_file"

  sort -u "$output_file" -o "$output_file"
}

# ==========================================
# NORMALIZE PRODUCT BANNER
# ==========================================
normalize_product_banner() {
  echo "$1" \
    | sed -E 's/^(syn-ack|udp-response|reset|conn-refused|no-response|echo-reply|arp-response|localhost-response)( ttl [0-9]+)?[[:space:]]*//I' \
    | sed -E 's/\([^)]*\)//g' \
    | sed 's/[()]//g' \
    | sed -E 's/[[:space:]]+/ /g' \
    | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}
# ==========================================
# EXTRACT VERSION FROM PRODUCT / QUERY
# ==========================================
extract_version() {
  echo "$1" \
    | grep -oE '[0-9]+(\.[0-9]+){1,4}([a-zA-Z0-9._-]*)?' \
    | head -n 1
}

# ==========================================
# EXTRACT VENDOR / APP TOKEN
# ==========================================
extract_vendor() {
  local cleaned="$1"

  echo "$cleaned" \
    | awk '{print $1}' \
    | sed 's/[?]//g' \
    | tr '[:upper:]' '[:lower:]'
}

# ==========================================
# NORMALIZE SEARCHSPLOIT OUTPUT LINE
# ==========================================
normalize_searchsploit_line() {
  echo "$1" \
    | sed -E 's/\x1B\[[0-9;]*[mK]//g' \
    | sed -E 's/[[:space:]]{2,}/ /g' \
    | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}

# ==========================================
# REMOTE EXPLOIT FILTER (REVISED)
# ==========================================

is_remote_exploit_line() {
  local line="$1"

  # Hard reject (useless)
  if echo "$line" | grep -qiE "Denial of Service|DoS"; then
    return 1
  fi

  # Strong indicators
  if echo "$line" | grep -qiE "RCE|Remote|Code Execution|Command Execution|Injection"; then
    return 0
  fi

  # Medium indicators
  if echo "$line" | grep -qiE "Traversal|File Upload|Bypass|Privilege"; then
    return 0
  fi

  # Default: still include (important for unknown cases)
  return 0
}


# ==========================================
# LOCAL PRIVESC FILTER
# ==========================================

is_local_privesc_line() {
  local title="$1"
  local path="$2"

  echo "$path" | grep -qiE '/local/' && return 0
  echo "$title" | grep -qiE "Privilege Escalation|Priv Esc|PrivEsc|LPE|Local Privilege" && return 0

  return 1
}

# ==========================================
# BUILD HIGH CONFIDENCE SEARCHSPLOIT QUERIES
# Mostly version-based
# ==========================================
build_searchsploit_queries_high() {
  local product="$1"

  local cleaned
  local version
  local first_word

  cleaned=$(normalize_product_banner "$product")
  version=$(extract_version "$cleaned")
  first_word=$(echo "$cleaned" | awk '{print $1}' | sed 's/[?]//g')

  [[ -z "$cleaned" ]] && return

  # Full cleaned product
  echo "$cleaned"

  # Vendor + exact version
  if [[ -n "$first_word" && -n "$version" ]]; then
    echo "$first_word $version"
  fi

  # Apache variants
  if echo "$cleaned" | grep -qiE '^Apache'; then
    [[ -n "$version" ]] && echo "Apache $version"
    [[ -n "$version" ]] && echo "Apache HTTP Server $version"
    [[ -n "$version" ]] && echo "Apache httpd $version"
  fi

  # Common services
  if echo "$cleaned" | grep -qiE '^OpenSSH'; then
    [[ -n "$version" ]] && echo "OpenSSH $version"
  fi

  if echo "$cleaned" | grep -qiE 'Samba|smbd'; then
    [[ -n "$version" ]] && echo "Samba $version"
    [[ -n "$version" ]] && echo "smbd $version"
  fi

  if echo "$cleaned" | grep -qiE '^vsftpd'; then
    [[ -n "$version" ]] && echo "vsftpd $version"
  fi

  if echo "$cleaned" | grep -qiE '^ProFTPD'; then
    [[ -n "$version" ]] && echo "ProFTPD $version"
  fi

  if echo "$cleaned" | grep -qiE 'Microsoft IIS|IIS'; then
    [[ -n "$version" ]] && echo "Microsoft IIS $version"
    [[ -n "$version" ]] && echo "IIS $version"
  fi

  if echo "$cleaned" | grep -qiE 'Tomcat'; then
    [[ -n "$version" ]] && echo "Tomcat $version"
    [[ -n "$version" ]] && echo "Apache Tomcat $version"
  fi
}

# ==========================================
# BUILD GENERIC / BROAD SEARCHSPLOIT QUERIES
# Product/app-name based, less strict
# ==========================================

build_searchsploit_queries_generic() {
  local product="$1"
  local service="$2"

  local cleaned version major minor vendor

  cleaned=$(normalize_product_banner "$product")
  version=$(extract_version "$cleaned")
  vendor=$(extract_vendor "$cleaned")

  [[ -z "$version" || -z "$vendor" ]] && return

  # FULL version
  echo "$vendor $version"

  # Extract major.minor
  if [[ "$version" =~ ^([0-9]+)\.([0-9]+) ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"

    echo "$vendor $major.$minor"
    echo "$vendor $major"
  else
    # fallback: just major
    major=$(echo "$version" | cut -d. -f1)
    echo "$vendor $major"
  fi

  # Apache alias handling
  if [[ "$vendor" == "apache" ]]; then
    echo "Apache HTTP Server $version"
    echo "Apache HTTP Server $major.$minor"
  fi
}

# ==========================================
# HIGH CONFIDENCE CHECK (REVISED)
# ==========================================
is_high_confidence_exploit() {
  local title="$1"
  local product="$2"
  local query="$3"

  local cleaned title_lc version vendor
  cleaned=$(normalize_product_banner "$product")
  title_lc=$(echo "$title" | tr '[:upper:]' '[:lower:]')
  version=$(extract_version "$cleaned")
  vendor=$(extract_vendor "$cleaned" | tr -d '[:space:]')

  [[ -z "$version" || -z "$vendor" ]] && return 1

  # Menggunakan grep standar tanpa flag -F fixed string agar lebih aman di Kali Linux
  echo "$title_lc" | grep -qi "$version" || return 1

  # Alias map jika vendor utamanya bernama apache
  if [[ "$vendor" == "apache" ]]; then
    echo "$title_lc" | grep -qiE 'apache|http server|httpd' && return 0
  fi

  echo "$title_lc" | grep -qiE "$vendor|apache|httpd|http server" && return 0

  return 1
}

# ==========================================
# LOCAL PRIVESC FILTER
# ==========================================

is_local_privesc_line() {
  local title="$1"
  local path="$2"

  # Path-based local exploit
  echo "$path" | grep -qiE '/local/' && return 0

  # Title-based privilege escalation only
  echo "$title" | grep -qiE "Privilege Escalation|Priv Esc|PrivEsc|LPE|Local Privilege" && return 0

  return 1
}

# ==========================================
# GENERATE EXPLOIT SUMMARY (ANTI-HALU VERSION)
# ==========================================
generate_exploit_summary() {
  local ip_dir="$1"
  local parsed_file="$2"

  local remote_out="$ip_dir/exploits_remote.txt"
  local generic_out="$ip_dir/exploits_remote_generic.txt"
  local local_out="$ip_dir/exploits_privesc.txt"

  # Jaminan file bersih dari sisa scan sebelumnya agar tidak append berulang
  : > "$remote_out"
  : > "$generic_out"
  : > "$local_out"

  local tmp_high
  local tmp_generic
  local tmp_loc
  local tmp_queries_seen

  tmp_high=$(mktemp)
  tmp_generic=$(mktemp)
  tmp_loc=$(mktemp)
  tmp_queries_seen=$(mktemp)

  [[ ! -s "$parsed_file" ]] && {
    rm -f "$tmp_high" "$tmp_generic" "$tmp_loc" "$tmp_queries_seen"
    return
  }

  info "Sorting Remote High Confidence vs Generic vs Local PrivEsc for $parsed_file..."

  while IFS=';' read -r port service product; do
    product=$(normalize_product_banner "$product")

    [[ "$product" == "microsoft-ds?" ]] && product="Microsoft Windows SMB"

    if [[ -z "$product" ]]; then
      case "$service" in
        ""|"unknown"|"tcpwrapped"|"msrpc"|"netbios-ssn"|"microsoft-ds")
          continue
          ;;
      esac
    fi

    # -------------------------
    # HIGH CONFIDENCE QUERIES
    # -------------------------
    product_version=$(extract_version "$product")

    if [[ -n "$product_version" ]]; then
      while IFS= read -r ss_query; do
        ss_query=$(echo "$ss_query" | tr '[:upper:]' '[:lower:]')
        [[ -z "$ss_query" ]] && continue

        [[ ${#ss_query} -lt 3 ]] && continue

        
        if [[ "$ss_query" =~ ^(microsoft|windows|linux|unix)$ ]] || \
           [[ "$ss_query" =~ ^(kerberos-sec|msrpc|ncacn_http|netbios-ssn|kpasswd5|domain)$ ]]; then
            continue
        fi


        if grep -Fxqi "HIGH::$ss_query" "$tmp_queries_seen"; then
          continue
        fi

        if echo "$ss_query" | grep -qiE '^microsoft$' || \
           echo "$ss_query" | grep -qiE '^microsoft[[:space:]]+[0-9]' || \
           echo "$ss_query" | grep -qi 'httpapi'; then
          continue
        fi

        echo "HIGH::$ss_query" >> "$tmp_queries_seen"
        
        # Cetak command tanpa tanda kutip agar sesuai dengan eksekusi asli
        print_cmd "COLUMNS=300 timeout 5s searchsploit -s -t \"$ss_query\" | remote filter"

        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          
          # Bersihkan warna/ANSI escape character dari output terminal Kali
          local clean_line=$(echo "$line" \
            | sed -E 's/\x1B\[[0-9;]*[mK]//g' \
            | sed -E 's/[[:space:]]+/ /g')
          
          local title path norm_line
          # Potong kolom berbasis literal pipe murni agar aman dari pergeseran spasi
          title=$(echo "$clean_line" | cut -d'|' -f1 \
            | sed 's/^[[:space:]]*//' \
            | sed 's/[[:space:]]*$//')

          path=$(echo "$clean_line" | cut -d'|' -f2 \
            | sed 's/^[[:space:]]*//' \
            | sed 's/[[:space:]]*$//')

          
          [[ -z "$title" || -z "$path" ]] && continue

          # 🔥 FILTER HEADER / GARBAGE LINE
          echo "$title" | grep -qiE "^=|^[-]|Exploit Title" && continue

          norm_line="${title} | ${path}"

          if is_remote_exploit_line "$norm_line"; then
            if is_high_confidence_exploit "$title" "$product" "$ss_query"; then
              echo "$norm_line" >> "$tmp_high"
            else
              
              major=$(echo "$product_version" | cut -d. -f1)
              minor=$(echo "$product_version" | cut -d. -f2)
              if echo "$title" | grep -qiE "$major\\.$minor|$major\\.x|< $major\\."; then
                echo "$norm_line" >> "$tmp_generic"
              fi

            fi
          fi

          if is_local_privesc_line "$title" "$path"; then
            echo "$norm_line" >> "$tmp_loc"
          fi
        done < <(
          # FIX: Lepas -t dan lepas tanda kutip agar query word-splitting (Logika AND) bekerja sempurna
          COLUMNS=300 timeout 5s searchsploit -t "$ss_query" 2>/dev/null \
            | grep -viE "Shellcodes:|No Results|Exploit Title|----"
        )
      done < <(build_searchsploit_queries_high "$product" \
        | sed 's/[?]//g' \
        | sed -E 's/[[:space:]]+/ /g' \
        | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
        | awk 'length($0) >= 2' \
        | sort -u | head -n 5)
    fi

    # -------------------------
    # GENERIC / PRODUCT QUERIES
    # -------------------------
    local generic_queries
    generic_queries=$(mktemp)

    build_searchsploit_queries_generic "$product" "$service" \
      | sed 's/[?]//g' \
      | sed -E 's/[[:space:]]+/ /g' \
      | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
      | awk 'length($0) >= 3' \
      | sort -u | head -n 7 > "$generic_queries"

    while IFS= read -r ss_query; do

      ss_query=$(echo "$ss_query" | tr '[:upper:]' '[:lower:]')
      [[ -z "$ss_query" ]] && continue
      [[ ${#ss_query} -lt 3 ]] && continue

      
      if [[ "$ss_query" =~ ^(microsoft|windows|linux|unix)$ ]] || \
         [[ "$ss_query" =~ ^(kerberos-sec|msrpc|ncacn_http|netbios-ssn|kpasswd5|domain)$ ]]; then
        continue
      fi

      if grep -Fxqi "GENERIC::$ss_query" "$tmp_queries_seen"; then
        continue
      fi

      if echo "$ss_query" | grep -qiE '^microsoft$' || \
         echo "$ss_query" | grep -qiE '^microsoft[[:space:]]+[0-9]' || \
         echo "$ss_query" | grep -qi 'httpapi'; then
        continue
      fi

      echo "GENERIC::$ss_query" >> "$tmp_queries_seen"
      print_cmd "COLUMNS=300 timeout 5s searchsploit -t \"$ss_query\" | remote filter"

      while IFS= read -r line; do
        [[ -z "$line" ]] && continue        
        local clean_line=$(echo "$line" \
          | sed -E 's/\x1B\[[0-9;]*[mK]//g' \
          | sed -E 's/[[:space:]]+/ /g')

        local title path norm_line        
        title=$(echo "$clean_line" | cut -d'|' -f1 \
          | sed 's/^[[:space:]]*//' \
          | sed 's/[[:space:]]*$//')

        path=$(echo "$clean_line" | cut -d'|' -f2 \
          | sed 's/^[[:space:]]*//' \
          | sed 's/[[:space:]]*$//')

        
        [[ -z "$title" || -z "$path" ]] && continue

        # 🔥 FILTER HEADER / GARBAGE LINE
        echo "$title" | grep -qiE "^=|^[-]|Exploit Title" && continue

        norm_line="${title} | ${path}"

        if is_remote_exploit_line "$norm_line"; then
          if is_high_confidence_exploit "$title" "$product" "$ss_query"; then
            echo "$norm_line" >> "$tmp_high"
          else  
            major=$(echo "$product_version" | cut -d. -f1)
            minor=$(echo "$product_version" | cut -d. -f2)

            if echo "$title" | grep -qiE "$major\\.$minor|$major\\.x|< $major\\."; then
              echo "$norm_line" >> "$tmp_generic"
            fi
          fi
        fi

        if is_local_privesc_line "$title" "$path"; then
          echo "$norm_line" >> "$tmp_loc"
        fi
      done < <(
        # FIX: Lepas -t dan lepas tanda kutip juga untuk pencarian generic
        COLUMNS=300 timeout 5s searchsploit -t "$ss_query" 2>/dev/null \
          | grep -viE "Shellcodes:|No Results|Exploit Title|----"
      )
    done < "$generic_queries"

    rm -f "$generic_queries"
  done < "$parsed_file"

  # -------------------------
  # WRITE OUTPUT FILES
  # -------------------------
  {
    echo "======================================================"
    echo "   SPECIFIC REMOTE EXPLOITS (High Confidence)"
    echo "======================================================"
    if [ -s "$tmp_high" ]; then sort -u "$tmp_high"; else echo "No obvious high-confidence Remote/RCE exploit found from service banners."; fi
  } >> "$remote_out"

  {
    echo "======================================================"
    echo "   GENERIC REMOTE SEARCH (Product/App Based)"
    echo "======================================================"
    echo "Review manually. These are lower confidence results."
    echo "======================================================"
    if [ -s "$tmp_generic" ]; then comm -23 <(sort -u "$tmp_generic") <(sort -u "$tmp_high"); else echo "No generic remote results generated."; fi
  } >> "$generic_out"

  {
    echo "======================================================"
    echo "   LOCAL PRIVILEGE ESCALATION CANDIDATES"
    echo "======================================================"
    if [ -s "$tmp_loc" ]; then sort -u "$tmp_loc"; else echo "No obvious Local PrivEsc found in service banners."; fi
  } >> "$local_out"

  rm -f "$tmp_high" "$tmp_generic" "$tmp_loc" "$tmp_queries_seen"
  ok "Exploit summaries written:"
  echo "    - $remote_out"
  echo "    - $generic_out"
  echo "    - $local_out"
}


# =========================
# ENUM SERVICE
# =========================
enum_service() {
  local ip="$1"
  local port="$2"
  local service="$3"
  local product="$4"
  local ip_dir="$SCAN_DIR/$ip"

  # Clean leftover reason noise
  product=$(echo "$product" | sed -E 's/^(syn-ack|udp-response|reset|conn-refused|no-response|echo-reply|arp-response|localhost-response)( ttl [0-9]+)?[[:space:]]*//I')
  product=$(echo "$product" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')

  # Skip unknown empty services to reduce noise
  if [[ "$service" == "unknown" && -z "$product" ]]; then
    info "Skipping unknown service on port $port."
    return
  fi

  # -------------------------
  # HTTP / HTTPS
  # -------------------------
  if [[ "$service" == http* || "$service" == *http* || "$service" == https* || "$service" == ssl/http* ]]; then
    if [[ "$port" == "5985" || "$port" == "5986" || "$port" == "47001" ]]; then
      warn "Skipping Web Discovery for WinRM-like port ($port) on $ip"
      return
    fi
    info "Enumerating service=$service product=\"$product\" on port $port..."
    local scheme="http"
    if [[ "$service" == *https* || "$service" == ssl/http* || "$port" == "443" || "$port" == "8443" || "$port" == "9443" || "$port" == "10443" ]]; then
      scheme="https"
    fi

    local url="$scheme://$ip:$port"
    local web_dir="$ip_dir/web_$port"
    mkdir -p "$web_dir"

    print_cmd "curl -k -s -L --max-time 7 \"$url\""
    timeout 1m curl -k -s -L --max-time 7 "$url" | tee "$web_dir/index.html" >/dev/null

    if grep -qiE "wordpress|wp-content|wp-includes" "$web_dir/index.html"; then
      ok "WordPress detected on $url"
      echo "$url" >> "$SCAN_DIR/wordpress_targets.txt"

      if [ -x "$WPSCAN_SCRIPT" ]; then
        (
          cd "$web_dir" || exit
          print_cmd "$WPSCAN_SCRIPT \"$url\" fast"            
          "$WPSCAN_SCRIPT" "$url" fast "$web_dir/wpscan" \
            2>&1 | tee "$web_dir/wpscan.log"

        )
      else
        warn "WPScan wrapper not found/executable: $WPSCAN_SCRIPT"
      fi
    else
      ok "Running FFUF on $url"

      if [ -x "$FFUF_SCRIPT" ]; then
        (
          cd "$web_dir" || exit
          print_cmd "$FFUF_SCRIPT path \"$url/FUZZ\""
          "$FFUF_SCRIPT" path "$url/FUZZ" 2>&1 | tee "$web_dir/ffuf.log"
        )
      else
        warn "FFUF wrapper not found/executable: $FFUF_SCRIPT"
      fi
    fi
  fi

  # -------------------------
  # SMB - once per host
  # -------------------------
  if [[ "$service" == smb* || "$service" == microsoft-ds* || "$service" == netbios-ssn* || "$port" == "445" || "$port" == "139" ]]; then
    if [ -f "$ip_dir/.smb_enum_done" ]; then
      info "SMB enum already done for $ip. Skipping duplicate SMB enum on port $port."
    else
      info "Enumerating service=$service product=\"$product\" on port $port..."
      if has_cmd enum4linux-ng; then
        print_cmd "enum4linux-ng -A \"$ip\""
        enum4linux-ng -A "$ip" 2>&1 | tee "$ip_dir/smb.txt"
        touch "$ip_dir/.smb_enum_done"
      else
        warn "enum4linux-ng not found. Skipping SMB enum."
      fi
    fi
  fi


  # -------------------------
  # DNS - blackbox
  # -------------------------
  # 1. Pastikan skrip hanya masuk ke modul DNS jika layanannya sesuai
  if [[ "$service" == domain* || "$service" == dns* || "$port" == "53" ]]; then
    local dns_dir="$ip_dir/dns_$port"
    mkdir -p "$dns_dir"

    info "Running DNS blackbox enumeration on $ip:$port"

    print_cmd "timeout $QUICK_HOST_TIMEOUT nmap  --host-timeout $QUICK_HOST_TIMEOUT -Pn -p \"$port\" -sCV --script dns-nsid,dns-recursion,dns-service-discovery \"$ip\" -oN \"$dns_dir/dns_basic.txt\""

    timeout $QUICK_HOST_TIMEOUT nmap  --host-timeout $QUICK_HOST_TIMEOUT -Pn -p "$port" -sCV \
      --script dns-nsid,dns-recursion,dns-service-discovery \
      "$ip" \
      -oN "$dns_dir/dns_basic.txt" \
      2>&1 | tee "$dns_dir/dns_basic_live.log"

    if has_cmd dig; then
      print_cmd "dig @$ip -x $ip +short"
      dig @"$ip" -x "$ip" +short 2>&1 | tee "$dns_dir/reverse_lookup.txt"
    fi

    # 2. Logika pengecekan AXFR dipisahkan di dalam modul DNS
    # (Contoh di bawah mengasumsikan adanya file zone_candidates.txt yang diisi sebelumnya)
    if [[ -s "$dns_dir/zone_candidates.txt" ]]; then
      info "Zone candidates found, proceeding with AXFR..."
      # Masukkan perintah AXFR/dig di sini jika ada kandidat
    else
      # Pesan warn dipindahkan ke sini agar hanya muncul saat memeriksa DNS
      warn "No DNS zone candidates discovered. Skipping AXFR."
    fi

  fi # Akhir dari pengecekan port/service DNS

  # -------------------------
  # SNMP - blackbox
  # -------------------------
  if [[ "$service" == snmp* || "$port" == "161" ]]; then
    local snmp_dir="$ip_dir/snmp_$port"
    mkdir -p "$snmp_dir"

    info "Running SNMP blackbox enumeration on $ip:$port"

    echo "$ip" > "$snmp_dir/ip.txt"

    cat > "$snmp_dir/communities_default.txt" <<EOF
public
private
manager
EOF

    if has_cmd onesixtyone; then
      print_cmd "onesixtyone -c \"$snmp_dir/communities_default.txt\" -i \"$snmp_dir/ip.txt\""

      onesixtyone \
        -c "$snmp_dir/communities_default.txt" \
        -i "$snmp_dir/ip.txt" \
        2>&1 | tee "$snmp_dir/onesixtyone.txt"

      grep -oE '\[[^]]+\]' "$snmp_dir/onesixtyone.txt" 2>/dev/null \
        | tr -d '[]' \
        | sort -u > "$snmp_dir/communities_found.txt"
    else
      warn "onesixtyone not found. Falling back to public only."
      echo "public" > "$snmp_dir/communities_found.txt"
    fi

    if [ ! -s "$snmp_dir/communities_found.txt" ]; then
      warn "No SNMP community found. Trying public as fallback."
      echo "public" > "$snmp_dir/communities_found.txt"
    fi
    if has_cmd snmpwalk; then
      while read -r community; do
        [[ -z "$community" ]] && continue

        local safe_community
        safe_community=$(sanitize_filename "$community")

        info "SNMP community candidate: $community"

        # 1. TEST UTAMA: Coba Full Walk super cepat pakai snmpbulkwalk v2c
        print_cmd "snmpbulkwalk -c \"$community\" -v2c -Cr30 -t 10  \"$ip\" .1"
        timeout 5m snmpbulkwalk -c "$community" -v2c -Cr30 -t 10 "$ip" .1 2>/dev/null \
          | tee "$snmp_dir/snmpwalk_${safe_community}_full_v2c.txt"

        # 2. FALLBACK: Jika v2c gagal/kosong, coba full walk pakai snmpwalk v1 biasa
        if [ ! -s "$snmp_dir/snmpwalk_${safe_community}_full_v2c.txt" ]; then
          # Hapus file v2c yang kosong agar tidak membingungkan
          rm -f "$snmp_dir/snmpwalk_${safe_community}_full_v2c.txt"
          
          print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" (Fallback v1)"
          timeout 5m snmpwalk -c "$community" -v1 -t 10 "$ip" 2>/dev/null \
            | tee "$snmp_dir/snmpwalk_${safe_community}_full_v1.txt"
        fi

        # 3. TARGETED JACKPOT SCAN: Tembak langsung OID angka Net-SNMP Extend
        # Tetap jalankan ini secara terpisah untuk mengantisipasi jika Full Walk di atas terkena timeout/tidak lengkap
        print_cmd "snmpwalk -c \"$community\" -v2c -t 10 \"$ip\" .1.3.6.1.4.1.8072.1.3"
        timeout 5m snmpwalk -c "$community" -v2c -t 10 "$ip" .1.3.6.1.4.1.8072.1.3 2>/dev/null \
          | tee "$snmp_dir/snmpwalk_${safe_community}_extensions.txt"

      done < "$snmp_dir/communities_found.txt"
    else
      warn "snmpwalk not found. Skipping SNMP MIB walk."
    fi
  fi
}


# =========================
# RUN RUSTSCAN PORT DISCOVERY ONLY
# =========================
run_rustscan_full() {
  local ip="$1"
  local ip_dir="$SCAN_DIR/$ip"

  rm -f \
      "$ip_dir/parsed_new.txt" \
      "$ip_dir/new_ports.txt" \
      "$ip_dir/new_ports_scv.txt" \
      "$ip_dir/nuclei_targets_new.txt" \
      "$ip_dir/nuclei_targets_nonweb_new.txt" \
      "$ip_dir/nuclei_new.txt" \
      "$ip_dir/nuclei_nonweb_new.txt"


  print_cmd "timeout $RUSTSCAN_TIMEOUT rustscan -a \"$ip\" -r 1-65535 --tries 2 --ulimit 5000 -g"

  timeout "$RUSTSCAN_TIMEOUT" rustscan \
    -a "$ip" \
    -r 1-65535 \
    --tries 2 \
    --ulimit 5000 \
    -g \
    > "$ip_dir/rustscan_ports.txt" \
    2> "$ip_dir/rustscan_live.log"
}
# =========================
# BUILD NEW PORTS FROM RUSTSCAN
# =========================
build_new_ports_from_rustscan() {
  local ip_dir="$1"

  : > "$ip_dir/new_ports.txt"

  [ ! -s "$ip_dir/rustscan_ports.txt" ] && return
  [ ! -s "$ip_dir/parsed_quick.txt" ] && return

  awk -F';' '{print $1}' "$ip_dir/parsed_quick.txt" \
    | sort -u \
    > "$ip_dir/quick_ports.txt"

  grep -oP '\[[0-9, ]+\]' "$ip_dir/rustscan_ports.txt" \
    | tr -d '[]' \
    | tr ',' '\n' \
    | sed 's/ //g' \
    | awk '/^[0-9]+$/' \
    | sort -u \
    > "$ip_dir/rust_ports.txt"

  comm -23 \
    "$ip_dir/quick_ports.txt" \
    "$ip_dir/rust_ports.txt" \
    > "$ip_dir/new_ports.txt"
}


# =========================
# GLOBAL SUMMARY
# =========================
generate_global_summary() {
  section "GENERATING GLOBAL SUMMARY"

  local global_remote="$SCAN_DIR/global_exploits_remote.txt"
  local global_privesc="$SCAN_DIR/global_exploits_privesc.txt"
  local global_ports="$SCAN_DIR/global_open_ports.txt"

  local global_nuclei="$SCAN_DIR/global_nuclei.txt"
  local global_nuclei_high="$SCAN_DIR/global_nuclei_high.txt"
  local global_ffuf="$SCAN_DIR/global_ffuf.txt"
  local global_web="$SCAN_DIR/global_web_targets.txt"
  local global_wp="$SCAN_DIR/global_wordpress.txt"
  local global_nuclei_nonweb="$SCAN_DIR/global_nuclei_nonweb.txt"
  local global_nuclei_all="$SCAN_DIR/global_nuclei_all.txt"


  print_cmd "find \"$SCAN_DIR\" -name exploits_remote.txt -exec cat {} \\; | sort -u > \"$global_remote\""
  find "$SCAN_DIR" -mindepth 2 -maxdepth 2 -name "exploits_remote.txt" -print0 \
    | xargs -0 cat 2>/dev/null \
    | grep -vE "^\s*$|^=|SPECIFIC|No obvious" \
    | grep -E " \| " \
    | sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g' \
    | sort -u > "$global_remote"


  print_cmd "find \"$SCAN_DIR\" -name exploits_privesc.txt -exec cat {} \\; | sort -u > \"$global_privesc\""
  find "$SCAN_DIR" -mindepth 2 -maxdepth 2 -name "exploits_privesc.txt" -print0 \
    | xargs -0 cat 2>/dev/null \
    | grep -vE "^\s*$|^=|LOCAL PRIV|No obvious" \
    | grep -E " \| " \
    | sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g' \
    | sort -u > "$global_privesc"

  # Tambahan untuk remote generic
  find "$SCAN_DIR" -mindepth 2 -maxdepth 2 -name "exploits_remote_generic.txt" -print0 \
    | xargs -0 cat 2>/dev/null \
    | grep -vE "^\s*$|^=|GENERIC|Review|No generic" \
    | grep -E " \| " \
    | sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g' \
    | sort -u > "$SCAN_DIR/global_exploits_remote_generic.txt"


  : > "$global_ports"

  for ip in $(safe_target_list); do
    local pf="$SCAN_DIR/$ip/parsed_full.txt"
    local pq="$SCAN_DIR/$ip/parsed_quick.txt"
    local pu="$SCAN_DIR/$ip/parsed_udp.txt"

    # ✅ TCP: merge quick + full
    for f in "$pf"; do
      if [ -s "$f" ]; then
        awk -F';' -v ip="$ip" '{print ip ";tcp;" $0}' "$f" >> "$global_ports"
      fi
    done

    # ✅ UDP
    if [ -s "$pu" ]; then
      awk -F';' -v ip="$ip" '{print ip ";udp;" $0}' "$pu" >> "$global_ports"
    fi
  done

  # ✅ FINAL DEDUP (SMART)
  sort -t';' -u -k1,1 -k2,2 -k3,3 "$global_ports" -o "$global_ports"


  sort -u "$global_ports" -o "$global_ports"

  print_cmd "Aggregating nuclei results..."

  find "$SCAN_DIR" -type f \( -name "nuclei.txt" -o -name "nuclei_new.txt" \) -print0 \
    | xargs -0 cat 2>/dev/null \
    | sort -u > "$global_nuclei"

  print_cmd "Aggregating ffuf results..."

  echo "target_found,status,size,redirect_to,final_destination_info" > "$global_ffuf"

  find "$SCAN_DIR" -name "*_FUZZ_output_bersih.csv" -type f | while read -r file; do
      tail -n +2 "$file"
  done | sort -u >> "$global_ffuf"

  print_cmd "Collecting web targets..."

  find "$SCAN_DIR" -type f \( -name "nuclei_targets.txt" -o -name "nuclei_targets_new.txt" \) -print0 \
    | xargs -0 cat 2>/dev/null \
    | sort -u > "$global_web"


  
  print_cmd "Collecting WordPress targets..."

  if [ -s "$SCAN_DIR/wordpress_targets.txt" ]; then
      sort -u "$SCAN_DIR/wordpress_targets.txt" > "$global_wp"
  fi

  if [ -s "$global_wp" ]; then

    print_cmd "nuclei -l $global_wp -tags wordpress -severity critical,high,medium -nh -ni -duc -fr"
    # Untuk wordpress ada follow redirectnya
    timeout "$NUCLEI_TIMEOUT" nuclei \
      -l "$global_wp" \
      -tags wordpress \
      -severity critical,high,medium \
      -nh -ni -duc -fr \
      -o "$SCAN_DIR/global_nuclei_wordpress.txt"

  fi



  print_cmd "Aggregating non-web nuclei results..."

  find "$SCAN_DIR" -type f \( -name "nuclei_nonweb_quick.txt" -o -name "nuclei_nonweb_new.txt" \) -print0 \
    | xargs -0 cat 2>/dev/null \
    | sort -u > "$global_nuclei_nonweb"


  print_cmd "Building global nuclei master report..."

  cat \
    "$SCAN_DIR/general_nuclei.txt" \
    "$global_nuclei" \
    "$global_nuclei_nonweb" \
    "$SCAN_DIR/global_nuclei_wordpress.txt" \
    2>/dev/null \
    | grep -vE '^[[:space:]]*$' \
    | sort -u \
    > "$global_nuclei_all"



  ok "Global files:"
  echo "    - $global_remote"
  echo "    - $global_privesc"
  echo "    - $global_ports"
  echo "  * - $global_nuclei_all"
  echo "    - $global_ffuf"
  echo "    - $global_web"
  echo "    - $global_wp"
  echo "    - $global_nuclei_nonweb"

}

# =========================
# START
# =========================
requirement_check

# ==========================================
# TAHAP 1: QUICK SCAN & EARLY ENUM
# ==========================================
section "TAHAP 1: QUICK SCAN & EARLY ENUM (ALL TARGETS)"

for ip in $(safe_target_list); do
  subsection "PROCESSING TARGET: $ip"

  IP_DIR="$SCAN_DIR/$ip"
  mkdir -p "$IP_DIR"

  info "Nmap Quick Scan..."
  print_cmd "nmap -sC -sV --host-timeout $QUICK_HOST_TIMEOUT --version-intensity 0 --stats-every $NMAP_STATS_EVERY -Pn \"$ip\" -oN \"$IP_DIR/quick.txt\""

  timeout $QUICK_HOST_TIMEOUT nmap -n -sC -sV \
    --host-timeout "$QUICK_HOST_TIMEOUT" \
    --version-intensity 0 \
    --stats-every "$NMAP_STATS_EVERY" \
    -Pn "$ip" \
    -oN "$IP_DIR/quick.txt" \
    2>&1 | tee "$IP_DIR/quick_live.log"

  parse_nmap_open "$IP_DIR/quick.txt" > "$IP_DIR/parsed_quick.txt"

  if [ -s "$IP_DIR/parsed_quick.txt" ]; then
    ok "Parsed quick open ports:"
    column -t -s';' "$IP_DIR/parsed_quick.txt" 2>/dev/null || cat "$IP_DIR/parsed_quick.txt"
  else
    warn "No open ports parsed from quick scan for $ip"
  fi

  info "Nmap UDP Fast Scan running in background..."
  print_cmd "$SUDO_BIN nmap -sU --top-ports 20 --max-retries 1 --host-timeout $UDP_HOST_TIMEOUT --stats-every $NMAP_STATS_EVERY -Pn \"$ip\" -oN \"$IP_DIR/udp_fast.txt\""

  (
    $SUDO_BIN timeout $QUICK_HOST_TIMEOUT nmap -n -sU \
      --top-ports 20 \
      --max-retries 1 \
      --host-timeout "$UDP_HOST_TIMEOUT" \
      --stats-every "$NMAP_STATS_EVERY" \
      -Pn "$ip" \
      -oN "$IP_DIR/udp_fast.txt" \
      2>&1 | tee "$IP_DIR/udp_fast_live.log"
  ) &

  UDP_PIDS+=($!)

  generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_quick.txt"

  # =========================
  # NUCLEI NON-WEB (QUICK)
  # =========================
  build_nonweb_targets "$ip" "$IP_DIR/parsed_quick.txt" "$IP_DIR/nuclei_targets_nonweb_quick.txt"

  if [ -s "$IP_DIR/nuclei_targets_nonweb_quick.txt" ]; then
    info "Running Nuclei NON-WEB (QUICK)..."
    sed 's/^/    - /' "$IP_DIR/nuclei_targets_nonweb_quick.txt"

    print_cmd "timeout $NUCLEI_TIMEOUT nuclei -l $IP_DIR/nuclei_targets_nonweb_quick.txt -o $IP_DIR/nuclei_nonweb_quick.txt -s critical,high,medium -nh -ni -duc -ept http 2>&1 | tee $IP_DIR/nuclei_nonweb_quick.log"

    timeout "$NUCLEI_TIMEOUT" nuclei \
      -l "$IP_DIR/nuclei_targets_nonweb_quick.txt" \
      -o "$IP_DIR/nuclei_nonweb_quick.txt" \
      -s critical,high,medium \
      -nh -ni -duc -ept http \
      2>&1 | tee "$IP_DIR/nuclei_nonweb_quick.log"
  else
    warn "No non-web quick targets for $ip"
  fi


  while IFS=';' read -r port service product; do
    enum_service "$ip" "$port" "$service" "$product"
  done < "$IP_DIR/parsed_quick.txt"
done

# ==========================================
# TAHAP 2: DEEP SCAN & NUCLEI
# ==========================================
section "TAHAP 2: NUCLEI PARALLEL (ALL TARGETS)"

for ip in $(safe_target_list); do
  (
    subsection "NUCLEI: $ip"

    IP_DIR="$SCAN_DIR/$ip"
    mkdir -p "$IP_DIR"

    build_web_targets "$ip" "$IP_DIR/parsed_quick.txt" "$IP_DIR/nuclei_targets.txt"

    if [ -s "$IP_DIR/nuclei_targets.txt" ]; then
      info "Running Nuclei..."
      sed 's/^/    - /' "$IP_DIR/nuclei_targets.txt"
      print_cmd "timeout $NUCLEI_TIMEOUT nuclei -s critical,high,medium -l $IP_DIR/nuclei_targets.txt -o $IP_DIR/nuclei.txt -nh -ni -mhe 25 -duc -pt http -etags wordpress -retries 2 2>&1 | tee $IP_DIR/nuclei_live.log"
      timeout "$NUCLEI_TIMEOUT" nuclei \
        -s critical,high,medium \
        -l "$IP_DIR/nuclei_targets.txt" \
        -o "$IP_DIR/nuclei.txt" \
        -nh -ni -mhe 25 -duc -pt http -etags wordpress -retries 2 \
        2>&1 | tee "$IP_DIR/nuclei_live.log"
    else
      warn "No nuclei targets for $ip"
    fi
  ) &

  # LIMIT 3 concurrent
  while [ "$(jobs -rp | wc -l)" -ge 3 ]; do
    sleep 1
  done
done

wait
ok "All Nuclei scans completed"

section "TAHAP 2: RUSTSCAN PARALLEL (ALL TARGETS)"

for ip in $(safe_target_list); do
  (
    subsection "RUSTSCAN: $ip"

    IP_DIR="$SCAN_DIR/$ip"

    run_rustscan_full "$ip"

    if [ ! -s "$IP_DIR/rustscan_ports.txt" ]; then
        warn "RustScan failed or no output for $ip" 
    fi

    build_new_ports_from_rustscan "$IP_DIR"

    if [ -s "$IP_DIR/new_ports.txt" ]; then

      NEW_PORTS=$(paste -sd, "$IP_DIR/new_ports.txt")

      info "New ports discovered by RustScan:"
      cat "$IP_DIR/new_ports.txt"

      print_cmd "nmap -n -Pn -sCV -p $NEW_PORTS --script-timeout 4m --stats-every $NMAP_STATS_EVERY \"$ip\" -oN \"$IP_DIR/new_ports_scv.txt\""

      timeout "$QUICK_HOST_TIMEOUT" nmap \
        -n \
        -Pn \
        -sCV \
        -p "$NEW_PORTS" \
        --script-timeout 4m \
        --stats-every "$NMAP_STATS_EVERY" \
        "$ip" \
        -oN "$IP_DIR/new_ports_scv.txt" \
        2>&1 | tee "$IP_DIR/new_ports_scv_live.log"

      parse_nmap_open "$IP_DIR/new_ports_scv.txt" > "$IP_DIR/parsed_new.txt"

      cat \
        "$IP_DIR/parsed_quick.txt" \
        "$IP_DIR/parsed_new.txt" \
        | sort -u \
        > "$IP_DIR/parsed_full.txt"

      generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_full.txt"

    else

      info "No new RustScan ports found."

      sort -u "$IP_DIR/parsed_quick.txt" \
      > "$IP_DIR/parsed_full.txt"


    fi

    if [[ -s "$IP_DIR/parsed_new.txt" ]]; then
      echo -e "${RED}[!] New ports:${NC}"
      column -t -s';' "$IP_DIR/parsed_new.txt" 2>/dev/null || cat "$IP_DIR/parsed_new.txt"

      while IFS=';' read -r port service product; do
        enum_service "$ip" "$port" "$service" "$product"
      done < "$IP_DIR/parsed_new.txt"

      build_web_targets "$ip" "$IP_DIR/parsed_new.txt" "$IP_DIR/nuclei_targets_new.txt"

      # =========================
      # NUCLEI NON-WEB (NEW PORTS)
      # =========================
      build_nonweb_targets "$ip" "$IP_DIR/parsed_new.txt" "$IP_DIR/nuclei_targets_nonweb_new.txt"

      if [ -s "$IP_DIR/nuclei_targets_nonweb_new.txt" ]; then
        info "Running Nuclei NON-WEB (NEW PORTS)..."
        sed 's/^/    - /' "$IP_DIR/nuclei_targets_nonweb_new.txt"

        print_cmd "timeout $NUCLEI_TIMEOUT nuclei -l $IP_DIR/nuclei_targets_nonweb_new.txt -o $IP_DIR/nuclei_nonweb_new.txt -s critical,high,medium -nh -ni -duc -ept http 2>&1 | tee $IP_DIR/nuclei_nonweb_new.log"

        timeout "$NUCLEI_TIMEOUT" nuclei \
          -l "$IP_DIR/nuclei_targets_nonweb_new.txt" \
          -o "$IP_DIR/nuclei_nonweb_new.txt" \
          -s critical,high,medium \
          -nh -ni -duc -ept http \
          2>&1 | tee "$IP_DIR/nuclei_nonweb_new.log"
      else
        warn "No non-web new targets for $ip"
      fi

      if [ -s "$IP_DIR/nuclei_targets_new.txt" ]; then
        info "Running Nuclei for NEW ports..."
        print_cmd "timeout $NUCLEI_TIMEOUT nuclei -s critical,high,medium -l $IP_DIR/nuclei_targets_new.txt -o $IP_DIR/nuclei_new.txt -duc -pt http -etags wordpress -nh -ni 2>&1 | tee $IP_DIR/nuclei_new_live.log"

        timeout "$NUCLEI_TIMEOUT" nuclei \
          -s critical,high,medium \
          -l "$IP_DIR/nuclei_targets_new.txt" \
          -o "$IP_DIR/nuclei_new.txt" \
          -duc -pt http -etags wordpress -nh -ni \
          2>&1 | tee "$IP_DIR/nuclei_new_live.log"
      fi
    else
      ok "No new ports for $ip"
    fi
  ) &

  while [ "$(jobs -rp | wc -l)" -ge 3 ]; do
    sleep 1
  done
done

wait
ok "All RustScan completed"

# ==========================================
# WAIT UDP SCANS
# ==========================================
section "WAITING FOR UDP BACKGROUND SCANS"

if [ "${#UDP_PIDS[@]}" -gt 0 ]; then
  for pid in "${UDP_PIDS[@]}"; do
    info "Waiting UDP scan PID $pid..."
    wait "$pid" 2>/dev/null
  done
  ok "All UDP background scans finished."
else
  warn "No UDP background PIDs found."
fi

# ==========================================
# PARSE & ENUM UDP RESULTS
# ==========================================
section "PARSING AND ENUMERATING UDP RESULTS"

for ip in $(safe_target_list); do
  IP_DIR="$SCAN_DIR/$ip"

  if [ -s "$IP_DIR/udp_fast.txt" ]; then
    parse_nmap_open "$IP_DIR/udp_fast.txt" > "$IP_DIR/parsed_udp.txt"

    if [ -s "$IP_DIR/parsed_udp.txt" ]; then
      ok "Parsed UDP ports for $ip:"
      column -t -s';' "$IP_DIR/parsed_udp.txt" 2>/dev/null || cat "$IP_DIR/parsed_udp.txt"

      info "Enumerating UDP services for $ip..."
      while IFS=';' read -r port service product; do
        enum_service "$ip" "$port" "$service" "$product"
      done < "$IP_DIR/parsed_udp.txt"
    else
      warn "No open UDP ports parsed for $ip"
    fi
  else
    warn "No udp_fast.txt found or empty for $ip"
  fi
done

# ==========================================
# GLOBAL SUMMARY
# ==========================================
generate_global_summary

echo -e "\n${GREEN}[+] DONE!${NC}"
echo -e "${GREEN}[+] Check output in:${NC} $SCAN_DIR"
echo -e "${GREEN}[+] Master log:${NC} $MASTER_LOG"

# ==========================================
# FINAL: GENERATE EXCEL REPORT (AUTOENUM)
# ==========================================
section "FINAL: GENERATING EXCEL REPORT"

AUTOENUM_SCRIPT="/opt/autorecon/autoenum_generateexcel.py"
LOCAL_SCRIPT="$SCAN_DIR/autoenum_generateexcel.py"

if [ ! -f "$AUTOENUM_SCRIPT" ]; then
  err "Autoenum script not found at: $AUTOENUM_SCRIPT"
  warn "Skipping Excel report generation."
else
  if ! has_cmd python3; then
    err "python3 not found. Cannot execute autoenum script."
    warn "Skipping Excel report generation."
  else
    info "Preparing Autoenum Generate Summary Excel Python script..."

    print_cmd "cp \"$AUTOENUM_SCRIPT\" \"$LOCAL_SCRIPT\""
    cp "$AUTOENUM_SCRIPT" "$LOCAL_SCRIPT"

    if [ ! -f "$LOCAL_SCRIPT" ]; then
      err "Failed to copy autoenum script."
    else
      info "Running Autoenum Generate Summary Excel Python script..."

      (
        cd "$SCAN_DIR" || exit

        print_cmd "python3 autoenum_generateexcel.py"

        python3 autoenum_generateexcel.py 2>&1 | tee "$SCAN_DIR/autoenum.log"

        if [ "${PIPESTATUS[0]}" -ne 0 ]; then
          err "Autoenum script execution failed!"
        else
          ok "Excel report generated successfully."
        fi
      )
    fi
  fi
fi
