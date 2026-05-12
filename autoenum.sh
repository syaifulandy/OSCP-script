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
QUICK_HOST_TIMEOUT="3m"
UDP_HOST_TIMEOUT="3m"
NUCLEI_TIMEOUT="5m"
RUSTSCAN_TIMEOUT="12m"
NMAP_STATS_EVERY="15s"

FFUF_SCRIPT="/opt/ffuf/ffufscan.sh"
WPSCAN_SCRIPT="/opt/wpscan/wpscan.sh"

UDP_PIDS=()

# =========================
# BASIC VALIDATION
# =========================
if [ -z "$TARGETS" ] || [ ! -f "$TARGETS" ]; then
  echo -e "${RED}[-] Usage: $0 targets.txt${NC}"
  exit 1
fi

mkdir -p "$SCAN_DIR"

# =========================
# LOGGING
# =========================
MASTER_LOG="$SCAN_DIR/master_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$MASTER_LOG") 2>&1

echo -e "${GREEN}[+] Master log: $MASTER_LOG${NC}"

# =========================
# HELPERS
# =========================
print_cmd() {
  echo -e "${CYAN}[CMD]${NC} $*"
}

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
    if ($start == "ttl") {
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

# =========================
# BUILD WEB TARGETS
# =========================
build_web_targets() {
  local ip="$1"
  local parsed_file="$2"
  local output_file="$3"

  : > "$output_file"

  if [ ! -s "$parsed_file" ]; then
    return
  fi

  while IFS=';' read -r port service product; do
    [[ -z "$port" || -z "$service" ]] && continue

    if [[ "$service" == http* || "$service" == *http* || "$service" == https* || "$service" == ssl/http* ]]; then
      if [[ "$port" == "5985" || "$port" == "5986" || "$port" == "47001" ]]; then
        continue
      fi

      local scheme="http"

      if [[ "$service" == *https* || "$service" == ssl/http* || "$port" == "443" || "$port" == "8443" || "$port" == "9443" || "$port" == "10443" ]]; then
        scheme="https"
      fi

      echo "$scheme://$ip:$port" >> "$output_file"
    fi
  done < "$parsed_file"

  sort -u "$output_file" -o "$output_file"
}


# ==========================================
# NORMALIZE PRODUCT BANNER
# ==========================================
normalize_product_banner() {
  echo "$1" \
    | sed -E 's/^(syn-ack|udp-response|reset|conn-refused|no-response|echo-reply|arp-response|localhost-response)( ttl [0-9]+)?[[:space:]]*//I' \
    | sed -E 's/\(\([^)]*\)\)//g' \
    | sed -E 's/\([^)]*\)//g' \
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
    | sed -E 's/[[:space:]]+/ /g' \
    | sed -E 's/[[:space:]]+\|[[:space:]]+/ | /g' \
    | sed -E 's/^[[:space:]]+|[[:space:]]+$//g'
}

# ==========================================
# REMOTE EXPLOIT FILTER
# ==========================================
is_remote_exploit_line() {
  local line="$1"

  echo "$line" \
    | grep -iE "Remote|RCE|Code Execution|Execution|Overflow|Path Traversal|Command Execution|Command Injection" \
    | grep -viE "Denial of Service|DoS|\.txt" >/dev/null
}

# ==========================================
# LOCAL PRIVESC FILTER
# Avoid false positive like "Local File Inclusion"
# ==========================================
is_local_privesc_line() {
  local line="$1"
  local title
  local path

  title=$(echo "$line" | awk -F'|' '{print $1}')
  path=$(echo "$line" | awk -F'|' '{print $2}')

  # Path-based local exploit
  echo "$path" | grep -qiE '/local/' && return 0

  # Title-based privilege escalation only
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

  # Version-only fallback, useful for Apache 2.4.49
  [[ -n "$version" ]] && echo "$version"

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

  local cleaned
  local first_word
  local service_clean

  cleaned=$(normalize_product_banner "$product")
  first_word=$(echo "$cleaned" | awk '{print $1}' | sed 's/[?]//g')
  service_clean=$(echo "$service" | sed 's/[?]//g')

  [[ -n "$first_word" ]] && echo "$first_word"

  if echo "$cleaned" | grep -qiE '^Apache'; then
    echo "Apache"
    echo "Apache HTTP Server"
    echo "Apache httpd"
  fi

  if echo "$cleaned" | grep -qiE '^OpenSSH'; then
    echo "OpenSSH"
  fi

  if echo "$cleaned" | grep -qiE 'Samba|smbd'; then
    echo "Samba"
    echo "smbd"
  fi

  if echo "$cleaned" | grep -qiE '^vsftpd'; then
    echo "vsftpd"
  fi

  if echo "$cleaned" | grep -qiE '^ProFTPD'; then
    echo "ProFTPD"
  fi

  if echo "$cleaned" | grep -qiE 'Tomcat'; then
    echo "Tomcat"
    echo "Apache Tomcat"
  fi

  # Service fallback only if not generic/noisy
  case "$service_clean" in
    ""|"unknown"|"tcpwrapped"|"msrpc"|"netbios-ssn"|"microsoft-ds")
      ;;
    "http"|"https"|"ssl/http"|"http-proxy"|"http-alt")
      ;;
    "domain"|"dns"|"snmp")
      ;;
    *)
      echo "$service_clean"
      ;;
  esac
}

# ==========================================
# HIGH CONFIDENCE CHECK
# Strict:
# If product has version, exploit title must contain vendor/app + exact version.
# ==========================================
is_high_confidence_exploit() {
  local title="$1"
  local product="$2"
  local query="$3"

  local cleaned
  local title_lc
  local version
  local vendor

  cleaned=$(normalize_product_banner "$product")
  title_lc=$(echo "$title" | tr '[:upper:]' '[:lower:]')
  version=$(extract_version "$cleaned $query")
  vendor=$(extract_vendor "$cleaned")

  [[ -z "$version" || -z "$vendor" ]] && return 1

  # Exact version must exist in title
  echo "$title_lc" | grep -Fqi "$version" || return 1

  # Vendor/app must exist in title
  echo "$title_lc" | grep -Fqi "$vendor" && return 0

  # Apache alias handling
  if [[ "$vendor" == "apache" ]]; then
    echo "$title_lc" | grep -Eqi 'apache|http server|httpd' && return 0
  fi

  return 1
}

# ==========================================
# GENERATE EXPLOIT SUMMARY
# Remote High Confidence vs Generic/Broad vs Local PrivEsc
# ==========================================
generate_exploit_summary() {
  local ip_dir="$1"
  local parsed_file="$2"

  local remote_out="$ip_dir/exploits_remote.txt"
  local generic_out="$ip_dir/exploits_remote_generic.txt"
  local local_out="$ip_dir/exploits_privesc.txt"

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

    # Skip useless rows
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
    local high_queries
    high_queries=$(mktemp)

    build_searchsploit_queries_high "$product" \
      | sed 's/[?]//g' \
      | sed -E 's/[[:space:]]+/ /g' \
      | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
      | awk 'length($0) >= 2' \
      | sort -u > "$high_queries"

    while IFS= read -r ss_query; do
      [[ -z "$ss_query" ]] && continue

      if grep -Fxqi "HIGH::$ss_query" "$tmp_queries_seen"; then
        continue
      fi
      echo "HIGH::$ss_query" >> "$tmp_queries_seen"

      print_cmd "COLUMNS=300 searchsploit -t \"$ss_query\" | remote filter"

      while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local norm_line
        local title

        norm_line=$(normalize_searchsploit_line "$line")
        title=$(echo "$norm_line" | awk -F'|' '{print $1}' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')

        if is_remote_exploit_line "$norm_line"; then
          if is_high_confidence_exploit "$title" "$product" "$ss_query"; then
            echo "$norm_line" >> "$tmp_high"
          else
            echo "$norm_line" >> "$tmp_generic"
          fi
        fi

        if is_local_privesc_line "$norm_line"; then
          echo "$norm_line" >> "$tmp_loc"
        fi
      done < <(
        COLUMNS=300 searchsploit -t "$ss_query" 2>/dev/null \
          | grep -viE "Shellcodes:|No Results|Exploit Title|----"
      )

    done < "$high_queries"

    rm -f "$high_queries"

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
      | sort -u > "$generic_queries"

    while IFS= read -r ss_query; do
      [[ -z "$ss_query" ]] && continue

      if grep -Fxqi "GENERIC::$ss_query" "$tmp_queries_seen"; then
        continue
      fi
      echo "GENERIC::$ss_query" >> "$tmp_queries_seen"

      print_cmd "COLUMNS=300 searchsploit -t \"$ss_query\" | generic remote filter"

      while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local norm_line
        norm_line=$(normalize_searchsploit_line "$line")

        if is_remote_exploit_line "$norm_line"; then
          echo "$norm_line" >> "$tmp_generic"
        fi

        if is_local_privesc_line "$norm_line"; then
          echo "$norm_line" >> "$tmp_loc"
        fi
      done < <(
        COLUMNS=300 searchsploit -t "$ss_query" 2>/dev/null \
          | grep -viE "Shellcodes:|No Results|Exploit Title|----"
      )

    done < "$generic_queries"

    rm -f "$generic_queries"

  done < "$parsed_file"

  # -------------------------
  # WRITE HIGH CONFIDENCE FILE
  # -------------------------
  {
    echo "======================================================"
    echo "   SPECIFIC REMOTE EXPLOITS (High Confidence)"
    echo "======================================================"

    if [ -s "$tmp_high" ]; then
      sort -u "$tmp_high"
    else
      echo "No obvious high-confidence Remote/RCE exploit found from service banners."
    fi
  } > "$remote_out"

  # -------------------------
  # WRITE GENERIC FILE
  # -------------------------
  {
    echo "======================================================"
    echo "   GENERIC REMOTE SEARCH (Product/App Based)"
    echo "======================================================"
    echo "Review manually. These are lower confidence results."
    echo "======================================================"

    if [ -s "$tmp_generic" ]; then
      comm -23 <(sort -u "$tmp_generic") <(sort -u "$tmp_high")
    else
      echo "No generic remote results generated."
    fi
  } > "$generic_out"

  # -------------------------
  # WRITE LOCAL PRIVESC FILE
  # -------------------------
  {
    echo "======================================================"
    echo "   LOCAL PRIVILEGE ESCALATION CANDIDATES"
    echo "======================================================"

    if [ -s "$tmp_loc" ]; then
      sort -u "$tmp_loc"
    else
      echo "No obvious Local PrivEsc found in service banners."
    fi
  } > "$local_out"

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

  info "Enumerating service=$service product=\"$product\" on port $port..."

  # -------------------------
  # HTTP / HTTPS
  # -------------------------
  if [[ "$service" == http* || "$service" == *http* || "$service" == https* || "$service" == ssl/http* ]]; then
    if [[ "$port" == "5985" || "$port" == "5986" || "$port" == "47001" ]]; then
      warn "Skipping Web Discovery for WinRM-like port ($port) on $ip"
      return
    fi

    local scheme="http"
    if [[ "$service" == *https* || "$service" == ssl/http* || "$port" == "443" || "$port" == "8443" || "$port" == "9443" || "$port" == "10443" ]]; then
      scheme="https"
    fi

    local url="$scheme://$ip:$port"
    local web_dir="$ip_dir/web_$port"
    mkdir -p "$web_dir"

    print_cmd "curl -k -s -L --max-time 7 \"$url\""
    curl -k -s -L --max-time 7 "$url" | tee "$web_dir/index.html" >/dev/null

    if grep -qiE "wordpress|wp-content|wp-includes" "$web_dir/index.html"; then
      ok "WordPress detected on $url"

      if [ -x "$WPSCAN_SCRIPT" ]; then
        (
          cd "$web_dir" || exit
          print_cmd "$WPSCAN_SCRIPT \"$url\" fast"
          "$WPSCAN_SCRIPT" "$url" fast 2>&1 | tee "$web_dir/wpscan.log"
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
  # FTP - no rescan
  # -------------------------
  if [[ "$service" == ftp* ]]; then
    local ftp_dir="$ip_dir/ftp_$port"
    mkdir -p "$ftp_dir"

    {
      echo "FTP detected on $ip:$port"
      echo "Service: $service"
      echo "Product: $product"
      echo
      echo "Note:"
      echo "- No extra nmap scan executed because quick/full scan already used -sCV."
      echo "- Manual checks to consider:"
      echo "  ftp $ip $port"
      echo "  anonymous / anonymous"
      echo "  anonymous / anonymous@"
    } | tee "$ftp_dir/ftp_notes.txt"
  fi

  # -------------------------
  # SSH - no rescan
  # -------------------------
  if [[ "$service" == ssh* ]]; then
    local ssh_dir="$ip_dir/ssh_$port"
    mkdir -p "$ssh_dir"

    {
      echo "SSH detected on $ip:$port"
      echo "Service: $service"
      echo "Product: $product"
      echo
      echo "Note:"
      echo "- No extra nmap scan executed because quick/full scan already used -sCV."
      echo "- Manual checks to consider:"
      echo "  ssh user@$ip -p $port"
      echo "  check banner/version against exploits_remote.txt"
      echo "  check credential reuse if creds are found later"
    } | tee "$ssh_dir/ssh_notes.txt"
  fi

  # -------------------------
  # RDP - no rescan
  # -------------------------
  if [[ "$service" == ms-wbt-server* || "$service" == rdp* || "$port" == "3389" ]]; then
    local rdp_dir="$ip_dir/rdp_$port"
    mkdir -p "$rdp_dir"

    {
      echo "RDP detected on $ip:$port"
      echo "Service: $service"
      echo "Product: $product"
      echo
      echo "Note:"
      echo "- No extra nmap scan executed because quick/full scan already used -sCV."
      echo "- Manual checks to consider:"
      echo "  xfreerdp /v:$ip:$port /u:user /p:password /cert:ignore"
      echo "  check credential reuse if creds are found later"
    } | tee "$rdp_dir/rdp_notes.txt"
  fi

  # -------------------------
  # DNS - blackbox
  # -------------------------
  if [[ "$service" == domain* || "$service" == dns* || "$port" == "53" ]]; then
    local dns_dir="$ip_dir/dns_$port"
    mkdir -p "$dns_dir"

    info "Running DNS blackbox enumeration on $ip:$port"

    print_cmd "nmap -Pn -p \"$port\" -sCV --script dns-nsid,dns-recursion,dns-service-discovery \"$ip\" -oN \"$dns_dir/dns_basic.txt\""

    nmap -Pn -p "$port" -sCV \
      --script dns-nsid,dns-recursion,dns-service-discovery \
      "$ip" \
      -oN "$dns_dir/dns_basic.txt" \
      2>&1 | tee "$dns_dir/dns_basic_live.log"

    if has_cmd dig; then
      print_cmd "dig @$ip -x $ip +short"
      dig @"$ip" -x "$ip" +short 2>&1 | tee "$dns_dir/reverse_lookup.txt"
    fi

    : > "$dns_dir/zone_candidates.txt"

    if [ -s "$dns_dir/reverse_lookup.txt" ]; then
      sed 's/\.$//' "$dns_dir/reverse_lookup.txt" \
        | awk -F'.' 'NF>=2 {
            print $(NF-1)"."$NF
            if (NF>=3) print $(NF-2)"."$(NF-1)"."$NF
          }' >> "$dns_dir/zone_candidates.txt"
    fi

    grep -Eoi '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' "$dns_dir/dns_basic.txt" 2>/dev/null \
      | sed 's/\.$//' \
      | awk -F'.' 'NF>=2 {
          print $(NF-1)"."$NF
          if (NF>=3) print $(NF-2)"."$(NF-1)"."$NF
        }' >> "$dns_dir/zone_candidates.txt"

    sort -u "$dns_dir/zone_candidates.txt" -o "$dns_dir/zone_candidates.txt"

    if [ -s "$dns_dir/zone_candidates.txt" ]; then
      info "Trying AXFR against discovered zone candidates..."
      sed 's/^/    - /' "$dns_dir/zone_candidates.txt"

      while read -r zone; do
        [[ -z "$zone" ]] && continue

        local safe_zone
        safe_zone=$(sanitize_filename "$zone")

        print_cmd "nmap -Pn -p \"$port\" --script dns-zone-transfer --script-args dns-zone-transfer.domain=\"$zone\" \"$ip\" -oN \"$dns_dir/axfr_${safe_zone}.txt\""

        nmap -Pn -p "$port" \
          --script dns-zone-transfer \
          --script-args "dns-zone-transfer.domain=$zone" \
          "$ip" \
          -oN "$dns_dir/axfr_${safe_zone}.txt" \
          2>&1 | tee "$dns_dir/axfr_${safe_zone}_live.log"

        if has_cmd dig; then
          print_cmd "dig @$ip $zone axfr"
          dig @"$ip" "$zone" axfr 2>&1 | tee "$dns_dir/dig_axfr_${safe_zone}.txt"
        fi
      done < "$dns_dir/zone_candidates.txt"
    else
      warn "No DNS zone candidates discovered. Skipping AXFR."
    fi
  fi

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

    print_cmd "$SUDO_BIN nmap -Pn -sU --open -p \"$port\" \"$ip\" -oN \"$snmp_dir/snmp_open.txt\""

    $SUDO_BIN nmap -Pn -sU --open -p "$port" "$ip" \
      -oN "$snmp_dir/snmp_open.txt" \
      2>&1 | tee "$snmp_dir/snmp_open_live.log"

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

    print_cmd "$SUDO_BIN nmap -Pn -sU -p \"$port\" --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr \"$ip\" -oN \"$snmp_dir/snmp_nmap_scripts.txt\""

    $SUDO_BIN nmap -Pn -sU -p "$port" \
      --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr \
      "$ip" \
      -oN "$snmp_dir/snmp_nmap_scripts.txt" \
      2>&1 | tee "$snmp_dir/snmp_nmap_scripts_live.log"

    if has_cmd snmpwalk; then
      while read -r community; do
        [[ -z "$community" ]] && continue

        local safe_community
        safe_community=$(sanitize_filename "$community")

        info "SNMP community candidate: $community"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\""
        snmpwalk -c "$community" -v1 -t 10 "$ip" \
          2>&1 | tee "$snmp_dir/snmpwalk_${safe_community}_full.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.25.1.6.0"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.25.1.6.0 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_system_processes.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.25.4.2.1.2"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.25.4.2.1.2 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_running_programs.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.25.4.2.1.4"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.25.4.2.1.4 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_process_paths.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.25.2.3.1.4"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.25.2.3.1.4 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_storage_units.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.25.6.3.1.2"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.25.6.3.1.2 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_software_names.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.4.1.77.1.2.25"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.4.1.77.1.2.25 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_windows_users.txt"

        print_cmd "snmpwalk -c \"$community\" -v1 -t 10 \"$ip\" 1.3.6.1.2.1.6.13.1.3"
        snmpwalk -c "$community" -v1 -t 10 "$ip" 1.3.6.1.2.1.6.13.1.3 \
          2>&1 | tee "$snmp_dir/snmp_${safe_community}_tcp_local_ports.txt"

      done < "$snmp_dir/communities_found.txt"
    else
      warn "snmpwalk not found. Skipping SNMP MIB walk."
    fi
  fi
}

# =========================
# RUN RUSTSCAN FULL
# =========================
run_rustscan_full() {
  local ip="$1"
  local ip_dir="$SCAN_DIR/$ip"

  print_cmd "timeout $RUSTSCAN_TIMEOUT rustscan -a \"$ip\" -r 1-65535 --tries 3 --ulimit 5000 -- -Pn -sCV --stats-every $NMAP_STATS_EVERY -oN \"$ip_dir/full.txt\""

  timeout "$RUSTSCAN_TIMEOUT" rustscan -a "$ip" \
    -r 1-65535 \
    --tries 3 \
    --ulimit 5000 \
    -- \
    -Pn -sCV --stats-every "$NMAP_STATS_EVERY" -oN "$ip_dir/full.txt" \
    2>&1 | tee "$ip_dir/rustscan_live.log"
}

# =========================
# BUILD NEW PORTS ONLY
# Compare by port only.
# =========================
build_new_ports_only() {
  local quick_file="$1"
  local full_file="$2"
  local new_file="$3"

  : > "$new_file"

  if [ ! -s "$full_file" ]; then
    return
  fi

  if [ ! -s "$quick_file" ]; then
    cp "$full_file" "$new_file"
    return
  fi

  awk -F';' '
    NR==FNR {
      old_ports[$1]=1
      next
    }
    !($1 in old_ports) {
      print
    }
  ' "$quick_file" "$full_file" > "$new_file"
}

# =========================
# GLOBAL SUMMARY
# =========================
generate_global_summary() {
  section "GENERATING GLOBAL SUMMARY"

  local global_remote="$SCAN_DIR/global_exploits_remote.txt"
  local global_privesc="$SCAN_DIR/global_exploits_privesc.txt"
  local global_ports="$SCAN_DIR/global_open_ports.txt"

  print_cmd "find \"$SCAN_DIR\" -name exploits_remote.txt -exec cat {} \\; | sort -u > \"$global_remote\""
  find "$SCAN_DIR" -mindepth 2 -maxdepth 2 -name "exploits_remote.txt" -print0 \
    | xargs -0 cat 2>/dev/null \
    | sort -u > "$global_remote"

  print_cmd "find \"$SCAN_DIR\" -name exploits_privesc.txt -exec cat {} \\; | sort -u > \"$global_privesc\""
  find "$SCAN_DIR" -mindepth 2 -maxdepth 2 -name "exploits_privesc.txt" -print0 \
    | xargs -0 cat 2>/dev/null \
    | sort -u > "$global_privesc"

  : > "$global_ports"
  for ip in $(safe_target_list); do
    local pf="$SCAN_DIR/$ip/parsed_full.txt"
    local pq="$SCAN_DIR/$ip/parsed_quick.txt"
    local pu="$SCAN_DIR/$ip/parsed_udp.txt"

    if [ -s "$pf" ]; then
      awk -F';' -v ip="$ip" '{print ip ";tcp;" $0}' "$pf" >> "$global_ports"
    elif [ -s "$pq" ]; then
      awk -F';' -v ip="$ip" '{print ip ";tcp;" $0}' "$pq" >> "$global_ports"
    fi

    if [ -s "$pu" ]; then
      awk -F';' -v ip="$ip" '{print ip ";udp;" $0}' "$pu" >> "$global_ports"
    fi
  done

  sort -u "$global_ports" -o "$global_ports"

  ok "Global files:"
  echo "    - $global_remote"
  echo "    - $global_privesc"
  echo "    - $global_ports"
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

  nmap -sC -sV \
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
  print_cmd "$SUDO_BIN nmap -sU -sV --top-ports 20 --max-retries 1 --host-timeout $UDP_HOST_TIMEOUT --stats-every $NMAP_STATS_EVERY -Pn \"$ip\" -oN \"$IP_DIR/udp_fast.txt\""

  (
    $SUDO_BIN nmap -sU -sV \
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

  while IFS=';' read -r port service product; do
    enum_service "$ip" "$port" "$service" "$product"
  done < "$IP_DIR/parsed_quick.txt"
done

# ==========================================
# TAHAP 2: DEEP SCAN & NUCLEI
# ==========================================
section "TAHAP 2: DEEP SCAN & NUCLEI PARALLEL (ALL TARGETS)"

for ip in $(safe_target_list); do
  subsection "DEEP SCANNING: $ip"

  IP_DIR="$SCAN_DIR/$ip"
  mkdir -p "$IP_DIR"

  build_web_targets "$ip" "$IP_DIR/parsed_quick.txt" "$IP_DIR/nuclei_targets.txt"

  NUCLEI_PID=""

  if [ -s "$IP_DIR/nuclei_targets.txt" ]; then
    info "Running Nuclei in background while RustScan runs..."
    info "Nuclei targets:"
    sed 's/^/    - /' "$IP_DIR/nuclei_targets.txt"

    print_cmd "timeout $NUCLEI_TIMEOUT nuclei -s critical,high,medium -l \"$IP_DIR/nuclei_targets.txt\" -o \"$IP_DIR/nuclei.txt\" -nh -ni"

    (
      timeout "$NUCLEI_TIMEOUT" nuclei \
        -s critical,high,medium \
        -l "$IP_DIR/nuclei_targets.txt" \
        -o "$IP_DIR/nuclei.txt" \
        -nh -ni \
        2>&1 | tee "$IP_DIR/nuclei_live.log"
    ) &

    NUCLEI_PID=$!
  else
    warn "No quick web targets found for nuclei on $ip."
  fi

  info "Running RustScan Full Port..."
  run_rustscan_full "$ip"

  if [[ -n "$NUCLEI_PID" ]]; then
    info "Waiting for Nuclei PID $NUCLEI_PID to finish..."
    wait "$NUCLEI_PID"
    ok "Nuclei finished for $ip"
  fi

  parse_nmap_open "$IP_DIR/full.txt" > "$IP_DIR/parsed_full.txt"

  if [ -s "$IP_DIR/parsed_full.txt" ]; then
    ok "Parsed full open ports:"
    column -t -s';' "$IP_DIR/parsed_full.txt" 2>/dev/null || cat "$IP_DIR/parsed_full.txt"
  else
    warn "No open ports parsed from full scan for $ip"
  fi

  build_new_ports_only "$IP_DIR/parsed_quick.txt" "$IP_DIR/parsed_full.txt" "$IP_DIR/parsed_new.txt"

  if [[ -s "$IP_DIR/parsed_new.txt" ]]; then
    echo -e "${RED}[!] New ports found from full scan:${NC}"
    column -t -s';' "$IP_DIR/parsed_new.txt" 2>/dev/null || cat "$IP_DIR/parsed_new.txt"

    info "Updating exploit summaries using parsed_full.txt..."
    generate_exploit_summary "$IP_DIR" "$IP_DIR/parsed_full.txt"

    info "Enumerating only NEW ports..."
    while IFS=';' read -r port service product; do
      enum_service "$ip" "$port" "$service" "$product"
    done < "$IP_DIR/parsed_new.txt"

    build_web_targets "$ip" "$IP_DIR/parsed_new.txt" "$IP_DIR/nuclei_targets_new.txt"

    if [ -s "$IP_DIR/nuclei_targets_new.txt" ]; then
      info "Running Nuclei on NEW web targets only..."
      sed 's/^/    - /' "$IP_DIR/nuclei_targets_new.txt"

      print_cmd "timeout $NUCLEI_TIMEOUT nuclei -s critical,high,medium -l \"$IP_DIR/nuclei_targets_new.txt\" -o \"$IP_DIR/nuclei_new.txt\" -nh -ni"

      timeout "$NUCLEI_TIMEOUT" nuclei \
        -s critical,high,medium \
        -l "$IP_DIR/nuclei_targets_new.txt" \
        -o "$IP_DIR/nuclei_new.txt" \
        -nh -ni \
        2>&1 | tee "$IP_DIR/nuclei_new_live.log"
    fi
  else
    ok "No new ports found. Skipping re-enumeration."
  fi
done

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
