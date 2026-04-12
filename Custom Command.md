# ⚙️ Custom Commands (Kali Linux)

Kumpulan shortcut untuk mempercepat workflow pentest / OSCP.

---

## 1️⃣ 🌐 webserver

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

## 2️⃣ 🖥️ rdp

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
