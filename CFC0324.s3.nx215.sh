#!/bin/bash
################################################################################
#                        SOC Analyst Project: CHECKER                          #
#                           Program Code: NX215                                #
#                                                                              #
# STUDENT NAME	: PENG SEYHA                                                   #
# SCODE	        : s3                                                           #
# UNIT NAME	    : TCI-2510-CAMBODIA-SOC                                        #
# Class Code    : E201                                              	       #
# Lecturer	    : RONAK Singh                                         	       #
#                                                                              #
################################################################################
#                                REFERENCES                                    #
################################################################################
#                                                                              #
# 1. Bash Scripting                                                            #
#    - Advanced Bash-Scripting Guide by Mendel Cooper                         #
#    - https://tldp.org/LDP/abs/html/                                         #
#    - Used as the main programming language for building the SOC simulator   #
#      including menus, attack simulation logic, logging, and automation      #
#                                                                              #
# 2. Kali Linux                                                                #
#    - Kali Linux Official Documentation                                      #
#    - https://www.kali.org/docs/                                             #
#    - Used as the main operating system for development and execution        #
#      because it provides strong cybersecurity tools and environment         #
#                                                                              #
# 3. Nmap                                                                      #
#    - Nmap Network Scanning by Gordon Lyon                                   #
#    - https://nmap.org/book/                                                 #
#    - Used for network discovery, host detection, and port scanning         #
#                                                                              #
# 4. Linux Terminal                                                            #
#    - GNU Bash Manual                                                        #
#    - https://www.gnu.org/software/bash/manual/                             #
#    - Used for running the project, monitoring outputs, and managing logs   #
#                                                                              #
# 5. Log Files (/var/log)                                                      #
#    - The Art of Unix Programming by Eric Raymond                           #
#    - http://www.catb.org/~esr/writings/taoup/                             #
#    - Used for storing attack history, incident reports, and investigation  #
#      summaries for later review                                             #
#                                                                              #
# 6. MITRE ATT&CK Mapping                                                      #
#    - MITRE ATT&CK Framework                                                 #
#    - https://attack.mitre.org/                                              #
#    - Used for classifying attack behavior and improving investigation      #
#      realism in SOC analysis                                                #
#                                                                              #
# 7. ANSI Color System                                                         #
#    - ANSI/VT100 Control Sequences                                           #
#    - https://misc.flogisoft.com/bash/tip_colors_and_formatting            #
#    - Used for implementing color-coded dashboard output and alert display  #
#                                                                              #
# 8. Shell Utilities                                                           #
#    - Linux Command Line and Shell Scripting Bible                          #
#    - Wiley Publishing                                                       #
#    - Used for commands such as grep, awk, sed, cut, wc, tail, and date    #
#      for parsing data and formatting reports                                #
#                                                                              #
################################################################################
C_PRIMARY='\033[38;5;51m'
C_SUCCESS='\033[38;5;46m'
C_WARN='\033[38;5;226m'
C_DANGER='\033[38;5;196m'
C_ACCENT='\033[38;5;201m'

C_BLUE='\033[38;5;39m'
C_WHITE='\033[1;97m'
C_GRAY='\033[38;5;250m'
C_DIM='\033[2m'
C_BOLD='\033[1m'

C_BG_RED='\033[48;5;52m'
C_BG_DARK='\033[48;5;234m'

NC='\033[0m'

PROG_NAME="CyberShield Elite"
PROG_VERSION="6.2"
PROG_CODE="s3"
PROG_AUTHOR="Peng Seyha"

LOG_DIR=""
LOG_FILE=""
REPORT_FILE=""
SUMMARY_FILE=""
CORRELATION_FILE=""
IOC_FILE=""
SELECTED_SCAN_RANGE=""
SELECTED_TARGET=""
CURRENT_NETWORK_RANGE=""
UI_WIDTH=106
SESSION_INCIDENTS=0
SESSION_LAST_ATTACK=""
SESSION_LAST_SEVERITY=""
SESSION_LAST_TARGET=""
SESSION_LAST_RISK=0

_setup_log_paths() {
    if [ -w /var/log ] 2>/dev/null || [ "$(id -u)" -eq 0 ]; then
        LOG_DIR="/var/log/cybershield"
    else
        LOG_DIR="$HOME/.cybershield/logs"
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || { echo "Cannot create log directory: $LOG_DIR"; exit 1; }
    chmod 700 "$LOG_DIR" 2>/dev/null || true
    LOG_FILE="$LOG_DIR/incidents.log"
    REPORT_FILE="$LOG_DIR/reports.log"
    SUMMARY_FILE="$LOG_DIR/summary.log"
    CORRELATION_FILE="$LOG_DIR/correlation.log"
    IOC_FILE="$LOG_DIR/ioc_export.txt"
    local f
    for f in "$LOG_FILE" "$REPORT_FILE" "$SUMMARY_FILE" "$CORRELATION_FILE" "$IOC_FILE"; do
        touch "$f" 2>/dev/null || { echo "Cannot create: $f"; exit 1; }
        chmod 600 "$f" 2>/dev/null || true
    done
}

TMP_DIR="$(mktemp -d /tmp/cybershield.XXXXXX)"
TMP_SCAN="$TMP_DIR/nmap_scan.txt"
TMP_AVAILABLE_IPS="$TMP_DIR/available_ips"
TMP_SELECTED_TARGET="$TMP_DIR/selected_target"

cleanup() {
    tput cnorm 2>/dev/null || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'echo -e "\n${C_WARN}[!] Interrupted. Exiting safely.${NC}"; cleanup; exit 130' INT TERM

ui_term_width() {
    local cols w
    cols=$(tput cols 2>/dev/null || echo 132)
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=132

    # Keep boxes inside the real terminal width.
    # This prevents wrapped borders and broken SYSTEM MESSAGES bottom lines.
    w=$((cols - 4))
    [ "$w" -lt 100 ] && w=100
    [ "$w" -gt 132 ] && w=132
    echo "$w"
}

ui_repeat() {
    local char="$1" count="$2" out="" i
    [ "$count" -le 0 ] 2>/dev/null && echo "" && return
    for ((i=0; i<count; i++)); do out+="$char"; done
    echo "$out"
}

ui_strip_ansi() {
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g'
}

ui_text_len() {
    local stripped
    stripped=$(ui_strip_ansi "$1")
    echo ${#stripped}
}

ui_pad_right() {
    local max="$1" text="$2"
    local clean len pad
    clean=$(ui_strip_ansi "$text")
    len=${#clean}
    pad=$((max - len))
    [ "$pad" -lt 0 ] && pad=0
    printf "%b%s" "$text" "$(ui_repeat " " $pad)"
}

ui_box_top() {
    local w="$1" title="${2:-}"
    local inner=$((w - 2))
    if [ -n "$title" ]; then
        local titled="  ${C_BOLD}${C_WHITE}${title}${NC}  "
        local tlen
        tlen=$(ui_text_len "$titled")
        local left=$(( (inner - tlen) / 2 ))
        local right=$(( inner - tlen - left ))
        [ "$left" -lt 0 ] && left=0
        [ "$right" -lt 0 ] && right=0
        echo -e "${C_PRIMARY}╔$(ui_repeat "═" $left)${titled}${C_PRIMARY}$(ui_repeat "═" $right)╗${NC}"
    else
        echo -e "${C_PRIMARY}╔$(ui_repeat "═" $inner)╗${NC}"
    fi
}

ui_box_line() {
    local w="$1" content="${2:-}"
    local inner=$((w - 4))
    local padded
    padded=$(ui_pad_right "$inner" "$content")
    echo -e "${C_PRIMARY}║ ${NC}${padded}${C_PRIMARY} ║${NC}"
}

ui_box_separator() {
    local w="$1"
    local inner=$((w - 2))
    echo -e "${C_PRIMARY}╠$(ui_repeat "═" $inner)╣${NC}"
}

ui_box_bottom() {
    local w="$1"
    local inner=$((w - 2))
    echo -e "${C_PRIMARY}╚$(ui_repeat "═" $inner)╝${NC}"
}

status_ok()    { echo -e " ${C_SUCCESS}[✓]${NC} $*"; }
status_warn()  { echo -e " ${C_WARN}[!]${NC} $*"; }
status_error() { echo -e " ${C_DANGER}[✗]${NC} $*"; }
status_info()  { echo -e " ${C_PRIMARY}[›]${NC} $*"; }

safe_read() {
    local prompt="$1" varname="$2"
    echo -ne "\n ${C_PRIMARY}▶${NC} ${C_WHITE}${prompt}${NC} "
    # shellcheck disable=SC2229  # read -r "$varname" correctly reads into the named variable
    read -r "$varname" 2>/dev/null || true
}

pause_screen() {
    local rows pause_row

    # If the shortcuts footer is pinned, keep pause text above it.
    if [ "${PINNED_FOOTER_ACTIVE:-0}" = "1" ]; then
        rows=$(tput lines 2>/dev/null || echo 30)
        pause_row=$((rows - 4))
        [ "$pause_row" -lt 0 ] && pause_row=0
        tput cup "$pause_row" 0 2>/dev/null || true
        printf "\033[2K"
        echo -ne " ${C_GRAY}[ Press ENTER to continue ]${NC}"
        read -r 2>/dev/null || true
        printf "\033[2K"
        return
    fi

    echo ""
    echo -ne " ${C_GRAY}[ Press ENTER to continue ]${NC}"
    read -r 2>/dev/null || true
    echo ""
}

ui_loading_bar() {
    local label="$1" steps="${2:-20}"
    local bar_width=42
    local label_width=30
    local pct filled empty bar clean_label content inner padded

    # Keep the loading animation clean: one progress line updates in place.
    # This avoids the staircase/duplicate-bar effect in the terminal.
    clean_label=$(printf "%s" "$label" | cut -c1-${label_width})
    inner=$((UI_WIDTH - 4))

    echo ""
    ui_box_top "$UI_WIDTH" "ANALYZING THREAT"

    for pct in 15 35 55 75 100; do
        filled=$((pct * bar_width / 100))
        empty=$((bar_width - filled))
        bar="$(ui_repeat "█" "$filled")$(ui_repeat "░" "$empty")"
        content="${C_PRIMARY}$(printf '%-*s' "$label_width" "$clean_label")${NC} ${C_SUCCESS}${bar}${NC} ${C_WARN}$(printf '%3d' "$pct")%${NC}"
        padded=$(ui_pad_right "$inner" "$content")
        printf "\r${C_PRIMARY}║ ${NC}%b${C_PRIMARY} ║${NC}" "$padded"
        sleep 0.10
    done

    echo ""
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_SUCCESS}[✓] ANALYSIS COMPLETE${NC}  ${C_GRAY}Simulation evidence generated safely.${NC}"
    ui_box_bottom "$UI_WIDTH"
    echo ""
}
ui_menu_item() {
    local width="$1" num="$2" title="$3" desc="$4"
    local inner=$((width-4)) col1=38 col2
    col2=$((inner - col1 - 3))
    [ "$col2" -lt 24 ] && col2=24
    local left="${C_SUCCESS}[ ${C_WHITE}${num}${C_SUCCESS} ]${NC} ${C_WHITE}${title}${NC}"
    local right="${C_GRAY}→${NC} ${C_PRIMARY}${desc}${NC}"
    ui_box_line "$width" "$(ui_pad_right "$col1" "$left") ${C_GRAY}│${NC} $(ui_pad_right "$col2" "$right")"
}

ui_metric_row() {
    local width="$1" a="$2" b="$3" c="$4" d="$5"
    local col=$(( (width-4)/2 - 2 ))
    local left="${C_ACCENT}${a}${NC}  ${C_WHITE}${b}${NC}"
    local right="${C_ACCENT}${c}${NC}  ${C_WHITE}${d}${NC}"
    ui_box_line "$width" "$(ui_pad_right "$col" "$left") ${C_GRAY}│${NC} $(ui_pad_right "$col" "$right")"
}

ui_safety_notice() {
    echo -e "  ${C_WARN}⚠${NC}  ${C_BOLD}SAFE EDUCATIONAL SOC SIMULATION${NC}  ${C_GRAY}─ Built for detection, investigation, and response practice.${NC}"
}

show_demo_hint() {
    echo -e "  ${C_GRAY}Judge demo flow:${NC} ${C_WHITE}Malware Detection${NC} ${C_GRAY}→${NC} ${C_WHITE}Critical Alert${NC} ${C_GRAY}→${NC} ${C_WHITE}Dashboard${NC} ${C_GRAY}→${NC} ${C_WHITE}IOC Export${NC} ${C_GRAY}→${NC} ${C_WHITE}Summary${NC}"
}

check_root_advisory() {
    if [ "$(id -u)" -ne 0 ]; then
        status_warn "Not running as root — logs will be saved to ${C_WHITE}${HOME}/.cybershield/logs${NC}"
        sleep 0.5
    fi
}

check_dependencies() {
    status_info "Checking system tools..."
    local tool missing=0
    for tool in ip awk grep sort shuf date wc tail mkdir chmod mktemp sed head cut hostname tput; do
        command -v "$tool" >/dev/null 2>&1 || { status_error "Missing: ${C_WHITE}$tool${NC}"; missing=1; }
    done
    [ "$missing" -eq 1 ] && { echo -e "${C_DANGER}[!] Install missing tools and retry.${NC}"; exit 1; }
    if ! command -v nmap >/dev/null 2>&1; then
        status_warn "nmap not found — fallback discovery will be used."
    else
        status_ok "nmap available."
    fi
    status_ok "Dependencies OK."
    sleep 0.3
}

setup_environment() {
    _setup_log_paths
    mkdir -p "$TMP_DIR"
    chmod 700 "$TMP_DIR"
    status_ok "Logs: ${C_WHITE}${LOG_DIR}${NC}"
    status_ok "Workspace: ${C_WHITE}${TMP_DIR}${NC}"
}

validate_ip() {
    local ip="$1" a b c d
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r a b c d <<< "$ip"
    [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]
}

validate_range() {
    local range="$1"
    [[ "$range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
    local ip="${range%/*}" cidr="${range#*/}"
    validate_ip "$ip" && [ "$cidr" -ge 0 ] && [ "$cidr" -le 32 ]
}

get_current_interface() {
    ip route 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

get_current_ip() {
    local iface
    iface=$(get_current_interface)
    if [ -n "$iface" ]; then
        ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1 || true
    else
        hostname -I 2>/dev/null | awk '{print $1}' || true
    fi
}

get_current_network_range() {
    local ip
    ip=$(get_current_ip)
    validate_ip "$ip" || return 1
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo "$a.$b.$c.0/24"
}

get_attack_name() {
    case "$1" in
        1) echo "Port Scanning" ;;
        2) echo "DoS Attack" ;;
        3) echo "ARP Spoofing" ;;
        4) echo "Brute Force Login" ;;
        5) echo "Malware Detection" ;;
        6) echo "Random Auto-Simulation" ;;
        *) echo "Unknown" ;;
    esac
}

get_severity_color() {
    case "$1" in
        Low)      echo "$C_SUCCESS" ;;
        Medium)   echo "$C_WARN" ;;
        High)     echo "$C_DANGER" ;;
        Critical) echo "$C_ACCENT" ;;
        *)        echo "$C_WHITE" ;;
    esac
}

read_menu_choice() {
    local prompt="$1" varname="$2"
    local value rows input_row msg_row

    # In command-center mode, keep input on a clean line above the footer.
    # This prevents "Select an option" from printing inside SYSTEM MESSAGES.
    if [ "${PINNED_FOOTER_ACTIVE:-0}" = "1" ]; then
        rows=$(tput lines 2>/dev/null || echo 30)
        input_row=$((rows - 5))
        [ "$input_row" -lt 0 ] && input_row=0

        tput cup "$input_row" 0 2>/dev/null || true
        printf "\033[2K"
        echo -ne " ${C_PRIMARY}▶${NC} ${C_WHITE}${prompt}${NC} "
        read -r value 2>/dev/null || true

        tput cup "$input_row" 0 2>/dev/null || true
        printf "\033[2K"
    else
        safe_read "$prompt" value
    fi

    value=$(printf '%s' "$value" | tr -d '[:space:]')
    printf -v "$varname" '%s' "$value"
}

show_network_menu() {
    local range="$1"
    ui_box_top "$UI_WIDTH" "STEP 1  ─  TARGET RANGE SELECTION"
    ui_menu_item "$UI_WIDTH" "1" "Auto-detected LAN range"    "${range:-Not detected}"
    ui_menu_item "$UI_WIDTH" "2" "Custom CIDR range"          "e.g. 10.0.0.0/24"
    ui_menu_item "$UI_WIDTH" "3" "Single host mode"           "Scan a specific IP"
    ui_box_bottom "$UI_WIDTH"
}

select_network_range() {
    local range choice custom single
    range=$(get_current_network_range)
    CURRENT_NETWORK_RANGE="$range"
    show_network_menu "$range"
    read_menu_choice "Select range (1–3):" choice
    case "$choice" in
        1) if [ -n "$range" ]; then
               SELECTED_SCAN_RANGE="$range"
               status_ok "Range: ${C_WHITE}${range}${NC}"
           else
               status_error "Cannot auto-detect range."
               return 1
           fi ;;
        2) safe_read "Enter CIDR (e.g. 192.168.1.0/24):" custom
           if validate_range "$custom"; then
               SELECTED_SCAN_RANGE="$custom"
               status_ok "Custom range: ${C_WHITE}${custom}${NC}"
           else
               status_error "Invalid CIDR."
               return 1
           fi ;;
        3) safe_read "Enter host IP:" single
           if validate_ip "$single"; then
               SELECTED_SCAN_RANGE="${single}/32"
               status_ok "Single host: ${C_WHITE}${single}${NC}"
           else
               status_error "Invalid IP."
               return 1
           fi ;;
        *) status_error "Invalid choice."; return 1 ;;
    esac
}

add_fallback_ips() {
    local ip
    ip=$(get_current_ip)
    validate_ip "$ip" && echo "$ip" >> "$TMP_AVAILABLE_IPS"
    ip neigh show 2>/dev/null | awk '{print $1}' | while read -r a; do
        validate_ip "$a" && echo "$a" >> "$TMP_AVAILABLE_IPS"
    done
    ip route 2>/dev/null | awk '/default/ {print $3; exit}' | while read -r gw; do
        validate_ip "$gw" && echo "$gw" >> "$TMP_AVAILABLE_IPS"
    done
}

display_available_targets() {
    ui_box_top "$UI_WIDTH" "STEP 2  ─  DISCOVERED HOSTS"
    ui_box_line "$UI_WIDTH" "${C_ACCENT}  ID    HOST ADDRESS           STATUS        CLASSIFICATION${NC}"
    ui_box_separator "$UI_WIDTH"
    local n=1 ip
    while IFS= read -r ip; do
        local tag="${C_GRAY}Simulation Target${NC}"
        ui_box_line "$UI_WIDTH" "${C_SUCCESS}[ $(printf '%02d' "$n") ]${NC}  ${C_WHITE}$(printf '%-22s' "$ip")${NC}  ${C_SUCCESS}● ONLINE${NC}   $tag"
        n=$((n+1))
    done < "$TMP_AVAILABLE_IPS"
    ui_box_bottom "$UI_WIDTH"
}

scan_network() {
    local range="$1"
    if [ "${range}" = "${SCAN_CACHE_RANGE}" ] && [ -s "$TMP_AVAILABLE_IPS" ]; then
        local count; count=$(wc -l < "$TMP_AVAILABLE_IPS")
        status_ok "Using cached scan: ${C_WHITE}${count}${NC} host(s). Use ${C_NEON}R${NC} to re-scan."
        SCAN_DONE=1
        return 0
    fi
    echo ""
    status_info "Starting host discovery on ${C_WHITE}${range}${NC}"
    : > "$TMP_AVAILABLE_IPS"
    if command -v nmap >/dev/null 2>&1; then
        ui_loading_bar "Scanning ${range}" 14
        nmap -sn -T4 --host-timeout 5s "$range" > "$TMP_SCAN" 2>/dev/null || true
        grep "Nmap scan report" "$TMP_SCAN" 2>/dev/null | while read -r line; do
            if echo "$line" | grep -q '('; then echo "$line" | awk -F'[()]' '{print $2}'; else echo "$line" | awk '{print $NF}'; fi
        done >> "$TMP_AVAILABLE_IPS" || true
    else
        ui_loading_bar "Fallback host discovery" 14
        add_fallback_ips
    fi
    [ ! -s "$TMP_AVAILABLE_IPS" ] && add_fallback_ips
    sort -u "$TMP_AVAILABLE_IPS" -o "$TMP_AVAILABLE_IPS" 2>/dev/null || true
    if [ ! -s "$TMP_AVAILABLE_IPS" ]; then status_error "No hosts found."; return 1; fi
    SCAN_CACHE_RANGE="$range"; SCAN_DONE=1
    local count; count=$(wc -l < "$TMP_AVAILABLE_IPS")
    LAST_SYSTEM_MESSAGE="Network scan completed. ${count} host(s) discovered."
    status_ok "${C_WHITE}${count}${NC} host(s) discovered on ${C_WHITE}${range}${NC}."
}

show_target_menu() {
    local ip="$1"
    ui_box_top "$UI_WIDTH" "STEP 3  ─  SELECT SIMULATION TARGET"
    ui_menu_item "$UI_WIDTH" "1" "Current machine (self)"      "${ip:-Not detected}"
    ui_menu_item "$UI_WIDTH" "2" "Choose from discovered list"  "Select by ID"
    ui_menu_item "$UI_WIDTH" "3" "Enter custom IP"              "Any valid address"
    ui_menu_item "$UI_WIDTH" "4" "Auto-select random target"    "Randomly picked"
    ui_box_bottom "$UI_WIDTH"
}

select_target() {
    local current_ip choice num sel custom
    current_ip=$(get_current_ip)
    show_target_menu "$current_ip"
    read_menu_choice "Select target (1–4):" choice
    case "$choice" in
        1) if [ -n "$current_ip" ]; then
               SELECTED_TARGET="$current_ip"
               echo "$current_ip" > "$TMP_SELECTED_TARGET"
               status_ok "Target: ${C_WHITE}${current_ip}${NC}"
           else
               status_error "Cannot detect local IP."
               return 1
           fi ;;
        2) if [ ! -s "$TMP_AVAILABLE_IPS" ]; then
               status_error "No discovered hosts."
               return 1
           fi
           display_available_targets
           read_menu_choice "Enter host ID:" num
           if [[ ! "$num" =~ ^[0-9]+$ ]]; then
               status_error "Invalid number."
               return 1
           fi
           sel=$(sed -n "${num}p" "$TMP_AVAILABLE_IPS" 2>/dev/null)
           if [ -n "$sel" ]; then
               SELECTED_TARGET="$sel"
               echo "$sel" > "$TMP_SELECTED_TARGET"
               status_ok "Target: ${C_WHITE}${sel}${NC}"
           else
               status_error "No host at that ID."
               return 1
           fi ;;
        3) safe_read "Enter IP:" custom
           if validate_ip "$custom"; then
               SELECTED_TARGET="$custom"
               echo "$custom" > "$TMP_SELECTED_TARGET"
               status_ok "Target: ${C_WHITE}${custom}${NC}"
           else
               status_error "Invalid IP."
               return 1
           fi ;;
        4) if [ ! -s "$TMP_AVAILABLE_IPS" ]; then
               status_error "No hosts available."
               return 1
           fi
           SELECTED_TARGET=$(shuf -n 1 "$TMP_AVAILABLE_IPS")
           echo "$SELECTED_TARGET" > "$TMP_SELECTED_TARGET"
           status_ok "Random target: ${C_WHITE}${SELECTED_TARGET}${NC}" ;;
        *) status_error "Invalid choice."; return 1 ;;
    esac
}

severity_rank()    { case "$1" in Low) echo 1;; Medium) echo 2;; High) echo 3;; Critical) echo 4;; *) echo 1;; esac; }
rank_to_severity() { case "$1" in 1) echo "Low";; 2) echo "Medium";; 3) echo "High";; 4) echo "Critical";; *) echo "Low";; esac; }

escalate_severity() {
    local sev="$1" rc="$2" rank
    rank=$(severity_rank "$sev")
    [ "$rc" -ge 5 ] && rank=4
    [ "$rc" -ge 3 ] && [ "$rank" -lt 4 ] && rank=$((rank+1))
    rank_to_severity "$rank"
}

get_alert_status() {
    local sev="$1" rc="$2"
    [ "$sev" = "Critical" ] && echo "CRITICAL — Immediate Response Required" && return
    [ "$rc" -ge 3 ]         && echo "ESCALATED — Repeated Incident Pattern"  && return
    [ "$sev" = "High" ]     && echo "ESCALATED — Forwarded to Tier 2 Analyst" && return
    echo "OPEN — Pending Analyst Review"
}

calculate_risk_score() {
    local sev="$1" rc="$2" base score
    case "$sev" in Low) base=25;; Medium) base=45;; High) base=70;; Critical) base=90;; *) base=25;; esac
    score=$((base + rc*3))
    [ "$score" -gt 100 ] && score=100
    echo "$score"
}

get_repeat_count() {
    local attack="$1" target="$2" rc
    if [ ! -s "$CORRELATION_FILE" ]; then
        echo 0
        return
    fi
    rc=$(grep -cF "| Attack=${attack} | Target=${target} |" "$CORRELATION_FILE" 2>/dev/null || true)
    [[ "$rc" =~ ^[0-9]+$ ]] || rc=0
    echo "$rc"
}

record_correlation_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Incident=$4 | Attack=$1 | Target=$2 | Severity=$3 |" >> "$CORRELATION_FILE"
}

get_top_target() {
    if [ ! -s "$CORRELATION_FILE" ]; then echo "No data"; return; fi
    sed -n 's/.*| Target=\([^|]*\) |.*/\1/p' "$CORRELATION_FILE" \
        | sed 's/[[:space:]]*$//' | sort | uniq -c | sort -nr | head -1 \
        | sed 's/^ *[0-9]* //'
}

get_most_common_attack() {
    if [ ! -s "$CORRELATION_FILE" ]; then echo "No data"; return; fi
    sed -n 's/.*| Attack=\([^|]*\) |.*/\1/p' "$CORRELATION_FILE" \
        | sed 's/[[:space:]]*$//' | sort | uniq -c | sort -nr | head -1 \
        | sed 's/^ *[0-9]* //'
}

generate_incident_id() {
    echo "SOC-$(date +%Y%m%d-%H%M%S)-$RANDOM"
}

print_soc_alert() {
    local id="$1" attack="$2" target="$3" sev="$4" src="$5" status="$6" mitre="$7"
    local why="$8" cause="$9" action="${10}" t1="${11}" t2="${12}" t3="${13}" t4="${14}"
    local rcount="${15}" risk="${16}" orig_sev="${17}"
    local sev_color
    sev_color=$(get_severity_color "$sev")
    echo ""
    if [ "$sev" = "Critical" ] || [ "$sev" = "High" ]; then
        echo -e "${C_DANGER}${C_BOLD}"
cat <<'ALERT'
  ╔═══════════════════════════════════════════════════════════╗
  ║     ⚠  PRIORITY  SECURITY INCIDENT DETECTED  ⚠            ║
  ╚═══════════════════════════════════════════════════════════╝
ALERT
        echo -e "${NC}"
    else
        echo -e "${C_WARN}${C_BOLD}"
        echo "  ─────────────────────── SECURITY ALERT ───────────────────────"
        echo -e "${NC}"
    fi
    ui_box_top "$UI_WIDTH" "INCIDENT ALERT REPORT"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ INCIDENT OVERVIEW${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_metric_row "$UI_WIDTH" "Incident ID"  "$id"                                                   "Attack Type"  "$attack"
    ui_metric_row "$UI_WIDTH" "Target Host"  "${C_PRIMARY}$target${NC}"                               "Detection"    "$src"
    ui_metric_row "$UI_WIDTH" "Severity"     "${sev_color}${C_BOLD}$sev${NC} (was: $orig_sev)"        "Risk Score"   "${C_WARN}$risk / 100${NC}"
    ui_metric_row "$UI_WIDTH" "Repeat Count" "${rcount}x"                                             "Status"       "$status"
    ui_box_line "$UI_WIDTH" "${C_SUCCESS}MITRE ATT&CK${NC}  ${C_ACCENT}${C_BOLD}${mitre}${NC}"
    ui_box_separator "$UI_WIDTH"
    local bar_full bar_empty bar_color
    bar_full=$(( risk / 5 ))
    bar_empty=$(( 20 - risk/5 ))
    bar_color="$C_SUCCESS"
    [ "$risk" -gt 50 ] && bar_color="$C_WARN"
    [ "$risk" -gt 75 ] && bar_color="$C_DANGER"
    ui_box_line "$UI_WIDTH" "${C_ACCENT}Risk Level${NC}  ${bar_color}$(ui_repeat "█" $bar_full)${C_GRAY}$(ui_repeat "░" $bar_empty)${NC}  ${bar_color}${risk}/100${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ ANALYST ASSESSMENT${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_SUCCESS}Why Alert Fired${NC}   ${C_WHITE}${why}${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_SUCCESS}Root Cause${NC}        ${C_WHITE}${cause}${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_WARN}Recommendation${NC}    ${C_WHITE}${action}${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ INCIDENT TIMELINE${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}$(date '+%H:%M:%S')${NC}  Anomalous activity detected on ${C_WHITE}${target}${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}$(date '+%H:%M:%S')${NC}  Detection threshold crossed — alert generated"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}$(date '+%H:%M:%S')${NC}  Severity: ${sev_color}${C_BOLD}${sev}${NC}  Risk Score: ${C_WARN}${risk}/100${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ IOC SNAPSHOT${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_metric_row "$UI_WIDTH" "Target IP"  "$target"   "Attack Type"  "$attack"
    ui_metric_row "$UI_WIDTH" "Source"     "$src"       "Risk Score"   "${risk}/100"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ TIER 1 TRIAGE WORKFLOW${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}01.${NC} $t1"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}02.${NC} $t2"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}03.${NC} $t3"
    ui_box_line "$UI_WIDTH" "  ${C_PRIMARY}04.${NC} $t4"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_BOLD}${C_ACCENT}▸ ANALYST DECISION${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${sev_color}[✓] Escalate / Review${NC}   ${C_GRAY}[ ] False Positive   [ ] Monitor Only   [ ] Contained${NC}"
    ui_box_bottom "$UI_WIDTH"
}

save_soc_record() {
    local id="$1" attack="$2" target="$3" sev="$4" src="$5" status="$6" mitre="$7"
    local why="$8" cause="$9" action="${10}" t1="${11}" t2="${12}" t3="${13}" t4="${14}"
    local rcount="${15}" risk="${16}" orig_sev="${17}"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] Incident=$id | Attack=$attack | Target=$target | Severity=$sev | Original=$orig_sev | RepeatCount=$rcount | RiskScore=$risk | MITRE=$mitre | Source=$src | Status=$status" >> "$LOG_FILE"
    {
        echo "============================================================"
        echo " SOC INCIDENT REPORT — $PROG_NAME v$PROG_VERSION"
        echo "============================================================"
        printf " %-22s %s\n" "Incident ID:"      "$id"
        printf " %-22s %s\n" "Timestamp:"        "$ts"
        printf " %-22s %s\n" "Attack Type:"      "$attack"
        printf " %-22s %s\n" "Target IP:"        "$target"
        printf " %-22s %s\n" "Severity:"         "$sev"
        printf " %-22s %s\n" "Risk Score:"       "$risk/100"
        printf " %-22s %s\n" "Repeat Count:"     "$rcount"
        printf " %-22s %s\n" "MITRE ATT&CK:"    "$mitre"
        printf " %-22s %s\n" "Detection Source:" "$src"
        printf " %-22s %s\n" "Status:"           "$status"
        printf " %-22s %s\n" "Why Fired:"        "$why"
        printf " %-22s %s\n" "Root Cause:"       "$cause"
        printf " %-22s %s\n" "Action:"           "$action"
        echo ""
        echo " Triage Steps:"
        echo "  1. $t1"
        echo "  2. $t2"
        echo "  3. $t3"
        echo "  4. $t4"
        echo "============================================================"
        echo ""
    } >> "$REPORT_FILE"
    echo "[$ts] Severity=$sev | Attack=$attack | Target=$target | RepeatCount=$rcount | RiskScore=$risk | MITRE=$mitre" >> "$SUMMARY_FILE"
    echo "[$ts] IOC: target=$target | attack=$attack | mitre=$mitre | risk=$risk | id=$id" >> "$IOC_FILE"
}

create_soc_alert() {
    local attack="$1" target="$2" sev="$3" src="$4" status="$5" mitre="$6"
    local why="$7" cause="$8" action="$9" t1="${10}" t2="${11}" t3="${12}" t4="${13}"
    local id rc rcount orig_sev risk
    id=$(generate_incident_id)
    rc=$(get_repeat_count "$attack" "$target")
    rcount=$((rc+1))
    orig_sev="$sev"
    sev=$(escalate_severity "$sev" "$rcount")
    status=$(get_alert_status "$sev" "$rcount")
    risk=$(calculate_risk_score "$sev" "$rcount")
    if [ "$rcount" -ge 3 ]; then
        why="$why [Repeated: ${rcount}x]"
        cause="$cause Correlation engine flagged repeated activity."
        action="$action PRIORITY: escalate immediately."
    fi
    print_soc_alert "$id" "$attack" "$target" "$sev" "$src" "$status" "$mitre" \
        "$why" "$cause" "$action" "$t1" "$t2" "$t3" "$t4" "$rcount" "$risk" "$orig_sev"
    save_soc_record "$id" "$attack" "$target" "$sev" "$src" "$status" "$mitre" \
        "$why" "$cause" "$action" "$t1" "$t2" "$t3" "$t4" "$rcount" "$risk" "$orig_sev"
    record_correlation_event "$attack" "$target" "$sev" "$id"
    SESSION_LAST_SEVERITY="$sev"
    SESSION_LAST_RISK="$risk"
    echo ""
    status_ok "Incident saved → ${C_WHITE}${LOG_FILE}${NC}"
    status_ok "IOC exported  → ${C_WHITE}${IOC_FILE}${NC}"
}

sim_port_scan() {
    local target="$1" ports sev
    ports=$((20 + RANDOM % 80))
    sev="Medium"; [ "$ports" -gt 60 ] && sev="High"
    status_warn "Port Scan on ${C_WHITE}${target}${NC}"
    ui_loading_bar "Enumerating services on ${target}" 22
    ui_box_top "$UI_WIDTH" "SIMULATION RESULTS — PORT SCAN"
    ui_metric_row "$UI_WIDTH" "Ports Probed"    "${C_WHITE}${ports}${NC}"  "Threshold"  "${C_WHITE}15${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_SUCCESS}Exposed Services${NC}  ${C_PRIMARY}22/tcp ssh  80/tcp http  443/tcp https${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Evidence${NC}          ${C_WHITE}${ports} probes exceeded detection threshold.${NC}"
    ui_box_bottom "$UI_WIDTH"
    create_soc_alert "Port Scanning" "$target" "$sev" \
        "Network IDS / Firewall Logs" "Open" "T1046 — Network Service Discovery" \
        "${ports} port probes exceeded threshold of 15." \
        "Pre-exploitation reconnaissance activity suspected." \
        "Review firewall rules and confirm scan authorization." \
        "Verify if source IP matches any authorized security scanner." \
        "Review firewall and IDS logs for source IP." \
        "Identify and close unnecessary listening ports." \
        "Escalate if source is unknown or scan repeats."
}

sim_dos() {
    local target="$1" rate sev
    rate=$((800 + RANDOM % 2500))
    sev="High"; [ "$rate" -gt 2500 ] && sev="Critical"
    status_warn "DoS Simulation on ${C_WHITE}${target}${NC}"
    ui_loading_bar "Analyzing traffic flood pattern on ${target}" 22
    ui_box_top "$UI_WIDTH" "SIMULATION RESULTS — DENIAL OF SERVICE"
    ui_metric_row "$UI_WIDTH" "Request Rate"  "${C_WHITE}${rate} req/min${NC}"      "Threshold"  "${C_WHITE}1000 req/min${NC}"
    ui_metric_row "$UI_WIDTH" "Availability"  "${C_WARN}Monitoring required${NC}"   "Impact"     "${C_DANGER}Service degradation risk${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Evidence${NC}  ${C_WHITE}Rate exceeded threshold. No real traffic generated.${NC}"
    ui_box_bottom "$UI_WIDTH"
    create_soc_alert "DoS Attack" "$target" "$sev" \
        "Firewall / Network Monitor" "Escalated — Tier 2" "T1498 — Network Denial of Service" \
        "${rate}/min exceeded alert threshold of 1000/min." \
        "Potential resource exhaustion or volumetric availability attack." \
        "Apply rate limiting and monitor service uptime." \
        "Check service availability and latency immediately." \
        "Review firewall and load balancer logs." \
        "Block or rate-limit suspicious source ranges." \
        "Escalate to network ops if service impact confirmed."
}

sim_arp_spoof() {
    local target="$1"
    status_warn "ARP Spoofing Simulation on ${C_WHITE}${target}${NC}"
    ui_loading_bar "Analyzing ARP table anomalies on ${target}" 22
    ui_box_top "$UI_WIDTH" "SIMULATION RESULTS — ARP SPOOFING"
    ui_metric_row "$UI_WIDTH" "ARP Anomaly"    "${C_DANGER}Detected${NC}"                "Behavior"  "${C_WHITE}Gateway impersonation pattern${NC}"
    ui_metric_row "$UI_WIDTH" "Network Layer"  "${C_WHITE}Suspicious local activity${NC}" "MITM Risk" "${C_DANGER}Elevated${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Note${NC}  ${C_WHITE}No real ARP spoofing executed. Simulated anomaly only.${NC}"
    ui_box_bottom "$UI_WIDTH"
    create_soc_alert "ARP Spoofing" "$target" "High" \
        "Switch Logs / ARP Monitor" "Escalated — Network Team" "T1557 — Adversary-in-the-Middle" \
        "Suspicious ARP response indicates gateway MAC impersonation." \
        "Possible local network man-in-the-middle attempt." \
        "Verify gateway MAC, isolate host, review switch CAM table." \
        "Compare gateway MAC against trusted ARP baseline." \
        "Check switch CAM table for duplicate MACs." \
        "Isolate the suspicious host if duplicate ARP confirmed." \
        "Enable DHCP snooping and dynamic ARP inspection."
}

sim_brute_force() {
    local target="$1" fails sev
    fails=$((10 + RANDOM % 40))
    sev="High"; [ "$fails" -gt 30 ] && sev="Critical"
    status_warn "Brute Force Simulation on ${C_WHITE}${target}${NC}"
    ui_loading_bar "Analyzing failed authentication on ${target}" 22
    ui_box_top "$UI_WIDTH" "SIMULATION RESULTS — BRUTE FORCE LOGIN"
    ui_metric_row "$UI_WIDTH" "Failed Attempts"  "${C_WHITE}${fails}${NC}"  "Threshold"       "${C_WHITE}10${NC}"
    ui_metric_row "$UI_WIDTH" "Target Account"   "${C_WHITE}admin${NC}"     "Credential Risk" "${C_DANGER}Elevated${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Evidence${NC}  ${C_WHITE}Failed login count exceeded threshold. No real credentials tested.${NC}"
    ui_box_bottom "$UI_WIDTH"
    create_soc_alert "Brute Force Login" "$target" "$sev" \
        "Auth Logs / SIEM" "Escalated — Tier 2" "T1110 — Brute Force" \
        "${fails} failed logins on 'admin' exceeded threshold of 10." \
        "Possible password spray or credential stuffing." \
        "Lock account, reset credentials, review auth logs." \
        "Confirm failure volume and time window from logs." \
        "Check if any successful login followed the burst." \
        "Lock or reset targeted account immediately." \
        "Block source IP if pattern repeats."
}

sim_malware() {
    local target="$1" fake_hash="f2a1b9c8d7e6a5f403928171abcdef12"
    status_warn "Malware Detection Simulation on ${C_WHITE}${target}${NC}"
    ui_loading_bar "Scanning file system for suspicious executables on ${target}" 22
    ui_box_top "$UI_WIDTH" "SIMULATION RESULTS — MALWARE DETECTION"
    ui_metric_row "$UI_WIDTH" "Suspicious File"  "${C_WHITE}/tmp/update_service.bin${NC}"    "Hash"      "${C_WHITE}${fake_hash}${NC}"
    ui_metric_row "$UI_WIDTH" "Detection Type"   "${C_DANGER}Suspicious executable${NC}"    "Behavior"  "${C_WHITE}Possible staging / persistence${NC}"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Note${NC}  ${C_WHITE}No malware executed or dropped. Simulated detection only.${NC}"
    ui_box_bottom "$UI_WIDTH"
    create_soc_alert "Malware Detection" "$target" "Critical" \
        "Endpoint Detection / EDR" "CRITICAL — Immediate Response" "T1204 — User Execution" \
        "Suspicious executable at /tmp/update_service.bin with anomalous hash." \
        "Possible malware staging, dropper, or persistence mechanism." \
        "Isolate host, collect evidence, escalate to incident response." \
        "Immediately isolate the affected host from the network." \
        "Collect file path, hash, and running process evidence." \
        "Run full endpoint scan and check persistence paths." \
        "Escalate to incident response team for containment."
}

execute_attack() {
    local choice="$1" target="$2" actual_choice="$1"
    case "$choice" in
        1) sim_port_scan   "$target" ;;
        2) sim_dos         "$target" ;;
        3) sim_arp_spoof   "$target" ;;
        4) sim_brute_force "$target" ;;
        5) sim_malware     "$target" ;;
        6)
            local r
            r=$((1 + RANDOM % 5))
            actual_choice="$r"
            status_info "Auto-selected module: ${C_WHITE}$(get_attack_name "$r")${NC}"
            case "$r" in
                1) sim_port_scan   "$target" ;;
                2) sim_dos         "$target" ;;
                3) sim_arp_spoof   "$target" ;;
                4) sim_brute_force "$target" ;;
                5) sim_malware     "$target" ;;
            esac ;;
        *) status_error "Invalid module."; return 1 ;;
    esac
    SESSION_LAST_ATTACK=$(get_attack_name "$actual_choice")
}

show_threat_map() {
    echo ""
    ui_box_top "$UI_WIDTH" "NETWORK THREAT MAP  ─  ATTACK DISTRIBUTION"
    if [ ! -s "$CORRELATION_FILE" ]; then
        ui_box_line "$UI_WIDTH" "  ${C_GRAY}No incidents recorded yet. Run simulations to populate.${NC}"
        ui_box_bottom "$UI_WIDTH"
        return
    fi
    ui_box_line "$UI_WIDTH" "  ${C_ACCENT}ATTACK TYPE${NC}                  ${C_ACCENT}COUNT${NC}   ${C_ACCENT}VISUAL DISTRIBUTION${NC}"
    ui_box_separator "$UI_WIDTH"
    local attacks=("Port Scanning" "DoS Attack" "ARP Spoofing" "Brute Force Login" "Malware Detection")
    local colors=("$C_PRIMARY" "$C_DANGER" "$C_WARN" "$C_ACCENT" "$C_SUCCESS")
    local total=0 cnt atk
    for atk in "${attacks[@]}"; do
        cnt=$(grep -cF "| Attack=${atk} |" "$CORRELATION_FILE" 2>/dev/null || echo 0)
        total=$((total + cnt))
    done
    [ "$total" -eq 0 ] && total=1
    local i=0
    for atk in "${attacks[@]}"; do
        cnt=$(grep -cF "| Attack=${atk} |" "$CORRELATION_FILE" 2>/dev/null || echo 0)
        local bar_len
        bar_len=$(( cnt * 30 / total ))
        [ "$bar_len" -lt 1 ] && [ "$cnt" -gt 0 ] && bar_len=1
        local col
        col="${colors[$i]}"
        local bar
        bar="${col}$(ui_repeat "█" "$bar_len")${NC}"
        ui_box_line "$UI_WIDTH" "  ${C_WHITE}$(printf '%-28s' "$atk")${NC}  ${col}$(printf '%3d' "$cnt")${NC}   ${bar}"
        i=$((i+1))
    done
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_GRAY}Total incidents: ${C_WHITE}${total}${NC}  ${C_GRAY}│  Source: $CORRELATION_FILE${NC}"
    ui_box_bottom "$UI_WIDTH"
}

show_ioc_export() {
    echo ""
    ui_box_top "$UI_WIDTH" "IOC EXPORT — INDICATORS OF COMPROMISE"
    if [ ! -s "$IOC_FILE" ]; then
        ui_box_line "$UI_WIDTH" "  ${C_GRAY}No IOCs recorded yet.${NC}"
        ui_box_bottom "$UI_WIDTH"
        return
    fi
    ui_box_line "$UI_WIDTH" "  ${C_ACCENT}TIMESTAMP             TARGET           ATTACK               RISK   ID${NC}"
    ui_box_separator "$UI_WIDTH"
    tail -n 10 "$IOC_FILE" | while IFS= read -r line; do
        local ts tgt atk risk iid
        ts=$(echo "$line"  | sed -n 's/^\[\([^]]*\)\].*/\1/p')
        tgt=$(echo "$line" | sed -n 's/.*target=\([^|]*\)|.*/\1/p'  | sed 's/ *$//')
        atk=$(echo "$line" | sed -n 's/.*attack=\([^|]*\)|.*/\1/p'  | sed 's/ *$//')
        risk=$(echo "$line" | sed -n 's/.*risk=\([^|]*\)|.*/\1/p'   | sed 's/ *$//')
        iid=$(echo "$line"  | sed -n 's/.*id=\(.*\)/\1/p'           | sed 's/ *$//')
        ui_box_line "$UI_WIDTH" "  ${C_GRAY}$(printf '%-21s' "$ts")${NC}${C_WHITE}$(printf '%-17s' "$tgt")${NC}${C_PRIMARY}$(printf '%-21s' "$atk")${NC}${C_WARN}$(printf '%-7s' "$risk")${NC}${C_GRAY}${iid}${NC}"
    done
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_SUCCESS}Full export:${NC} ${C_WHITE}${IOC_FILE}${NC}"
    ui_box_bottom "$UI_WIDTH"
}

show_session_summary() {
    echo ""
    ui_box_top "$UI_WIDTH" "SESSION SUMMARY  ─  INCIDENT REVIEW"
    if [ "$SESSION_INCIDENTS" -eq 0 ]; then
        ui_box_line "$UI_WIDTH" "  ${C_GRAY}No session activity yet. Run one simulation to create a review summary.${NC}"
        ui_box_bottom "$UI_WIDTH"
        return
    fi
    local sev_color
    sev_color=$(get_severity_color "$SESSION_LAST_SEVERITY")
    ui_box_line "$UI_WIDTH" "  ${C_BOLD}${C_ACCENT}▸ LAST INCIDENT${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_metric_row "$UI_WIDTH" "Attack"            "$SESSION_LAST_ATTACK"                              "Target"   "$SESSION_LAST_TARGET"
    ui_metric_row "$UI_WIDTH" "Severity"          "${sev_color}${SESSION_LAST_SEVERITY}${NC}"         "Risk"     "${C_WARN}${SESSION_LAST_RISK}/100${NC}"
    ui_metric_row "$UI_WIDTH" "Session Incidents" "$SESSION_INCIDENTS"                                "Status"   "${C_SUCCESS}Logged${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_BOLD}${C_ACCENT}▸ ANALYST TAKEAWAY${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_WHITE}1.${NC} Incident was simulated and documented with full SOC evidence."
    ui_box_line "$UI_WIDTH" "  ${C_WHITE}2.${NC} MITRE ATT&CK mapping and risk scoring applied automatically."
    ui_box_line "$UI_WIDTH" "  ${C_WHITE}3.${NC} Logs and IOC export are ready for review or presentation."
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_BOLD}${C_ACCENT}▸ NEXT ACTION${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "  ${C_WARN}Present Dashboard, IOC Export, and this Summary as the final SOC evidence package.${NC}"
    ui_box_bottom "$UI_WIDTH"
}

C_NEON='\033[38;5;45m'
C_PURPLE='\033[38;5;141m'
C_ORANGE='\033[38;5;214m'
C_RED='\033[38;5;196m'
C_GREEN='\033[38;5;40m'
C_YELLOW='\033[38;5;220m'
C_BLUE2='\033[38;5;39m'

SCAN_DONE=0
SCAN_CACHE_RANGE=""
SESSION_ID="CS-$(date +%Y%m%d-%H%M)"
SESSION_STARTED_EPOCH=$(date +%s)
LAST_SYSTEM_MESSAGE="Ready. Choose an action from the menu."
PINNED_FOOTER_ACTIVE=0

count_sev() {
    local sev="$1" n
    if [ -s "$SUMMARY_FILE" ]; then
        n=$(grep -c "Severity=${sev}" "$SUMMARY_FILE" 2>/dev/null || true)
    else
        n=0
    fi
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}


crop_visible() {
    local max="$1" s="$2" clean
    clean=$(ui_strip_ansi "$s")
    if [ "${#clean}" -gt "$max" ]; then
        printf "%s..." "${clean:0:$((max-3))}"
    else
        printf "%s" "$s"
    fi
}

fit_text() {
    local max="$1" text="$2" clean
    clean=$(ui_strip_ansi "$text")
    if [ "${#clean}" -gt "$max" ]; then
        printf "%s…" "${clean:0:$((max-1))}"
    else
        printf "%s" "$text"
    fi
}

count_file_lines() { local file="$1"; [ -s "$file" ] && wc -l < "$file" || echo 0; }

mini_bar() {
    local count="$1" color="$2" max="${3:-12}" fill empty
    fill=$count; [ "$fill" -gt "$max" ] && fill="$max"
    empty=$((max-fill))
    printf "%b%s%b%s%b" "$color" "$(ui_repeat "█" "$fill")" "$C_GRAY" "$(ui_repeat "░" "$empty")" "$NC"
}

cybershield_big_banner() {
    local banner_width=99
    local cols pad line
    cols=$(tput cols 2>/dev/null || echo 132)
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=132
    pad=$(( (cols - banner_width) / 2 - 6 ))
    [ "$pad" -lt 0 ] && pad=0

    echo ""
    echo -e "\033[38;5;201m${C_BOLD}"
    while IFS= read -r line; do
        printf "%*s%b\n" "$pad" "" "$line"
    done <<'ART'
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗███████╗██╗     ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗███████║██║█████╗  ██║     ██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
ART
    echo -e "${NC}"
    echo ""
}

ui_topbar() {
    PINNED_FOOTER_ACTIVE=0
    local now alerts status_color
    UI_WIDTH=$(ui_term_width)
    now=$(date '+%I:%M:%S %p')
    alerts=$(count_file_lines "$SUMMARY_FILE")
    status_color="$C_GREEN"; [ "$alerts" -gt 5 ] && status_color="$C_YELLOW"; [ "$alerts" -gt 10 ] && status_color="$C_RED"
    clear
    # printf "%b%-38s%b %b%-43s%b %b%18s%b   %b● SYSTEM OPERATIONAL%b\n" \
    #     "$C_NEON" "CyberShield Elite SOC Simulator  v${PROG_VERSION}" "$NC" \
    #     "$C_NEON" "${PROG_CODE}  |  ${PROG_AUTHOR}  |  Competition Build" "$NC" \
    #     "$C_GRAY" "$now" "$NC" "$status_color" "$NC"
    # echo -e "${C_PRIMARY}$(ui_repeat "─" "$UI_WIDTH")${NC}"
}

ui_brand_panel() {
    local host_count risk last now uptime session_alerts system_status

    host_count=$(count_file_lines "$TMP_AVAILABLE_IPS")
    session_alerts=${SESSION_INCIDENTS:-0}

    risk=${SESSION_LAST_RISK:-0}
    [ -z "$risk" ] && risk=0

    last=${SESSION_LAST_ATTACK:-N/A}
    [ -z "$last" ] && last="N/A"

    system_status="COMPETITION READY"

    now=$(date +%s)
    uptime=$((now - SESSION_STARTED_EPOCH))

    ui_box_top "$UI_WIDTH" "CYBERSHIELD CHECKER"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%s%b" \
        "$C_NEON" "PROJECT" "$NC" "$C_WHITE" "CHECKER" "$NC" "$C_NEON" "QUICK STATS" "$NC")"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%-4s%b %-18s : %b%s%b" \
        "$C_NEON" "STUDENT CODE" "$NC" "$C_WHITE" "s3" "$NC" "$C_BLUE2" "[H]" "$NC" "Detected Hosts" "$C_WHITE" "$host_count" "$NC")"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%-4s%b %-18s : %b%s%b" \
        "$C_NEON" "STUDENT NAME" "$NC" "$C_WHITE" "PENG SEYHA" "$NC" "$C_RED" "[I]" "$NC" "Session Alerts" "$C_WHITE" "$session_alerts" "$NC")"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%-4s%b %-18s : %b%s / 100%b" \
        "$C_NEON" "PROGRAM" "$NC" "$C_WHITE" "SOC Analyst" "$NC" "$C_YELLOW" "[R]" "$NC" "Risk Score" "$C_WHITE" "$risk" "$NC")"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%-4s%b %-18s : %b%s%b" \
        "$C_NEON" "SESSION ID" "$NC" "$C_WHITE" "$SESSION_ID" "$NC" "$C_ORANGE" "[L]" "$NC" "Last Scenario" "$C_WHITE" "$last" "$NC")"

    ui_box_line "$UI_WIDTH" "$(printf "%b%-14s%b : %b%-26s%b  %b%-4s%b %-18s : %b%s%b" \
        "$C_NEON" "STATUS" "$NC" "$C_WHITE" "${uptime}s Active" "$NC" "$C_GREEN" "[S]" "$NC" "System Status" "$C_WHITE" "$system_status" "$NC")"

    ui_box_bottom "$UI_WIDTH"
}
ui_context_cards() {
    local count target last risk logfiles range risk_sub
    count=$(count_file_lines "$TMP_AVAILABLE_IPS")
    range=${SELECTED_SCAN_RANGE:-Not selected}; target=${SELECTED_TARGET:-Not selected}
    last=${SESSION_LAST_ATTACK:-None yet}; [ -z "$last" ] && last="None yet"
    risk=${SESSION_LAST_RISK:-0}; [ -z "$risk" ] && risk=0
    logfiles=$(ls "$LOG_DIR" 2>/dev/null | wc -l 2>/dev/null || echo 0)
    risk_sub="Safe"; [ "$risk" -ge 60 ] && risk_sub="Review required"; [ "$risk" -ge 80 ] && risk_sub="High priority"
    ui_box_top "$UI_WIDTH" "CURRENT SESSION CONTEXT"
    ui_metric_row "$UI_WIDTH" "NETWORK RANGE" "${range}  |  ${count} hosts scanned" "TARGET HOST" "$target"
    ui_metric_row "$UI_WIDTH" "LAST ACTIVITY" "$last" "SESSION RISK" "${risk} / 100  ${risk_sub}"
    ui_metric_row "$UI_WIDTH" "LOG DIRECTORY" "$LOG_DIR" "LOG FILES" "${logfiles} files"
    ui_box_bottom "$UI_WIDTH"
}







# -------- Fixed side-by-side dashboard layout for Kali terminal --------
LEFT_W=50
RIGHT_W=66
PANEL_GAP="  "

line_top() {
    local w="$1" title="${2:-}"
    local inner=$((w-2))
    if [ -n "$title" ]; then
        local clean len left right
        clean=$(ui_strip_ansi "$title")
        len=${#clean}
        left=1
        right=$((inner - len - left - 2))
        [ "$right" -lt 1 ] && right=1
        printf "%b┌%s %b%s%b %s┐%b" "$C_PRIMARY" "$(ui_repeat "─" "$left")" "$C_NEON" "$title" "$NC$C_PRIMARY" "$(ui_repeat "─" "$right")" "$NC"
    else
        printf "%b┌%s┐%b" "$C_PRIMARY" "$(ui_repeat "─" "$inner")" "$NC"
    fi
}

line_mid() {
    local w="$1"
    printf "%b├%s┤%b" "$C_PRIMARY" "$(ui_repeat "─" "$((w-2))")" "$NC"
}

line_bottom() {
    local w="$1"
    printf "%b└%s┘%b" "$C_PRIMARY" "$(ui_repeat "─" "$((w-2))")" "$NC"
}

line_content() {
    local w="$1" text="${2:-}"
    local inner=$((w-4))
    text=$(crop_visible "$inner" "$text")
    printf "%b│%b %b %b│%b" "$C_PRIMARY" "$NC" "$(ui_pad_right "$inner" "$text")" "$C_PRIMARY" "$NC"
}

print_pair() {
    local left="$1" right="$2"
    printf "%b  %b\n" "$left" "$right"
}

make_menu_lines() {
    MENU_LINES=()
    MENU_LINES+=("$(line_top "$LEFT_W" "MAIN MENU")")
    MENU_LINES+=("$(line_content "$LEFT_W" "")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[1] Port Scanning${NC}      ${C_GRAY}Discover ports${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[2] DoS Attack${NC}          ${C_GRAY}Sim service flood${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[3] ARP Spoofing${NC}        ${C_GRAY}MITM pattern${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[4] Brute Force${NC}         ${C_GRAY}Login burst${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[5] Malware Detect${NC}      ${C_GRAY}File alert${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[6] Random Sim${NC}          ${C_GRAY}Auto scenario${NC}")")
    MENU_LINES+=("$(line_mid "$LEFT_W")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[7] SOC Dashboard${NC}       ${C_GRAY}Overview${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[8] Session Summary${NC}     ${C_GRAY}Review${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[9] Threat Map${NC}          ${C_GRAY}Patterns${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[A] IOC Export${NC}          ${C_GRAY}Indicators${NC}")")
    MENU_LINES+=("$(line_mid "$LEFT_W")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[T] Change Target${NC}       ${C_GRAY}New host${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[R] Re-scan${NC}             ${C_GRAY}Discover${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[H] Help${NC}                ${C_GRAY}Commands${NC}")")
    MENU_LINES+=("$(line_content "$LEFT_W" "${C_WHITE}[0] Exit${NC}                ${C_GRAY}Save exit${NC}")")
    MENU_LINES+=("$(line_bottom "$LEFT_W")")
}

make_overview_lines() {
    local critical high medium low total common target risk health hfill hempty
    critical=$(count_sev Critical)
    high=$(count_sev High)
    medium=$(count_sev Medium)
    low=$(count_sev Low)
    total=$((critical + high + medium + low))
    common=$(crop_visible 20 "$(get_most_common_attack)")
    target=$(crop_visible 16 "$(get_top_target)")
    risk=${SESSION_LAST_RISK:-0}; [[ "$risk" =~ ^[0-9]+$ ]] || risk=0
    health=$((100 - critical*15 - high*8 - medium*4))
    [ "$health" -lt 0 ] && health=0
    hfill=$((health / 10))
    hempty=$((10 - hfill))

    OVERVIEW_LINES=()
    OVERVIEW_LINES+=("$(line_top "$RIGHT_W" "LIVE SECURITY OVERVIEW")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_PURPLE}INCIDENT SEVERITY${NC} ${C_GRAY}(This Session)${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_RED}CRITICAL${NC}  $(mini_bar "$critical" "$C_RED" 10) ${C_RED}${critical}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_ORANGE}HIGH${NC}      $(mini_bar "$high" "$C_ORANGE" 10) ${C_ORANGE}${high}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_YELLOW}MEDIUM${NC}    $(mini_bar "$medium" "$C_YELLOW" 10) ${C_YELLOW}${medium}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_BLUE2}LOW${NC}       $(mini_bar "$low" "$C_BLUE2" 10) ${C_BLUE2}${low}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "TOTAL INCIDENTS  ${C_NEON}${total}${NC}")")
    OVERVIEW_LINES+=("$(line_mid "$RIGHT_W")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_NEON}TOP ATTACK TYPE${NC} ${C_WHITE}${common}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_NEON}TOP TARGET${NC}      ${C_WHITE}${target}${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_NEON}SESSION RISK${NC}    ${C_WHITE}${risk}/100${NC}")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_NEON}SYSTEM HEALTH${NC}   ${C_GREEN}$(ui_repeat "█" "$hfill")${C_GRAY}$(ui_repeat "░" "$hempty")${NC} ${health}/100")")
    OVERVIEW_LINES+=("$(line_mid "$RIGHT_W")")
    OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_NEON}ANALYST TASKS${NC}")")
    if [ "$risk" -ge 60 ]; then
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_WARN}[1] Review repeated alerts${NC}")")
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_WHITE}[2] Check target activity${NC}")")
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_WHITE}[3] Prepare short report note${NC}")")
    else
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_SUCCESS}[1] Continue monitoring${NC}")")
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_WHITE}[2] Run one simulation${NC}")")
        OVERVIEW_LINES+=("$(line_content "$RIGHT_W" "${C_WHITE}[3] Review session summary${NC}")")
    fi
    OVERVIEW_LINES+=("$(line_bottom "$RIGHT_W")")
}

display_attack_menu() {
    make_menu_lines
    make_overview_lines
    local max=${#MENU_LINES[@]}
    [ "${#OVERVIEW_LINES[@]}" -gt "$max" ] && max=${#OVERVIEW_LINES[@]}
    local i left right
    for ((i=0; i<max; i++)); do
        left="${MENU_LINES[$i]:-$(line_content "$LEFT_W" "")}"
        right="${OVERVIEW_LINES[$i]:-$(line_content "$RIGHT_W" "")}"
        print_pair "$left" "$right"
    done
}

show_recent_activity_compact() {
    local line max_msg
    max_msg=$((UI_WIDTH - 18))
    [ "$max_msg" -lt 60 ] && max_msg=60

    ui_box_top "$UI_WIDTH" "SYSTEM MESSAGES"
    if [ -s "$SUMMARY_FILE" ]; then
        tail -n 4 "$SUMMARY_FILE" | while IFS= read -r line; do
            line=$(crop_visible "$max_msg" "$line")
            ui_box_line "$UI_WIDTH" "${C_GREEN}[OK]${NC} ${C_GRAY}${line}${NC}"
        done
    else
        ui_box_line "$UI_WIDTH" "${C_GREEN}[OK]${NC} System initialized successfully."
        ui_box_line "$UI_WIDTH" "${C_GREEN}[OK]${NC} Log files are ready."
        ui_box_line "$UI_WIDTH" "${C_PRIMARY}[i]${NC} Ready. Choose an action from the menu."
    fi
    ui_box_bottom "$UI_WIDTH"
}

show_fixed_shortcuts_footer() {
    PINNED_FOOTER_ACTIVE=1
    # Draw shortcuts as a real footer at the bottom of the terminal.
    # This keeps the main dashboard clean while preserving your original UI style.
    local cols rows footer_w inner_w prompt_row
    cols=$(tput cols 2>/dev/null || echo 120)
    rows=$(tput lines 2>/dev/null || echo 30)

    [ "$cols" -lt 84 ] && cols=84
    footer_w=$((cols - 4))
    inner_w=$((footer_w - 4))

    # Keep the footer on the last 3 terminal rows.
    tput cup $((rows - 3)) 0 2>/dev/null || true
    printf "\033[2K%b╔%s╗%b" "$C_PRIMARY" "$(ui_repeat "═" $((footer_w - 2)))" "$NC"

    tput cup $((rows - 2)) 0 2>/dev/null || true
    printf "\033[2K%b║%b %b %b║%b" \
        "$C_PRIMARY" "$NC" \
        "$(ui_pad_right "$inner_w" "${C_NEON}F1${NC} Help   |   ${C_NEON}F2${NC} Dashboard   |   ${C_NEON}F9${NC} Summary   |   ${C_NEON}Ctrl+L${NC} Clear   |   ${C_NEON}Q${NC} Quit      ${C_GRAY}Built for Cybersecurity - Made to Defend${NC}")" \
        "$C_PRIMARY" "$NC"

    tput cup $((rows - 1)) 0 2>/dev/null || true
    printf "\033[2K%b╚%s╝%b" "$C_PRIMARY" "$(ui_repeat "═" $((footer_w - 2)))" "$NC"

    # Move cursor to the clean command line above the footer.
    prompt_row=$((rows - 4))
    [ "$prompt_row" -lt 0 ] && prompt_row=0
    tput cup "$prompt_row" 0 2>/dev/null || true
    printf "\033[2K"
}

clear_fixed_shortcuts_footer() {
    # Remove the pinned footer before running actions, alerts, or loading screens.
    # This prevents prompts and progress bars from printing over the footer.
    local rows i
    rows=$(tput lines 2>/dev/null || echo 30)
    for i in 1 2 3 4 5; do
        tput cup $((rows - i)) 0 2>/dev/null || true
        printf "\033[2K"
    done
    PINNED_FOOTER_ACTIVE=0
    tput cup $((rows - 4)) 0 2>/dev/null || true
}

show_command_center() {
    ui_topbar
    ui_brand_panel
    echo ""
    ui_context_cards
    echo ""
    display_attack_menu
    echo ""
    show_recent_activity_compact
    echo ""
    echo ""
    echo ""
    echo ""
    echo ""
    show_fixed_shortcuts_footer
}

show_help_screen() {
    ui_box_top "$UI_WIDTH" "COMPETITION DEMO GUIDE"
    ui_box_line "$UI_WIDTH" "${C_NEON}Best flow:${NC} Malware Detection → Critical Alert → Dashboard → IOC Export → Session Summary"
    ui_box_line "$UI_WIDTH" "${C_NEON}Judge focus:${NC} Explain detection, severity, MITRE mapping, risk score, and response action."
    ui_box_line "$UI_WIDTH" "${C_GRAY}Tip:${NC} Run 2–3 simulations before judging so dashboard has useful data."
    ui_box_line "$UI_WIDTH" "${C_GRAY}Safety:${NC} Safe educational SOC simulation only. Built for detection and response practice."
    ui_box_line "$UI_WIDTH" "${C_GRAY}Controls:${NC} Use R to re-scan only when needed. Use T to change target without restarting."
    ui_box_bottom "$UI_WIDTH"
}

show_soc_dashboard() {
    local total critical high medium low escalated top_target common_attack health hc
    total=0; [ -s "$SUMMARY_FILE" ] && total=$(wc -l < "$SUMMARY_FILE")
    critical=$(count_sev Critical); high=$(count_sev High); medium=$(count_sev Medium); low=$(count_sev Low)
    if [ -s "$SUMMARY_FILE" ]; then escalated=$(grep -c 'RepeatCount=[3-9]' "$SUMMARY_FILE" 2>/dev/null); else escalated=0; fi
    top_target=$(get_top_target); common_attack=$(get_most_common_attack)
    health=$((100 - critical*15 - high*8 - medium*4)); [ "$health" -lt 0 ] && health=0
    hc="$C_GREEN"; [ "$health" -lt 70 ] && hc="$C_YELLOW"; [ "$health" -lt 40 ] && hc="$C_RED"
    ui_topbar
    ui_box_top "$UI_WIDTH" "SOC EXECUTIVE DASHBOARD"
    ui_metric_row "$UI_WIDTH" "CONSOLE" "${C_GREEN}OPERATIONAL${NC}" "HEALTH SCORE" "${hc}${health}/100${NC}"
    ui_metric_row "$UI_WIDTH" "TOTAL INCIDENTS" "$total" "ESCALATED" "$escalated"
    ui_metric_row "$UI_WIDTH" "CRITICAL" "${C_RED}${critical}${NC}" "HIGH" "${C_ORANGE}${high}${NC}"
    ui_metric_row "$UI_WIDTH" "MEDIUM" "${C_YELLOW}${medium}${NC}" "LOW" "${C_GREEN}${low}${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_NEON}Top Attack${NC}  ${common_attack}    ${C_NEON}Top Target${NC}  ${top_target}"
    ui_box_line "$UI_WIDTH" "${C_NEON}Priority${NC}    ${C_YELLOW}Review repeated alerts and escalate High/Critical incidents.${NC}"
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_NEON}Recent Alerts${NC}"
    if [ -s "$SUMMARY_FILE" ]; then
        tail -n 7 "$SUMMARY_FILE" | while IFS= read -r line; do ui_box_line "$UI_WIDTH" "${C_GRAY}▸${NC} $line"; done
    else
        ui_box_line "$UI_WIDTH" "${C_GRAY}No incidents yet. Run a simulation first.${NC}"
    fi
    ui_box_bottom "$UI_WIDTH"
}

show_completion_message() {
    echo ""
    ui_box_top "$UI_WIDTH" "SOC RESPONSE PACKAGE GENERATED"
    ui_box_line "$UI_WIDTH" "${C_GREEN}[✓]${NC} Safe simulation completed. No harmful traffic or real attack action was executed."
    ui_box_line "$UI_WIDTH" "${C_GREEN}[✓]${NC} SOC alert generated with severity, risk score, and MITRE ATT&CK mapping."
    ui_box_line "$UI_WIDTH" "${C_GREEN}[✓]${NC} Incident logs, investigation report, and IOC export were updated."
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_NEON}Recommended demo:${NC} ${C_WHITE}[7] Dashboard${NC} → ${C_WHITE}[A] IOC Export${NC} → ${C_WHITE}[8] Session Summary${NC}"
    ui_box_bottom "$UI_WIDTH"
}


show_boot_sequence() {
    ui_topbar
    cybershield_big_banner

    ui_box_top "$UI_WIDTH" "SOC CORE INITIALIZATION"
    ui_box_line "$UI_WIDTH" "${C_NEON}[01]${NC} Loading SOC command interface..."
    sleep 0.12
    ui_box_line "$UI_WIDTH" "${C_NEON}[02]${NC} Activating threat simulation engine..."
    sleep 0.12
    ui_box_line "$UI_WIDTH" "${C_NEON}[03]${NC} Preparing MITRE ATT&CK mapping..."
    sleep 0.12
    ui_box_line "$UI_WIDTH" "${C_NEON}[04]${NC} Initializing incident logging and IOC export..."
    sleep 0.12
    ui_box_separator "$UI_WIDTH"
    ui_box_line "$UI_WIDTH" "${C_SUCCESS}[✓] CYBERSHIELD ELITE READY${NC}  ${C_GRAY}Competition demonstration mode enabled.${NC}"
    ui_box_bottom "$UI_WIDTH"
    echo ""
    sleep 0.35
}

initial_setup_flow() {
    while true; do
        ui_topbar
        cybershield_big_banner
        ui_brand_panel
        echo ""
        ui_context_cards
        echo ""
        ui_safety_notice
        show_demo_hint
        echo ""
        if select_network_range && scan_network "$SELECTED_SCAN_RANGE"; then break; fi
        pause_screen
    done
    while [ -z "$SELECTED_TARGET" ]; do
        ui_topbar
        cybershield_big_banner
        ui_brand_panel
        echo ""
        ui_context_cards
        echo ""
        if ! select_target; then status_warn "Target selection failed. Retry."; pause_screen; fi
    done
}

main() {
    check_root_advisory
    check_dependencies
    setup_environment
    show_boot_sequence
    initial_setup_flow
    local choice rows msg_row
    while true; do
        show_command_center
        read_menu_choice "Select an option:" choice
        clear_fixed_shortcuts_footer
        echo ""
        case "$choice" in
            0|q|Q)
                echo ""
                ui_box_top "$UI_WIDTH" "SESSION CLOSED"
                ui_box_line "$UI_WIDTH" "${C_GREEN}Thank you for using ${PROG_NAME}. All sessions closed safely.${NC}"
                ui_box_line "$UI_WIDTH" "${C_GRAY}Logs at: ${LOG_DIR}${NC}"
                ui_box_bottom "$UI_WIDTH"
                exit 0 ;;
            7) show_soc_dashboard; pause_screen ;;
            8) show_session_summary; pause_screen ;;
            9) show_threat_map; pause_screen ;;
            [Aa]) show_ioc_export; pause_screen ;;
            [Hh]) show_help_screen; pause_screen ;;
            [Tt]) SELECTED_TARGET=""; while [ -z "$SELECTED_TARGET" ]; do select_target || pause_screen; done; LAST_SYSTEM_MESSAGE="Target changed to ${SELECTED_TARGET}." ;;
            [Rr]) SCAN_CACHE_RANGE=""; SELECTED_SCAN_RANGE=""; SELECTED_TARGET=""; if select_network_range && scan_network "$SELECTED_SCAN_RANGE"; then while [ -z "$SELECTED_TARGET" ]; do select_target || pause_screen; done; fi ;;
            [1-6])
                if [ -z "$SELECTED_TARGET" ]; then
                    status_warn "No target selected. Choose target first."
                    while [ -z "$SELECTED_TARGET" ]; do select_target || pause_screen; done
                fi
                execute_attack "$choice" "$SELECTED_TARGET"
                SESSION_INCIDENTS=$((SESSION_INCIDENTS + 1))
                SESSION_LAST_TARGET="$SELECTED_TARGET"
                LAST_SYSTEM_MESSAGE="${SESSION_LAST_ATTACK} completed against ${SELECTED_TARGET}."
                show_completion_message
                pause_screen ;;
            *)
                status_error "Invalid selection."
                pause_screen ;;
        esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi