#!/bin/bash

# ============================================================================
# LINUX SYSTEM CONFIGURATION INFO - Enhanced Edition with Debug Capabilities
# Optimized for systemd, SysVinit, OpenRC with extended metrics
# Multi-package-manager detection (like neofetch)
# Enhanced debugging features for troubleshooting and development
# ============================================================================

# Global flags
IS_SYSTEMD="false"
DEBUG_MODE="${DEBUG_MODE:-false}"
USE_COLORS="true"
VERBOSE_MODE="false"
TRACE_COMMANDS="false"
SCRIPT_VERSION="2.2.0"

# Debug step counter for tracking execution flow
DEBUG_STEP=0

# Start time for performance tracking
SCRIPT_START_TIME=$(date +%s)

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [SECTIONS]

Linux system configuration information tool - Enhanced Edition with Debug

OPTIONS:
    -n, --no-color       Disable colored output
    -d, --debug          Enable debug mode (shows function calls and logic flow)
    -v, --verbose        Enable verbose mode (shows detailed command outputs)
    -t, --trace          Enable command tracing (shows every command executed)
    -h, --help           Show this help message
    --version            Show script version

SECTIONS:
    --full (default)     Show all sections
    --system             Show System Overview section
    --hardware           Show Hardware section
    --mem                Show Memory & Storage section
    --core               Show Core System Components section
    --net                Show Network Interfaces section
    --packages           Show Package Managers section
    --alternatives       Show Alternative Components section
    --virt               Show Virtualization & Containers section

EXAMPLES:
    $(basename "$0")                    # Normal execution with colors
    $(basename "$0") --no-color         # Plain text output (pipe-friendly)
    $(basename "$0") -d                 # Enable debug logging
    $(basename "$0") --system --hardware # Show specific sections
    $(basename "$0") -d -v -t           # Full tracing (debug + verbose + command trace)

EOF
}

parse_arguments() {
    SECTIONS_TO_SHOW=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--no-color|--no-colors)
                USE_COLORS="false"
                shift
                ;;
            -d|--debug)
                DEBUG_MODE="true"
                shift
                ;;
            -v|--verbose)
                VERBOSE_MODE="true"
                shift
                ;;
            -t|--trace)
                TRACE_COMMANDS="true"
                # Trace mode implies verbose and debug
                VERBOSE_MODE="true"
                DEBUG_MODE="true"
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            --version)
                echo "sysinfo.sh version $SCRIPT_VERSION"
                exit 0
                ;;
            --full)
                SECTIONS_TO_SHOW+=("system" "hardware" "mem" "core" "net" "packages" "alternatives" "virt")
                shift
                ;;
            --system)
                SECTIONS_TO_SHOW+=("system")
                shift
                ;;
            --hardware)
                SECTIONS_TO_SHOW+=("hardware")
                shift
                ;;
            --mem)
                SECTIONS_TO_SHOW+=("mem")
                shift
                ;;
            --core)
                SECTIONS_TO_SHOW+=("core")
                shift
                ;;
            --net)
                SECTIONS_TO_SHOW+=("net")
                shift
                ;;
            --packages)
                SECTIONS_TO_SHOW+=("packages")
                shift
                ;;
            --alternatives)
                SECTIONS_TO_SHOW+=("alternatives")
                shift
                ;;
            --virt)
                SECTIONS_TO_SHOW+=("virt")
                shift
                ;;
            *)
                echo "Unknown option: $1" >&2
                show_usage
                exit 1
                ;;
        esac
    done

    if [[ ${#SECTIONS_TO_SHOW[@]} -eq 0 ]]; then
        SECTIONS_TO_SHOW=("system" "hardware" "mem" "core" "net" "packages" "alternatives" "virt")
    fi
}

# ============================================================================
# COLOR INITIALIZATION
# ============================================================================

init_colors() {
    if [[ "$USE_COLORS" == "true" ]] && [[ -t 1 ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[0;33m'
        BLUE='\033[0;34m'
        MAGENTA='\033[0;35m'
        CYAN='\033[0;36m'
        WHITE='\033[1;37m'
        BOLD='\033[1m'
        RESET='\033[0m'
        # Additional colors for debug levels
        GRAY='\033[0;90m'
        BRIGHT_YELLOW='\033[1;33m'
        BRIGHT_CYAN='\033[1;36m'
    else
        RED=''
        GREEN=''
        YELLOW=''
        BLUE=''
        MAGENTA=''
        CYAN=''
        WHITE=''
        BOLD=''
        RESET=''
        GRAY=''
        BRIGHT_YELLOW=''
        BRIGHT_CYAN=''
    fi
}

# ============================================================================
# ENHANCED DEBUG LOGGING FUNCTIONS
# ============================================================================

# Increment debug step counter and format step number
debug_step_counter() {
    ((DEBUG_STEP++))
    printf "[%03d]" "$DEBUG_STEP"
}

# Get elapsed time since script start
get_elapsed_time() {
    local current_time
    current_time=$(date +%s)
    local elapsed=$((current_time - SCRIPT_START_TIME))
    printf "+%.2fs" "$elapsed"
}

# Enhanced debug log with step counter and timing
debug_log() {
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local step
        step=$(debug_step_counter)
        local elapsed
        elapsed=$(get_elapsed_time)
        echo -e "${GRAY}${step}${RESET} ${YELLOW}[DEBUG]${RESET} ${GRAY}${elapsed}${RESET} $*" >&2
    fi
}

# Info level logging - always shown in debug mode
debug_info() {
    if [[ "$DEBUG_MODE" == "true" ]]; then
        local step
        step=$(debug_step_counter)
        local elapsed
        elapsed=$(get_elapsed_time)
        echo -e "${GRAY}${step}${RESET} ${BRIGHT_CYAN}[INFO]${RESET}  ${GRAY}${elapsed}${RESET} $*" >&2
    fi
}

# Verbose logging - only shown in verbose mode
debug_verbose() {
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        local step
        step=$(debug_step_counter)
        local elapsed
        elapsed=$(get_elapsed_time)
        echo -e "${GRAY}${step}${RESET} ${GREEN}[VERB]${RESET}  ${GRAY}${elapsed}${RESET} $*" >&2
    fi
}

# Command trace logging - shows commands being executed
debug_cmd() {
    if [[ "$TRACE_COMMANDS" == "true" ]]; then
        local step
        step=$(debug_step_counter)
        local elapsed
        elapsed=$(get_elapsed_time)
        echo -e "${GRAY}${step}${RESET} ${BRIGHT_YELLOW}[CMD]${RESET}   ${GRAY}${elapsed}${RESET} ${CYAN}➜${RESET} $*" >&2
    fi
}

# Function entry logging with parameters
debug_function_enter() {
    local func_name="$1"
    shift
    local params="$*"
    debug_info "${MAGENTA}→ ENTERING${RESET} ${BOLD}${func_name}${RESET}${params:+ with params: ${CYAN}${params}${RESET}}"
}

# Function exit logging with return value
debug_function_exit() {
    local func_name="$1"
    local return_val="${2:-}"
    if [[ -n "$return_val" ]]; then
        debug_info "${MAGENTA}← EXITING${RESET}  ${BOLD}${func_name}${RESET} → ${GREEN}${return_val}${RESET}"
    else
        debug_info "${MAGENTA}← EXITING${RESET}  ${BOLD}${func_name}${RESET}"
    fi
}

# Execute command with full tracing
trace_exec() {
    local description="$1"
    shift
    local cmd="$*"
    
    debug_cmd "${description}: ${YELLOW}${cmd}${RESET}"
    
    # Execute and capture output and exit code
    local output
    local exit_code
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
        if [[ -n "$output" ]]; then
            debug_verbose "Command output:\n${GRAY}${output}${RESET}"
        fi
        if [[ $exit_code -ne 0 ]]; then
            debug_log "${RED}Command failed with exit code: ${exit_code}${RESET}"
        fi
    else
        output=$(eval "$cmd" 2>&1)
        exit_code=$?
    fi
    
    echo "$output"
    return $exit_code
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_info() {
    local label="$1"
    local value="$2"
    local color="${3:-$GREEN}"
    printf "${CYAN}%-30s${RESET}: ${color}%s${RESET}\n" "$label" "$value"
}

print_info_multiline() {
    local label="$1"
    shift
    local values=("$@")
    local color="${GREEN}"
    
    if [[ ${#values[@]} -eq 0 ]]; then
        printf "${CYAN}%-30s${RESET}: ${color}%s${RESET}\n" "$label" "None"
        return
    fi
    
    printf "${CYAN}%-30s${RESET}: ${color}%s${RESET}\n" "$label" "${values[0]}"
    for ((i=1; i<${#values[@]}; i++)); do
        printf "${CYAN}%-30s${RESET}  ${color}%s${RESET}\n" "" "${values[i]}"
    done
}

format_with_version() {
    local name="$1"
    local version="$2"
    
    debug_function_enter "format_with_version" "$name" "$version"
    
    local result
    if [[ -z "$version" ]] || [[ "$version" == "unknown" ]] || [[ "$version" == "N/A" ]]; then
        result="$name"
    else
        result="$name (v. ${version})"
    fi
    
    debug_function_exit "format_with_version" "$result"
    echo "$result"
}

# ============================================================================
# INIT SYSTEM DETECTION
# ============================================================================

detect_init_and_set_env() {
    debug_function_enter "detect_init_and_set_env"
    
    debug_log "Checking for systemd init system..."
    if [[ -d /run/systemd/system ]]; then
        IS_SYSTEMD="true"
        debug_info "Detected ${GREEN}systemd${RESET} init system (directory /run/systemd/system exists)"
    else
        IS_SYSTEMD="false"
        debug_info "Detected ${YELLOW}non-systemd${RESET} init system (SysVinit/OpenRC)"
    fi
    
    debug_function_exit "detect_init_and_set_env" "IS_SYSTEMD=$IS_SYSTEMD"
}

is_service_active() {
    local service_name="$1"
    
    debug_function_enter "is_service_active" "$service_name"
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_cmd "Checking service status via systemd: systemctl is-active --quiet $service_name"
        systemctl is-active --quiet "$service_name" 2>/dev/null
        local result=$?
        debug_function_exit "is_service_active" "exit_code=$result"
        return $result
    else
        debug_log "Checking service via legacy methods (pgrep, service, init.d)..."
        
        # Method 1: Check via pgrep
        if pgrep -x "$service_name" >/dev/null 2>&1; then
            debug_verbose "Service found running via pgrep"
            debug_function_exit "is_service_active" "active (pgrep)"
            return 0
        fi
        
        # Method 2: Check via service command
        if command -v service >/dev/null 2>&1; then
            debug_cmd "Checking via service command: service $service_name status"
            service "$service_name" status >/dev/null 2>&1
            local result=$?
            if [[ $result -eq 0 ]]; then
                debug_function_exit "is_service_active" "active (service)"
                return 0
            fi
        fi
        
        # Method 3: Check via init.d
        if [[ -f "/etc/init.d/$service_name" ]]; then
            debug_cmd "Checking via init.d: /etc/init.d/$service_name status"
            "/etc/init.d/$service_name" status >/dev/null 2>&1
            local result=$?
            debug_function_exit "is_service_active" "exit_code=$result (init.d)"
            return $result
        fi
        
        debug_function_exit "is_service_active" "inactive"
        return 1
    fi
}

# ============================================================================
# DATA COLLECTION FUNCTIONS
# ============================================================================

# Section: System Overview
get_system_info() {
    debug_function_enter "get_system_info"
    HOSTNAME=$(hostname)
    HOST_MODEL=$(get_host_info)
    DISTRO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
    [[ -z "$DISTRO" ]] && DISTRO=$(lsb_release -d 2>/dev/null | cut -f2)
    KERNEL=$(uname -r)
    ARCH=$(uname -m)
    UPTIME=$(uptime -p 2>/dev/null | sed 's/up //')
    [[ -z "$UPTIME" ]] && UPTIME=$(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')
    SHELL_VERSION=$(basename "$SHELL")
    debug_function_exit "get_system_info"
}

# Section: Hardware
get_hardware_info() {
    debug_function_enter "get_hardware_info"
    CPU_INFO=$(get_cpu_info)
    GPU_INFO=$(get_gpu_info)
    GPU_ARRAY=()
    if [[ "$GPU_INFO" != "Unable to detect" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && GPU_ARRAY+=("$line")
        done < <(echo "$GPU_INFO" | tr '|' '\n')
    else
        GPU_ARRAY=("Unable to detect")
    fi
    debug_function_exit "get_hardware_info"
}

# Section: Memory & Storage
get_mem_info() {
    debug_function_enter "get_mem_info"
    MEMORY_INFO=$(get_memory_info)
    SWAP_INFO=$(get_swap_info)
    DISK_SUMMARY=()
    while IFS= read -r line; do
        DISK_SUMMARY+=("$line")
    done < <(get_disk_summary)
    PARTITIONS=()
    while IFS= read -r line; do
        PARTITIONS+=("$line")
    done < <(get_partition_layout)
    debug_function_exit "get_mem_info"
}

# Section: Core System Components
get_core_info() {
    debug_function_enter "get_core_info"
    INIT_SYSTEM=$(detect_init)
    INIT_VERSION=$(get_component_version "$INIT_SYSTEM")
    INIT_DISPLAY=$(format_with_version "$INIT_SYSTEM" "$INIT_VERSION")
    NETWORK_MGR=$(detect_network_manager)
    NETWORK_VERSION=$(get_component_version "$NETWORK_MGR")
    NETWORK_DISPLAY=$(format_with_version "$NETWORK_MGR" "$NETWORK_VERSION")
    TIME_SYNC=$(detect_time_sync)
    TIME_VERSION=$(get_component_version "$TIME_SYNC")
    TIME_DISPLAY=$(format_with_version "$TIME_SYNC" "$TIME_VERSION")
    FIREWALL=$(detect_firewall)
    FIREWALL_VERSION=$(get_component_version "$FIREWALL")
    FIREWALL_DISPLAY=$(format_with_version "$FIREWALL" "$FIREWALL_VERSION")
    DNS_RESOLVER=$(detect_dns_resolver)
    CRON_SYS=$(detect_cron)
    SECURITY=$(detect_security)
    if [[ "$SECURITY" == "AppArmor" ]]; then
        SECURITY_VERSION=$(get_component_version "$SECURITY")
        SECURITY_DISPLAY=$(format_with_version "$SECURITY" "$SECURITY_VERSION")
    else
        SECURITY_DISPLAY="$SECURITY"
    fi
    DISPLAY_SERVER=$(detect_display_server)
    BOOTLOADER=$(detect_bootloader)
    debug_function_exit "get_core_info"
}

# Section: Network Interfaces
get_net_info() {
    debug_function_enter "get_net_info"
    net_info # This function will now populate the arrays directly
    debug_function_exit "get_net_info"
}

# Section: Package Managers
get_packages_info() {
    debug_function_enter "get_packages_info"
    PKG_MGR=$(detect_package_manager)
    PKG_MANAGERS=$(detect_all_package_managers)
    debug_function_exit "get_packages_info"
}

# Section: Alternative Components
get_alternatives_info() {
    debug_function_enter "get_alternatives_info"
    NETWORK_ALTERNATIVES=()
    while IFS= read -r line; do
        NETWORK_ALTERNATIVES+=("$line")
    done < <(detect_network_alternatives)
    FIREWALL_ALTERNATIVES=()
    while IFS= read -r line; do
        FIREWALL_ALTERNATIVES+=("$line")
    done < <(detect_firewall_alternatives)
    TIMESYNC_ALTERNATIVES=()
    while IFS= read -r line; do
        TIMESYNC_ALTERNATIVES+=("$line")
    done < <(detect_timesync_alternatives)
    debug_function_exit "get_alternatives_info"
}

# Section: Virtualization & Containers
get_virt_info() {
    debug_function_enter "get_virt_info"
    KVM_STATUS=$(detect_kvm)
    CONTAINER_RUNTIME=$(detect_container_runtime)
    DOCKER_CONTAINERS=$(get_docker_containers)
    PODMAN_CONTAINERS=$(get_podman_containers)
    LXC_CONTAINERS=$(get_lxc_containers)
    DOCKER_ARRAY=()
    if [[ -n "$DOCKER_CONTAINERS" ]] && [[ "$DOCKER_CONTAINERS" != "None running" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && DOCKER_ARRAY+=("$line")
        done < <(echo "$DOCKER_CONTAINERS" | tr '|' '\n')
    fi
    PODMAN_ARRAY=()
    if [[ -n "$PODMAN_CONTAINERS" ]] && [[ "$PODMAN_CONTAINERS" != "None running" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && PODMAN_ARRAY+=("$line")
        done < <(echo "$PODMAN_CONTAINERS" | tr '|' '\n')
    fi
    LXC_ARRAY=()
    if [[ -n "$LXC_CONTAINERS" ]] && [[ "$LXC_CONTAINERS" != "None running" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && LXC_ARRAY+=("$line")
        done < <(echo "$LXC_CONTAINERS" | tr '|' '\n')
    fi
    declare -A DOCKER_DETAILS
    while IFS=':' read -r key value; do
        [[ -n "$key" ]] && DOCKER_DETAILS["$key"]="$value"
    done < <(get_docker_details)
    declare -A PODMAN_DETAILS
    while IFS=':' read -r key value; do
        [[ -n "$key" ]] && PODMAN_DETAILS["$key"]="$value"
    done < <(get_podman_details)
    declare -A LXC_DETAILS
    while IFS=':' read -r key value; do
        [[ -n "$key" ]] && LXC_DETAILS["$key"]="$value"
    done < <(get_lxc_details)
    debug_function_exit "get_virt_info"
}
# ============================================================================
# DETECTION FUNCTIONS - BASIC
# ============================================================================

detect_init() {
    debug_function_enter "detect_init"
    
    local init_system
    
    if [[ -d /run/systemd/system ]]; then
        init_system="systemd"
        debug_log "Init system detected via /run/systemd/system: $init_system"
    elif [[ -f /sbin/openrc ]]; then
        init_system="OpenRC"
        debug_log "Init system detected via /sbin/openrc: $init_system"
    elif ps -p 1 -o comm= 2>/dev/null | grep -q "init"; then
        init_system="SysVinit"
        debug_log "Init system detected via ps -p 1: $init_system"
    else
        init_system="Unknown"
        debug_log "Init system could not be determined: $init_system"
    fi
    
    debug_function_exit "detect_init" "$init_system"
    echo "$init_system"
}

detect_network_manager() {
    debug_function_enter "detect_network_manager"
    
    local network_mgr
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_log "Checking network manager options for systemd system..."
        
        if is_service_active NetworkManager; then
            network_mgr="NetworkManager"
        elif is_service_active systemd-networkd; then
            network_mgr="systemd-networkd"
        elif is_service_active networking; then
            network_mgr="ifupdown/ifupdown2"
        elif command -v netplan >/dev/null 2>&1; then
            network_mgr="Netplan"
            debug_verbose "Netplan command found"
        else
            network_mgr="Unknown"
        fi
    else
        debug_log "Checking network manager options for non-systemd system..."
        
        if pgrep -x "NetworkManager" >/dev/null 2>&1; then
            network_mgr="NetworkManager"
            debug_verbose "NetworkManager process found via pgrep"
        elif [[ -f /etc/init.d/networking ]]; then
            network_mgr="ifupdown/manual"
            debug_verbose "Found /etc/init.d/networking"
        else
            network_mgr="Manual"
        fi
    fi
    
    debug_function_exit "detect_network_manager" "$network_mgr"
    echo "$network_mgr"
}

detect_time_sync() {
    debug_function_enter "detect_time_sync"
    
    local time_sync
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_log "Checking time sync services for systemd..."
        
        if is_service_active chronyd; then
            time_sync="chrony"
        elif is_service_active ntpd || is_service_active ntp; then
            time_sync="ntpd"
        elif is_service_active systemd-timesyncd; then
            time_sync="systemd-timesyncd"
        else
            time_sync="None/Manual"
        fi
    else
        debug_log "Checking time sync services for non-systemd..."
        
        if pgrep -x "chronyd" >/dev/null 2>&1; then
            time_sync="chrony"
        elif pgrep -x "ntpd" >/dev/null 2>&1; then
            time_sync="ntpd"
        else
            time_sync="None/Manual"
        fi
    fi
    
    debug_function_exit "detect_time_sync" "$time_sync"
    echo "$time_sync"
}

detect_firewall() {
    debug_function_enter "detect_firewall"
    
    local fw=""
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_log "Checking firewall options for systemd system..."
        
        if is_service_active ufw; then
            fw="ufw"
        elif is_service_active firewalld; then
            fw="firewalld"
        elif command -v nft >/dev/null 2>&1 && [[ $(nft list ruleset 2>/dev/null | wc -l) -gt 0 ]]; then
            fw="nftables"
            debug_verbose "nftables detected with active rules"
        elif command -v iptables >/dev/null 2>&1 && [[ $(iptables -L 2>/dev/null | wc -l) -gt 8 ]]; then
            fw="iptables"
            debug_verbose "iptables detected with custom rules"
        else
            fw="None"
        fi
    else
        debug_log "Checking firewall options for non-systemd system..."
        
        if pgrep -x "ufw" >/dev/null 2>&1 || [[ -f /etc/init.d/ufw ]]; then
            fw="ufw"
        elif command -v iptables >/dev/null 2>&1 && [[ $(iptables -L 2>/dev/null | wc -l) -gt 8 ]]; then
            fw="iptables"
        else
            fw="None"
        fi
    fi
    
    debug_function_exit "detect_firewall" "$fw"
    echo "$fw"
}

# ============================================================================
# ACTIVE CONTAINERS DETECTION
# ============================================================================

get_docker_containers() {
    debug_function_enter "get_docker_containers"
    
    if ! command -v docker >/dev/null 2>&1; then
        debug_log "Docker command not found, skipping..."
        debug_function_exit "get_docker_containers" "docker not available"
        return
    fi
    
    local containers=()
    local container_count=0
    
    debug_log "Querying Docker for running containers..."
    
    # List running containers with name, image, status and uptime
    while IFS='|' read -r name image status uptime; do
        if [[ -n "$name" ]]; then
            containers+=("$name [$image] ($status, up $uptime)")
            ((container_count++))
            debug_verbose "Found Docker container: $name [$image]"
        fi
    done < <(trace_exec "Query Docker containers" 'docker ps --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.RunningFor}}" 2>/dev/null')
    
    if [[ ${#containers[@]} -eq 0 ]]; then
        debug_log "No running Docker containers found"
        echo "None running"
    else
        debug_info "Found $container_count running Docker container(s)"
        # Return all containers separated by |||
        local container_str="${containers[0]}"
        for ((i=1; i<${#containers[@]}; i++)); do
            container_str="${container_str}|||${containers[$i]}"
        done
        debug_function_exit "get_docker_containers" "$container_count containers"
        echo "$container_str"
    fi
}

get_podman_containers() {
    debug_function_enter "get_podman_containers"
    
    if ! command -v podman >/dev/null 2>&1; then
        debug_log "Podman command not found, skipping..."
        debug_function_exit "get_podman_containers" "podman not available"
        return
    fi
    
    local containers=()
    local container_count=0
    
    debug_log "Querying Podman for running containers..."
    
    # List running containers with name, image, status and uptime
    while IFS='|' read -r name image status uptime; do
        if [[ -n "$name" ]]; then
            containers+=("$name [$image] ($status, up $uptime)")
            ((container_count++))
            debug_verbose "Found Podman container: $name [$image]"
        fi
    done < <(trace_exec "Query Podman containers" 'podman ps --format "{{.Names}}|{{.Image}}|{{.Status}}|{{.RunningFor}}"')
    
    if [[ ${#containers[@]} -eq 0 ]]; then
        debug_log "No running Podman containers found"
        echo "None running"
    else
        debug_info "Found $container_count running Podman container(s)"
        local container_str="${containers[0]}"
        for ((i=1; i<${#containers[@]}; i++)); do
            container_str="${container_str}|||${containers[$i]}"
        done
        debug_function_exit "get_podman_containers" "$container_count containers"
        echo "$container_str"
    fi
}

get_lxc_containers() {
    debug_function_enter "get_lxc_containers"
    
    local containers=()
    local container_count=0
    
    # LXC traditional
    if command -v lxc-ls >/dev/null 2>&1; then
        debug_log "Checking LXC containers via lxc-ls..."
        
        while IFS= read -r container; do
            if [[ -n "$container" ]]; then
                debug_verbose "Checking LXC container: $container"
                
                # Get process PID for uptime calculation
                local pid
                pid=$(lxc-info -n "$container" -p 2>/dev/null | grep -oP "PID:\s*\K\d+")
                local uptime=""
                
                if [[ -n "$pid" ]] && [[ -f "/proc/$pid/stat" ]]; then
                    debug_cmd "Reading process start time from /proc/$pid/stat"
                    local start_time
                    start_time=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
                    
                    if [[ -n "$start_time" ]]; then
                        local boot_time
                        boot_time=$(awk '{print $1}' /proc/uptime 2>/dev/null | cut -d. -f1)
                        local container_uptime=$((boot_time - start_time / 100))
                        uptime=$(printf "%dd %dh" $((container_uptime/86400)) $(((container_uptime%86400)/3600)))
                        debug_verbose "Calculated uptime: $uptime"
                    fi
                fi
                
                if [[ -n "$uptime" ]]; then
                    containers+=("$container (running, up $uptime)")
                else
                    containers+=("$container (running)")
                fi
                ((container_count++))
            fi
        done < <(trace_exec "List running LXC containers" "lxc-ls --running")
    fi
    
    # LXD
    if command -v lxc >/dev/null 2>&1; then
        debug_log "Checking LXD containers via lxc list..."
        
        while IFS='|' read -r name status; do
            if [[ -n "$name" ]] && [[ "$status" == "RUNNING" ]]; then
                containers+=("$name (running)")
                ((container_count++))
                debug_verbose "Found LXD container: $name (running)"
            fi
        done < <(trace_exec "List LXD containers" "lxc list --format csv -c ns")
    fi
    
    if [[ ${#containers[@]} -eq 0 ]]; then
        debug_log "No running LXC/LXD containers found"
        echo "None running"
    else
        debug_info "Found $container_count running LXC/LXD container(s)"
        local container_str="${containers[0]}"
        for ((i=1; i<${#containers[@]}; i++)); do
            container_str="${container_str}|||${containers[$i]}"
        done
        debug_function_exit "get_lxc_containers" "$container_count containers"
        echo "$container_str"
    fi
}
# ============================================================================
# PACKAGE MANAGER DETECTION - EXTENDED (like neofetch)
# ============================================================================

detect_all_package_managers() {
    debug_function_enter "detect_all_package_managers"
    
    local packages=()
    local pkg_count=0
    local total_packages=0
    
    debug_log "Scanning for installed package managers and counting packages..."
    
    # Native package managers
    if command -v pacman >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count pacman packages" "pacman -Qq 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (pacman)") && ((total_packages+=pkg_count))
        debug_verbose "Pacman: $pkg_count packages"
    fi
    
    if command -v dpkg >/dev/null 2>&1 && [[ ! -f /etc/arch-release ]]; then
        pkg_count=$(trace_exec "Count dpkg packages" 'dpkg --get-selections 2>/dev/null | grep -c "install$"')
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (dpkg)") && ((total_packages+=pkg_count))
        debug_verbose "dpkg: $pkg_count packages"
    fi
    
    if command -v dnf >/dev/null 2>&1 && [[ ! -f /etc/arch-release ]]; then
        pkg_count=$(trace_exec "Count dnf packages" "dnf list installed 2>/dev/null | tail -n +2 | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (dnf)") && ((total_packages+=pkg_count))
        debug_verbose "dnf: $pkg_count packages"
    fi
    
    if command -v rpm >/dev/null 2>&1 && ! command -v dnf >/dev/null 2>&1 && [[ ! -f /etc/arch-release ]]; then
        pkg_count=$(trace_exec "Count rpm packages" "rpm -qa 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (rpm)") && ((total_packages+=pkg_count))
        debug_verbose "rpm: $pkg_count packages"
    fi
    
    if command -v zypper >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count zypper packages" 'zypper se --installed-only 2>/dev/null | grep "^i" | wc -l')
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (zypper)") && ((total_packages+=pkg_count))
        debug_verbose "zypper: $pkg_count packages"
    fi
    
    if command -v emerge >/dev/null 2>&1; then
        pkg_count=$(qlist -I 2>/dev/null | wc -l)
        [[ $pkg_count -eq 0 ]] && pkg_count=$(ls -d /var/db/pkg/*/* 2>/dev/null | wc -l)
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (emerge)") && ((total_packages+=pkg_count))
        debug_verbose "emerge: $pkg_count packages"
    fi
    
    if command -v xbps-query >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count xbps packages" "xbps-query -l 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (xbps)") && ((total_packages+=pkg_count))
        debug_verbose "xbps: $pkg_count packages"
    fi
    
    if command -v apk >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count apk packages" "apk info 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (apk)") && ((total_packages+=pkg_count))
        debug_verbose "apk: $pkg_count packages"
    fi
    
    # Universal package managers
    debug_log "Checking universal package managers (flatpak, snap, etc.)..."
    
    if command -v flatpak >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count flatpak packages" "flatpak list --app 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (flatpak)") && ((total_packages+=pkg_count))
        debug_verbose "flatpak: $pkg_count packages"
    fi
    
    if command -v snap >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count snap packages" "snap list 2>/dev/null | tail -n +2 | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (snap)") && ((total_packages+=pkg_count))
        debug_verbose "snap: $pkg_count packages"
    fi
    
    # AppImage
    debug_log "Scanning for AppImage files in common directories..."
    local appimage_dirs=(
        "$HOME/.local/bin"
        "$HOME/Applications"
        "$HOME/AppImages"
        "/opt/appimages"
    )
    
    local appimage_count=0
    for dir in "${appimage_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local count
            count=$(find "$dir" -maxdepth 1 -type f -name "*.AppImage" 2>/dev/null | wc -l)
            appimage_count=$((appimage_count + count))
            debug_verbose "Found $count AppImages in $dir"
        fi
    done
    [[ $appimage_count -gt 0 ]] && packages+=("${appimage_count} (appimage)") && ((total_packages+=appimage_count))
    
    # Other package managers
    if command -v brew >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count brew packages" "brew list --formula 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (brew)") && ((total_packages+=pkg_count))
        debug_verbose "brew: $pkg_count packages"
    fi
    
    if command -v nix-env >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count nix packages" "nix-env -q 2>/dev/null | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (nix)") && ((total_packages+=pkg_count))
        debug_verbose "nix: $pkg_count packages"
    fi
    
    # Programming language package managers
    debug_log "Checking language-specific package managers..."
    
    if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
        local pip_cmd="pip3"
        command -v pip3 >/dev/null 2>&1 || pip_cmd="pip"
        pkg_count=$(trace_exec "Count pip packages" "$pip_cmd list --user 2>/dev/null | tail -n +3 | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (pip)") && ((total_packages+=pkg_count))
        debug_verbose "pip: $pkg_count packages"
    fi
    
    if command -v uv >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count uv tools" "uv tool list 2>/dev/null | tail -n +2 | wc -l")
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (uv tool)") && ((total_packages+=pkg_count))
        debug_verbose "uv: $pkg_count tools"
    fi
    
    if command -v npm >/dev/null 2>&1; then
        pkg_count=$(trace_exec "Count npm packages" 'npm list -g --depth=0 2>/dev/null | tail -n +2 | grep -v "^$" | wc -l')
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (npm)") && ((total_packages+=pkg_count))
        debug_verbose "npm: $pkg_count packages"
    fi
    
    if command -v cargo >/dev/null 2>&1 && [[ -d "$HOME/.cargo/bin" ]]; then
        pkg_count=$(ls "$HOME/.cargo/bin" 2>/dev/null | wc -l)
        [[ $pkg_count -gt 0 ]] && packages+=("${pkg_count} (cargo)") && ((total_packages+=pkg_count))
        debug_verbose "cargo: $pkg_count binaries"
    fi
    
    if [[ ${#packages[@]} -eq 0 ]]; then
        debug_log "No package managers detected"
        echo "Unable to detect"
    else
        debug_info "Total packages detected across all managers: $total_packages"
        local IFS=", "
        debug_function_exit "detect_all_package_managers" "${#packages[@]} managers, $total_packages total packages"
        echo "${packages[*]}"
    fi
}

detect_package_manager() {
    debug_function_enter "detect_package_manager"
    
    local pkg_mgr="Unknown"
    
    debug_log "Detecting primary package manager..."
    
    if command -v pacman >/dev/null 2>&1; then
        pkg_mgr="pacman (Arch)"
    elif command -v apt >/dev/null 2>&1 && [[ -f /usr/bin/apt ]]; then
        pkg_mgr="apt (Debian/Ubuntu)"
    elif command -v dnf >/dev/null 2>&1; then
        pkg_mgr="dnf (Fedora/RHEL)"
    elif command -v yum >/dev/null 2>&1; then
        pkg_mgr="yum (RHEL/CentOS)"
    elif command -v zypper >/dev/null 2>&1; then
        pkg_mgr="zypper (openSUSE)"
    elif command -v emerge >/dev/null 2>&1; then
        pkg_mgr="emerge (Gentoo)"
    elif command -v xbps-query >/dev/null 2>&1; then
        pkg_mgr="xbps (Void)"
    elif command -v apk >/dev/null 2>&1; then
        pkg_mgr="apk (Alpine)"
    fi
    
    debug_function_exit "detect_package_manager" "$pkg_mgr"
    echo "$pkg_mgr"
}

# ============================================================================
# SECURITY DETECTION
# ============================================================================

detect_security() {
    debug_function_enter "detect_security"
    
    local security_framework
    
    if command -v getenforce >/dev/null 2>&1; then
        debug_log "Checking SELinux status..."
        local selinux_state
        selinux_state=$(trace_exec "Get SELinux status" "getenforce")
        
        if [[ "$selinux_state" =~ Enforcing|Permissive ]]; then
            security_framework="SELinux ($selinux_state)"
        else
            security_framework="SELinux (Disabled)"
        fi
    elif command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null; then
        debug_log "AppArmor detected and enabled"
        security_framework="AppArmor"
    else
        debug_log "No security framework detected"
        security_framework="None/Disabled"
    fi
    
    debug_function_exit "detect_security" "$security_framework"
    echo "$security_framework"
}

# ============================================================================
# DNS AND DISPLAY DETECTION
# ============================================================================

detect_dns_resolver() {
    debug_function_enter "detect_dns_resolver"
    
    local dns_resolver
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_log "Checking DNS resolver for systemd system..."
        
        if is_service_active systemd-resolved; then
            dns_resolver="systemd-resolved"
        elif command -v dnsmasq >/dev/null 2>&1 && pgrep -x dnsmasq >/dev/null; then
            dns_resolver="dnsmasq"
        elif grep -q "127.0.0.53" /etc/resolv.conf 2>/dev/null; then
            dns_resolver="systemd-resolved (stub)"
        else
            dns_resolver="direct (/etc/resolv.conf)"
        fi
    else
        debug_log "Checking DNS resolver for non-systemd system..."
        
        if command -v dnsmasq >/dev/null 2>&1 && pgrep -x dnsmasq >/dev/null; then
            dns_resolver="dnsmasq"
        else
            dns_resolver="direct (/etc/resolv.conf)"
        fi
    fi
    
    debug_function_exit "detect_dns_resolver" "$dns_resolver"
    echo "$dns_resolver"
}

detect_display_server() {
    debug_function_enter "detect_display_server"
    
    local display_server
    
    debug_log "Detecting display server type..."
    
    if [[ -n "$XDG_SESSION_TYPE" ]]; then
        display_server="$XDG_SESSION_TYPE"
        debug_verbose "Display server from XDG_SESSION_TYPE: $display_server"
    elif [[ -n "$WAYLAND_DISPLAY" ]]; then
        display_server="wayland"
        debug_verbose "Wayland display detected via WAYLAND_DISPLAY env var"
    elif [[ -n "$DISPLAY" ]]; then
        display_server="x11"
        debug_verbose "X11 display detected via DISPLAY env var"
    else
        display_server="No display server (headless)"
        debug_log "No display server environment variables found"
    fi
    
    debug_function_exit "detect_display_server" "$display_server"
    echo "$display_server"
}

detect_cron() {
    debug_function_enter "detect_cron"
    
    local cron_system
    
    if [[ "$IS_SYSTEMD" == "true" ]]; then
        debug_log "Checking cron/timer system for systemd..."
        
        if is_service_active cron || is_service_active cronie; then
            cron_system="cron/cronie"
        else
            local timer_count
            timer_count=$(systemctl list-timers --all --no-pager 2>/dev/null | grep -c "timer" || echo "0")
            cron_system="systemd-timers (${timer_count} timers)"
            debug_verbose "Found $timer_count systemd timers"
        fi
    else
        debug_log "Checking cron for non-systemd system..."
        
        if pgrep -x "cron" >/dev/null 2>&1 || pgrep -x "crond" >/dev/null 2>&1; then
            cron_system="cron/cronie"
        else
            cron_system="None"
        fi
    fi
    
    debug_function_exit "detect_cron" "$cron_system"
    echo "$cron_system"
}

# ============================================================================
# CONTAINER RUNTIME DETECTION - Enhanced with podman-docker support
# ============================================================================

detect_real_container_runtime() {
    debug_function_enter "detect_real_container_runtime"
    
    # Distinguish between real Docker and podman-docker
    local docker_type=""
    local podman_type=""
    
    debug_log "Analyzing container runtime configuration..."
    
    # Check if docker is really Docker or podman-docker
    if command -v docker >/dev/null 2>&1; then
        debug_verbose "Docker command found, analyzing type..."
        
        # Method 1: Check if it's a symlink to podman
        if [[ -L "$(command -v docker)" ]]; then
            local target
            target=$(readlink -f "$(command -v docker)")
            debug_cmd "Checking docker symlink target: $target"
            
            if [[ "$target" =~ podman ]]; then
                docker_type="podman-docker"
                debug_info "Docker is a symlink to podman (podman-docker wrapper)"
            else
                docker_type="docker"
                debug_info "Docker is a symlink but not to podman"
            fi
        # Method 2: Check docker version output
        elif docker version --format '{{.Server.Os}}' 2>/dev/null | grep -q "linux"; then
            # Verify if the daemon is truly docker
            local server_version
            server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
            
            if docker info 2>&1 | grep -qi "podman"; then
                docker_type="podman-docker"
                debug_info "Docker info reveals podman backend (podman-docker)"
            elif [[ -n "$server_version" ]]; then
                docker_type="docker"
                debug_info "Genuine Docker daemon detected (version: $server_version)"
            fi
        # Method 3: Check if Docker socket exists
        elif [[ -S /var/run/docker.sock ]] || systemctl is-active docker >/dev/null 2>&1; then
            docker_type="docker"
            debug_info "Docker socket or service detected (genuine Docker)"
        # Method 4: Fallback - probably podman-docker
        else
            docker_type="podman-docker"
            debug_info "Assuming podman-docker (no clear Docker indicators)"
        fi
    fi
    
    # Check native podman (direct podman command)
    if command -v podman >/dev/null 2>&1; then
        podman_type="podman"
        debug_verbose "Native podman command available"
    fi
    
    local result="docker_type:${docker_type}|podman_type:${podman_type}"
    debug_function_exit "detect_real_container_runtime" "$result"
    echo "$result"
}

detect_container_runtime() {
    debug_function_enter "detect_container_runtime"
    
    local runtimes=()
    local runtime_info
    runtime_info=$(detect_real_container_runtime)
    local docker_type
    docker_type=$(echo "$runtime_info" | grep -o 'docker_type:[^|]*' | cut -d: -f2)
    local podman_type
    podman_type=$(echo "$runtime_info" | grep -o 'podman_type:[^|]*' | cut -d: -f2)
    
    debug_log "Processing container runtime information..."
    debug_verbose "Docker type: ${docker_type:-none}"
    debug_verbose "Podman type: ${podman_type:-none}"
    
    # Real Docker
    if [[ "$docker_type" == "docker" ]]; then
        local containers
        containers=$(docker ps -q 2>/dev/null | wc -l)
        runtimes+=("Docker ($containers running)")
        debug_info "Docker: $containers running containers"
    fi
    
    # Podman (count only if not already counting via podman-docker)
    if [[ "$podman_type" == "podman" ]]; then
        local containers
        containers=$(podman ps -q 2>/dev/null | wc -l)
        
        if [[ "$docker_type" == "podman-docker" ]]; then
            runtimes+=("Podman ($containers running) [via docker alias]")
            debug_info "Podman: $containers containers (accessible via docker alias)"
        else
            runtimes+=("Podman ($containers running)")
            debug_info "Podman: $containers running containers"
        fi
    elif [[ "$docker_type" == "podman-docker" ]]; then
        # Only podman-docker without native podman
        local containers
        containers=$(docker ps -q 2>/dev/null | wc -l)
        runtimes+=("Podman ($containers running) [via docker alias]")
        debug_info "Podman (docker alias only): $containers running containers"
    fi
    
    # LXC
    if command -v lxc >/dev/null 2>&1 || command -v lxc-ls >/dev/null 2>&1; then
        debug_log "Checking LXC container count..."
        local containers=0
        
        if command -v lxc-ls >/dev/null 2>&1; then
            containers=$(lxc-ls --running 2>/dev/null | wc -w || echo "0")
        elif command -v lxc >/dev/null 2>&1; then
            containers=$(lxc list --format csv 2>/dev/null | grep -c "RUNNING" || echo "0")
        fi
        
        runtimes+=("LXC ($containers running)")
        debug_info "LXC: $containers running containers"
    fi
    
    if [[ ${#runtimes[@]} -eq 0 ]]; then
        debug_log "No container runtimes detected"
        echo "None"
    else
        debug_function_exit "detect_container_runtime" "${#runtimes[@]} runtime(s)"
        echo "${runtimes[*]}"
    fi
}

# ============================================================================
# VIRTUALIZATION AND BOOT
# ============================================================================

detect_kvm() {
    debug_function_enter "detect_kvm"
    
    local kvm_status="Inactive"
    
    debug_log "Checking if KVM kernel module is loaded..."
    
    if command -v lsmod >/dev/null 2>&1; then
        if lsmod | grep -qw kvm; then
            kvm_status="Active"
            debug_info "KVM module is loaded and active"
        else
            debug_verbose "KVM module not found in lsmod output"
        fi
    else
        debug_log "lsmod command not found, skipping KVM check."
    fi
    
    debug_function_exit "detect_kvm" "$kvm_status"
    echo "$kvm_status"
}

detect_bootloader() {
    debug_function_enter "detect_bootloader"
    
    local bootloader=""
    
    debug_log "Detecting bootloader configuration..."
    
    if [[ -d /sys/firmware/efi ]]; then
        debug_verbose "UEFI firmware detected (/sys/firmware/efi exists)"
        
        if command -v efibootmgr >/dev/null 2>&1; then
            debug_cmd "Querying EFI boot entries with efibootmgr"
            local efi_entries
            efi_entries=$(efibootmgr 2>/dev/null)
            
            if echo "$efi_entries" | grep -qi "grub"; then
                bootloader="GRUB (UEFI)"
                debug_info "GRUB UEFI bootloader detected"
            elif echo "$efi_entries" | grep -qi "systemd"; then
                bootloader="systemd-boot (UEFI)"
                debug_info "systemd-boot UEFI bootloader detected"
            elif echo "$efi_entries" | grep -qi "refind"; then
                bootloader="rEFInd (UEFI)"
                debug_info "rEFInd UEFI bootloader detected"
            else
                bootloader="UEFI"
                debug_verbose "UEFI detected but specific bootloader unknown"
            fi
        else
            bootloader="UEFI"
            debug_verbose "UEFI system but efibootmgr not available"
        fi
    elif [[ -f /boot/grub/grub.cfg ]]; then
        bootloader="GRUB (Legacy)"
        debug_info "Legacy GRUB detected (/boot/grub/grub.cfg)"
    elif [[ -f /boot/grub2/grub.cfg ]]; then
        bootloader="GRUB2 (Legacy)"
        debug_info "Legacy GRUB2 detected (/boot/grub2/grub.cfg)"
    elif [[ -f /boot/syslinux/syslinux.cfg ]]; then
        bootloader="SYSLINUX"
        debug_info "SYSLINUX bootloader detected"
    else
        bootloader="Unknown"
        debug_log "Unable to detect bootloader"
    fi
    
    debug_function_exit "detect_bootloader" "$bootloader"
    echo "$bootloader"
}

# ============================================================================
# MEMORY & STORAGE
# ============================================================================

get_memory_info() {
    debug_function_enter "get_memory_info"
    
    debug_log "Collecting RAM usage information..."
    
    local total_ram
    total_ram=$(free -h | awk '/^Mem:/{print $2}')
    local used_ram
    used_ram=$(free -h | awk '/^Mem:/{print $3}')
    local available_ram
    available_ram=$(free -h | awk '/^Mem:/{print $7}')
    local ram_percent
    ram_percent=$(free | awk '/^Mem:/{printf("%.1f%%", $3/$2 * 100)}')
    
    debug_verbose "RAM - Total: $total_ram, Used: $used_ram ($ram_percent), Available: $available_ram"
    
    local result="Total: ${total_ram} | Used: ${used_ram} (${ram_percent}) | Available: ${available_ram}"
    debug_function_exit "get_memory_info" "$result"
    echo "$result"
}

get_swap_info() {
    debug_function_enter "get_swap_info"
    
    debug_log "Collecting swap usage information..."
    
    local swap_total
    swap_total=$(free -h | awk '/^Swap:/{print $2}')
    local swap_used
    swap_used=$(free -h | awk '/^Swap:/{print $3}')
    local swap_free
    swap_free=$(free -h | awk '/^Swap:/{print $4}')
    
    if [[ "$swap_total" == "0B" ]] || [[ -z "$swap_total" ]]; then
        debug_verbose "No swap configured on this system"
        echo "Not configured"
    else
        local swap_percent
        swap_percent=$(free | awk '/^Swap:/{if($2>0) printf("%.1f%%", $3/$2 * 100); else print "0%"}')
        debug_verbose "Swap - Total: $swap_total, Used: $swap_used ($swap_percent), Free: $swap_free"
        local result="Total: ${swap_total} | Used: ${swap_used} (${swap_percent}) | Free: ${swap_free}"
        debug_function_exit "get_swap_info" "$result"
        echo "$result"
    fi
}

get_disk_summary() {
    debug_function_enter "get_disk_summary"
    
    debug_log "Gathering disk usage summary (excluding temporary filesystems)..."
    
    df -h 2>/dev/null | grep -vE '^(tmpfs|devtmpfs|udev|overlay|shm|run|cgroup|none|Filesystem)' | awk 'NF>=6 {printf "%s [%s] %s/%s (%s) → %s\n", $1, $2, $4, $3, $5, $6}'
}

get_partition_layout() {
    debug_function_enter "get_partition_layout"
    
    debug_log "Identifying system partition layout..."
    
    local partitions=()
    
    # Root partition
    local root_part
    root_part=$(findmnt / -o SOURCE -n 2>/dev/null)
    if [[ -n "$root_part" ]]; then
        partitions+=("${root_part} → /")
        debug_verbose "Root partition: $root_part"
    fi
    
    # Home partition (if separate)
    local home_part
    home_part=$(findmnt /home -o SOURCE -n 2>/dev/null)
    if [[ -n "$home_part" ]] && [[ "$root_part" != "$home_part" ]]; then
        partitions+=("${home_part} → /home")
        debug_verbose "Separate /home partition: $home_part"
    fi
    
    # Boot partition
    local boot_part
    boot_part=$(findmnt /boot -o SOURCE -n 2>/dev/null)
    if [[ -n "$boot_part" ]] && [[ "$root_part" != "$boot_part" ]]; then
        partitions+=("${boot_part} → /boot")
        debug_verbose "Separate /boot partition: $boot_part"
    fi
    
    # EFI partition
    local efi_part
    efi_part=$(findmnt /boot/efi -o SOURCE -n 2>/dev/null)
    if [[ -n "$efi_part" ]]; then
        partitions+=("${efi_part} → /boot/efi")
        debug_verbose "EFI partition: $efi_part"
    fi
    
    debug_info "Found ${#partitions[@]} key partition(s)"
    debug_function_exit "get_partition_layout" "${#partitions[@]} partitions"
    printf '%s\n' "${partitions[@]}"
}

# ============================================================================
# VERSION DETECTION
# ============================================================================

get_component_version() {
    local component="$1"
    
    debug_function_enter "get_component_version" "$component"
    
    local version=""
    
    case "$component" in
        "systemd")
            version=$(systemctl --version 2>/dev/null | head -n1 | awk '{print $2}')
            ;;
        "SysVinit")
            version=$(init --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
            ;;
        "OpenRC")
            version=$(openrc --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
            ;;
        "NetworkManager")
            version=$(NetworkManager --version 2>/dev/null)
            ;;
        "ifupdown/ifupdown2")
            version=$(ifup --version 2>/dev/null)
            ;;
        "systemd-networkd")
            version=$(systemctl --version 2>/dev/null | head -n1 | awk '{print $2}')
            ;;
        "ufw")
            version=$(ufw version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
            ;;
        "firewalld")
            version=$(firewall-cmd --version 2>/dev/null)
            ;;
        "iptables")
            version=$(iptables --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
            ;;
        "chrony"|"chronyd")
            version=$(chronyd --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
            ;;
        "ntpd"|"ntp")
            version=$(ntpd --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
            ;;
        "systemd-timesyncd")
            version=$(systemctl --version 2>/dev/null | head -n1 | awk '{print $2}')
            ;;
        "AppArmor")
            version=$(apparmor_status --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
            ;;
        "SELinux")
            version=$(sestatus 2>/dev/null | grep "version" | awk '{print $3}')
            ;;
        *)
            version=""
            ;;
    esac
    
    if [[ -n "$version" ]] && [[ "$version" != "unknown" ]]; then
        debug_function_exit "get_component_version" "$version"
        echo "$version"
    else
        debug_verbose "Version not found for component: $component"
        debug_function_exit "get_component_version" "none"
        echo ""
    fi
}

# ============================================================================
# HOST DETECTION
# ============================================================================

get_host_info() {
    debug_function_enter "get_host_info"
    
    local host=""
    
    debug_log "Detecting host/hardware information..."
    
    # Method 1: DMI/SMBIOS (most accurate for real hardware)
    if [[ -f /sys/devices/virtual/dmi/id/product_name ]] && [[ -f /sys/devices/virtual/dmi/id/product_version ]]; then
        debug_verbose "Reading DMI/SMBIOS information from /sys"
        
        local product_name
        product_name=$(tr -d '\0' < /sys/devices/virtual/dmi/id/product_name 2>/dev/null)
        local product_version
        product_version=$(tr -d '\0' < /sys/devices/virtual/dmi/id/product_version 2>/dev/null)
        
        # Ignore generic/non-useful values
        if [[ -n "$product_name" ]] && \
           [[ "$product_name" != "System Product Name" ]] && \
           [[ "$product_name" != "To be filled by O.E.M." ]] && \
           [[ "$product_name" != "Default string" ]] && \
           [[ "$product_name" != "Not Applicable" ]] && \
           [[ "$product_name" != "Not Specified" ]]; then
            host="$product_name"
            debug_verbose "Found product name: $product_name"
            
            # Add version if different and not generic
            if [[ -n "$product_version" ]] && \
               [[ "$product_version" != "Not Applicable" ]] && \
               [[ "$product_version" != "Not Specified" ]] && \
               [[ "$product_version" != "Default string" ]] && \
               [[ "$product_version" != "To be filled by O.E.M." ]] && \
               [[ "$product_version" != "$product_name" ]]; then
                host="$host $product_version"
                debug_verbose "Added product version: $product_version"
            fi
        fi
    fi
    
    # Method 2: dmidecode (fallback, often requires root)
    if [[ -z "$host" ]] && command -v dmidecode >/dev/null 2>&1; then
        debug_log "Trying dmidecode as fallback..."
        local dmi_output
        dmi_output=$(trace_exec "Query DMI information" "dmidecode -t system")
        
        if [[ -n "$dmi_output" ]]; then
            local product
            product=$(echo "$dmi_output" | grep "Product Name:" | cut -d: -f2 | sed 's/^[ \t]*//')
            local version
            version=$(echo "$dmi_output" | grep "Version:" | cut -d: -f2 | sed 's/^[ \t]*//')
            
            if [[ -n "$product" ]] && [[ "$product" != "System Product Name" ]]; then
                host="$product"
                [[ -n "$version" ]] && [[ "$version" != "Not Specified" ]] && host="$host $version"
                debug_verbose "DMI product: $host"
            fi
        fi
    fi
    
    # Method 3: Virtualization detection
    if [[ -z "$host" ]]; then
        debug_log "Attempting virtualization detection..."
        
        # systemd-detect-virt
        if command -v systemd-detect-virt >/dev/null 2>&1; then
            local virt_type
            virt_type=$(trace_exec "Detect virtualization" "systemd-detect-virt")
            
            if [[ "$virt_type" != "none" ]] && [[ -n "$virt_type" ]]; then
                debug_info "Virtualization detected: $virt_type"
                
                case "$virt_type" in
                    kvm)
                        host="KVM Virtual Machine"
                        # Look for KVM version
                        if [[ -f /sys/devices/virtual/dmi/id/product_version ]]; then
                            local kvm_ver
                            kvm_ver=$(tr -d '\0' < /sys/devices/virtual/dmi/id/product_version 2>/dev/null)
                            [[ -n "$kvm_ver" ]] && [[ "$kvm_ver" != "Not Specified" ]] && host="$host $kvm_ver"
                        fi
                        ;;
                    qemu) host="QEMU Virtual Machine" ;;
                    vmware) host="VMware Virtual Machine" ;;
                    oracle) host="VirtualBox VM" ;;
                    microsoft) host="Hyper-V Virtual Machine" ;;
                    xen) host="Xen Virtual Machine" ;;
                    lxc) host="LXC Container" ;;
                    docker) host="Docker Container" ;;
                    podman) host="Podman Container" ;;
                    *) host="Virtual Machine ($virt_type)" ;;
                esac
            fi
        fi
        
        # Fallback: check specific files
        if [[ -z "$host" ]]; then
            if grep -qi "hypervisor" /proc/cpuinfo 2>/dev/null; then
                host="Virtual Machine"
                debug_verbose "Hypervisor flag found in /proc/cpuinfo"
            elif [[ -f /.dockerenv ]]; then
                host="Docker Container"
                debug_verbose "Docker environment file detected"
            elif grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
                host="LXC Container"
                debug_verbose "LXC container detected via /proc/1/environ"
            fi
        fi
    fi
    
    # Method 4: Raspberry Pi / ARM boards
    if [[ -z "$host" ]] && [[ -f /proc/device-tree/model ]]; then
        host=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null)
        debug_verbose "ARM device model from device-tree: $host"
    fi
    
    # If still not found, use basic system information
    if [[ -z "$host" ]]; then
        if [[ -f /sys/devices/virtual/dmi/id/board_name ]]; then
            local board
            board=$(tr -d '\0' < /sys/devices/virtual/dmi/id/board_name 2>/dev/null)
            [[ -n "$board" ]] && [[ "$board" != "Default string" ]] && host="$board"
            debug_verbose "Board name: $host"
        fi
    fi
    
    # Last resort
    if [[ -z "$host" ]] || [[ "$host" == "Default string" ]]; then
        host="Unknown"
        debug_log "Unable to determine host information"
    fi
    
    debug_function_exit "get_host_info" "$host"
    echo "$host"
}

# ============================================================================
# ALTERNATIVE COMPONENTS DETECTION
# ============================================================================

detect_network_alternatives() {
    debug_function_enter "detect_network_alternatives"
    
    local alternatives=()
    
    debug_log "Scanning for all installed network managers..."
    
    if command -v nmcli >/dev/null 2>&1; then
        local status="inactive"
        is_service_active NetworkManager && status="active"
        local version
        version=$(get_component_version "NetworkManager")
        alternatives+=("NetworkManager (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "NetworkManager: $status"
    fi
    
    if command -v connmanctl >/dev/null 2>&1; then
        local status="inactive"
        is_service_active connman && status="active"
        alternatives+=("ConnMan (${status})")
        debug_verbose "ConnMan: $status"
    fi
    
    if command -v wicd >/dev/null 2>&1; then
        local status="inactive"
        is_service_active wicd && status="active"
        alternatives+=("Wicd (${status})")
        debug_verbose "Wicd: $status"
    fi
    
    if [[ -f /lib/systemd/systemd-networkd ]] || [[ -f /usr/lib/systemd/systemd-networkd ]]; then
        local status="inactive"
        is_service_active systemd-networkd && status="active"
        local version
        version=$(get_component_version "systemd-networkd")
        alternatives+=("systemd-networkd (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "systemd-networkd: $status"
    fi
    
    if [[ ${#alternatives[@]} -eq 0 ]]; then
        debug_log "No network manager alternatives found"
        echo "None detected"
    else
        debug_info "Found ${#alternatives[@]} network manager(s)"
        debug_function_exit "detect_network_alternatives" "${#alternatives[@]} found"
        printf '%s\n' "${alternatives[@]}"
    fi
}

detect_firewall_alternatives() {
    debug_function_enter "detect_firewall_alternatives"
    
    local alternatives=()
    
    debug_log "Scanning for all installed firewalls..."
    
    if command -v ufw >/dev/null 2>&1; then
        local status
        status=$(ufw status 2>/dev/null | grep -i "status" | awk '{print tolower($2)}')
        [[ -z "$status" ]] && status="inactive"
        local version
        version=$(get_component_version "ufw")
        alternatives+=("ufw (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "ufw: $status"
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        local status="inactive"
        is_service_active firewalld && status="active"
        local version
        version=$(get_component_version "firewalld")
        alternatives+=("firewalld (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "firewalld: $status"
    fi
    
    if command -v iptables >/dev/null 2>&1; then
        local rules
        rules=$(iptables -L -n 2>/dev/null | wc -l)
        local status="default"
        [[ $rules -gt 8 ]] && status="configured"
        local version
        version=$(get_component_version "iptables")
        alternatives+=("iptables (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "iptables: $status ($rules rule lines)"
    fi
    
    if command -v nft >/dev/null 2>&1; then
        local rules
        rules=$(nft list ruleset 2>/dev/null | wc -l)
        local status="default"
        [[ $rules -gt 0 ]] && status="configured"
        alternatives+=("nftables (${status})")
        debug_verbose "nftables: $status ($rules rule lines)"
    fi
    
    if [[ ${#alternatives[@]} -eq 0 ]]; then
        debug_log "No firewall alternatives found"
        echo "None detected"
    else
        debug_info "Found ${#alternatives[@]} firewall(s)"
        debug_function_exit "detect_firewall_alternatives" "${#alternatives[@]} found"
        printf '%s\n' "${alternatives[@]}"
    fi
}

detect_timesync_alternatives() {
    debug_function_enter "detect_timesync_alternatives"
    
    local alternatives=()
    
    debug_log "Scanning for all time synchronization services..."
    
    if command -v chronyd >/dev/null 2>&1; then
        local status="inactive"
        is_service_active chronyd && status="active"
        local version
        version=$(get_component_version "chronyd")
        alternatives+=("chronyd (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "chronyd: $status"
    fi
    
    if command -v ntpd >/dev/null 2>&1; then
        local status="inactive"
        (is_service_active ntpd || is_service_active ntp) && status="active"
        local version
        version=$(get_component_version "ntpd")
        alternatives+=("ntpd (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "ntpd: $status"
    fi
    
    if [[ -f /lib/systemd/systemd-timesyncd ]] || [[ -f /usr/lib/systemd/systemd-timesyncd ]]; then
        local status="inactive"
        is_service_active systemd-timesyncd && status="active"
        local version
        version=$(get_component_version "systemd-timesyncd")
        alternatives+=("systemd-timesyncd (${status})$([ -n "$version" ] && echo " (v. ${version})")")
        debug_verbose "systemd-timesyncd: $status"
    fi
    
    if [[ ${#alternatives[@]} -eq 0 ]]; then
        debug_log "No time sync alternatives found"
        echo "None detected"
    else
        debug_info "Found ${#alternatives[@]} time sync service(s)"
        debug_function_exit "detect_timesync_alternatives" "${#alternatives[@]} found"
        printf '%s\n' "${alternatives[@]}"
    fi
}

# ============================================================================
# CPU & GPU DETECTION
# ============================================================================

get_cpu_info() {
    debug_function_enter "get_cpu_info"
    
    local cpu_model=""
    local cpu_cores=""
    local cpu_threads=""
    
    debug_log "Collecting CPU information..."
    
    # CPU model from /proc/cpuinfo
    cpu_model=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^[ \t]*//')
    
    # If not found, try lscpu
    if [[ -z "$cpu_model" ]] && command -v lscpu >/dev/null 2>&1; then
        cpu_model=$(lscpu | grep "Model name:" | cut -d: -f2 | sed 's/^[ \t]*//')
        debug_verbose "CPU model from lscpu: $cpu_model"
    else
        debug_verbose "CPU model from /proc/cpuinfo: $cpu_model"
    fi
    
    # Clean the name (remove extra spaces, (R), (TM), etc)
    cpu_model=$(echo "$cpu_model" | sed -e 's/(R)//g' -e 's/(TM)//g' -e 's/(tm)//g' -e 's/CPU //g' -e 's/Processor //g' -e 's/  */ /g' | xargs)
    
    # Count physical cores and threads
    cpu_cores=$(grep "^cpu cores" /proc/cpuinfo 2>/dev/null | head -1 | awk '{print $4}')
    cpu_threads=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    
    debug_verbose "CPU cores: $cpu_cores, threads: $cpu_threads"
    
    # If not found, use lscpu
    if [[ -z "$cpu_cores" ]] && command -v lscpu >/dev/null 2>&1; then
        cpu_cores=$(lscpu | grep "Core(s) per socket:" | awk '{print $4}')
        cpu_threads=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
        debug_verbose "Core/thread info from lscpu"
    fi
    
    # Maximum frequency
    local cpu_freq=""
    if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]]; then
        cpu_freq=$(awk "BEGIN {printf \"%.2f\", $(< /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq)/1000000}" 2>/dev/null)
        debug_verbose "CPU frequency from sysfs: ${cpu_freq}GHz"
    elif command -v lscpu >/dev/null 2>&1; then
        cpu_freq=$(lscpu | grep "CPU max MHz:" | awk '{print $4}' | cut -d. -f1)
        [[ -n "$cpu_freq" ]] && cpu_freq=$(awk "BEGIN {printf \"%.2f\", $cpu_freq/1000}")
        debug_verbose "CPU frequency from lscpu: ${cpu_freq}GHz"
    fi
    
    # Build output
    local output="$cpu_model"
    if [[ -n "$cpu_threads" ]]; then
        if [[ -n "$cpu_cores" ]] && [[ "$cpu_cores" != "$cpu_threads" ]]; then
            output="$output ($cpu_threads) @ "
        else
            output="$output ($cpu_threads cores) @ "
        fi
    fi
    
    if [[ -n "$cpu_freq" ]]; then
        output="${output}${cpu_freq}GHz"
    else
        # Remove trailing @ if no frequency
        output="${output% @ }"
    fi
    
    debug_function_exit "get_cpu_info" "$output"
    echo "$output"
}

get_gpu_info() {
    debug_function_enter "get_gpu_info"
    
    local gpus=()
    
    debug_log "Scanning for GPU devices..."
    
    # Method 1: lspci (most reliable) - BETTER FILTERED
    if command -v lspci >/dev/null 2>&1; then
        debug_verbose "Using lspci to detect GPUs..."
        
        local gpus_output
        gpus_output=$(
            lspci |
            grep -iE "VGA|3D controller|Display controller" |
            grep -viE "Sensor Hub|Audio|Ethernet|Network|USB|Serial|SMBus|ISA bridge|PCI bridge|SATA|IDE|Memory controller|Host bridge|Signal processing|Communication controller|System peripheral" |
            sed -e 's/.*: //g' \
                -e 's/Corporation //g' \
                -e 's/\[AMD\/ATI\]/AMD/g' \
                -e 's/(R)//g' \
                -e 's/(TM)//g' \
                -e 's/  */ /g' \
                -e 's/ (rev [0-9a-f]\+)$//' \
                -e 's/Advanced Micro Devices, Inc\. \[AMD\/ATI\]/AMD/g' \
                -e 's/NVIDIA //' \
                -e 's/Intel /Intel /' |
            sort -u
        )
        while IFS= read -r line; do
            [[ -n "$line" ]] && gpus+=("$line")
        done <<< "$gpus_output"

        if [[ ${#gpus[@]} -gt 0 ]]; then
            debug_info "Found ${#gpus[@]} GPU(s) via lspci"
        fi
    fi
    
    # Method 2: nvidia-smi for NVIDIA (if not already found)
    if command -v nvidia-smi >/dev/null 2>&1 && [[ ${#gpus[@]} -eq 0 ]]; then
        debug_verbose "Trying nvidia-smi for NVIDIA GPU detection..."
        local nvidia_gpu
        nvidia_gpu=$(trace_exec "Query NVIDIA GPU" "nvidia-smi --query-gpu=name --format=csv,noheader" | head -1)
        
        if [[ -n "$nvidia_gpu" ]]; then
            gpus+=("$nvidia_gpu")
            debug_info "Found NVIDIA GPU via nvidia-smi: $nvidia_gpu"
        fi
    fi
    
    # Method 3: /sys/class/drm (generic fallback)
    if [[ ${#gpus[@]} -eq 0 ]]; then
        debug_log "Using /sys/class/drm fallback for GPU detection..."
        
        for card in /sys/class/drm/card*/device/vendor; do
            if [[ -f "$card" ]]; then
                local vendor
                vendor=$(<"$card" 2>/dev/null)
                
                debug_verbose "Found DRM card with vendor: $vendor"
                
                case "$vendor" in
                    "0x8086")
                        # Look for specific Intel model
                        if [[ -f "$(dirname "$card")/uevent" ]]; then
                            local pci_id
                            pci_id=$(grep "PCI_ID" "$(dirname "$card")/uevent" | cut -d= -f2)
                            case "$pci_id" in
                                *5916*|*5917*) gpus+=("Intel UHD Graphics 620") ;;
                                *591B*) gpus+=("Intel HD Graphics 630") ;;
                                *9BC5*) gpus+=("Intel UHD Graphics") ;;
                                *) gpus+=("Intel Integrated Graphics") ;;
                            esac
                        else
                            gpus+=("Intel Integrated Graphics")
                        fi
                        ;;
                    "0x10de") gpus+=("NVIDIA Graphics") ;;
                    "0x1002") gpus+=("AMD Graphics") ;;
                esac
            fi
        done
    fi
    
    # If nothing found
    if [[ ${#gpus[@]} -eq 0 ]]; then
        debug_log "Unable to detect any GPU"
        echo "Unable to detect"
    else
        debug_info "Total GPUs detected: ${#gpus[@]}"
        # Return all GPUs separated by |||
        local gpu_str="${gpus[0]}"
        for ((i=1; i<${#gpus[@]}; i++)); do
            gpu_str="${gpu_str}|||${gpus[$i]}"
        done
        debug_function_exit "get_gpu_info" "${#gpus[@]} GPU(s)"
        echo "$gpu_str"
    fi
}

# ============================================================================
# CONTAINER DETAILS
# ============================================================================

get_docker_details() {
    debug_function_enter "get_docker_details"
    
    local runtime_info
    runtime_info=$(detect_real_container_runtime)
    local docker_type
    docker_type=$(echo "$runtime_info" | grep -o 'docker_type:[^|]*' | cut -d: -f2)
    
    # If it's podman-docker, don't show as Docker
    if [[ "$docker_type" == "podman-docker" ]] || [[ -z "$docker_type" ]]; then
        debug_log "Skipping Docker details (podman-docker or not present)"
        debug_function_exit "get_docker_details" "skipped"
        return
    fi
    
    if ! command -v docker >/dev/null 2>&1; then
        debug_log "Docker command not available"
        debug_function_exit "get_docker_details" "not available"
        return
    fi
    
    debug_log "Gathering Docker configuration details..."
    
    local version
    version=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    [[ -n "$version" ]] && echo "version:${version}" && debug_verbose "Docker version: $version"
    
    local docker_root
    docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")
    echo "runRoot:${docker_root}"
    debug_verbose "Docker root: $docker_root"
    
    echo "volumePath:${docker_root}/volumes"
    
    local registries="docker.io (default)"
    if [[ -f /etc/docker/daemon.json ]] && command -v jq >/dev/null 2>&1; then
        local custom_reg
        custom_reg=$(jq -r '."registry-mirrors"[]?' /etc/docker/daemon.json 2>/dev/null)
        [[ -n "$custom_reg" ]] && registries="${registries}, ${custom_reg}"
        debug_verbose "Docker registries: $registries"
    fi
    echo "registries:${registries}"
    
    debug_function_exit "get_docker_details"
}

get_podman_details() {
    debug_function_enter "get_podman_details"
    
    local runtime_info
    runtime_info=$(detect_real_container_runtime)
    local docker_type
    docker_type=$(echo "$runtime_info" | grep -o 'docker_type:[^|]*' | cut -d: -f2)
    
    # Determine which command to use
    local cmd="podman"
    if [[ "$docker_type" == "podman-docker" ]] && command -v docker >/dev/null 2>&1; then
        cmd="docker"
        echo "note:Using podman via docker alias"
        debug_info "Using podman via docker alias"
    elif ! command -v podman >/dev/null 2>&1; then
        debug_log "Podman not available"
        debug_function_exit "get_podman_details" "not available"
        return
    fi
    
    debug_log "Gathering Podman configuration details using command: $cmd"
    
    local version
    version=$($cmd version --format '{{.Version}}' 2>/dev/null)
    [[ -n "$version" ]] && echo "version:${version}" && debug_verbose "Podman version: $version"
    
    if command -v jq >/dev/null 2>&1; then
        local podman_info
        podman_info=$($cmd info --format json 2>/dev/null)
        local run_root
        run_root=$(echo "$podman_info" | jq -r '.store.runRoot // ""' 2>/dev/null)
        local volume_path
        volume_path=$(echo "$podman_info" | jq -r '.store.volumePath // ""' 2>/dev/null)
        
        [[ -n "$run_root" ]] && echo "runRoot:${run_root}" && debug_verbose "Podman runRoot: $run_root"
        [[ -n "$volume_path" ]] && echo "volumePath:${volume_path}" && debug_verbose "Podman volumePath: $volume_path"
    else
        echo "runRoot:/run/containers"
        echo "volumePath:/var/lib/containers/storage/volumes"
        debug_verbose "Using default Podman paths (jq not available)"
    fi
    
    local registries="docker.io, quay.io (default)"
    if [[ -f /etc/containers/registries.conf ]]; then
        local custom_reg
        custom_reg=$(grep -E "^registries.*=.*\[" /etc/containers/registries.conf 2>/dev/null | \
            grep -oP "\[\K[^\]]*" | tr -d "'" | tr ',' ' ' | head -1)
        [[ -n "$custom_reg" ]] && registries="${custom_reg}"
        debug_verbose "Podman registries: $registries"
    fi
    echo "registries:${registries}"
    
    debug_function_exit "get_podman_details"
}

get_lxc_details() {
    debug_function_enter "get_lxc_details"
    
    if ! command -v lxc-ls >/dev/null 2>&1 && ! command -v lxc >/dev/null 2>&1; then
        debug_log "LXC/LXD not available"
        debug_function_exit "get_lxc_details" "not available"
        return
    fi
    
    debug_log "Gathering LXC/LXD configuration details..."
    
    # Check LXC version
    if command -v lxc-info >/dev/null 2>&1; then
        local lxc_version
        lxc_version=$(lxc-info --version 2>/dev/null)
        [[ -n "$lxc_version" ]] && echo "lxc_version:${lxc_version}" && debug_verbose "LXC version: $lxc_version"
    fi
    
    # Check LXD version
    if command -v lxc >/dev/null 2>&1; then
        local lxd_version
        lxd_version=$(lxc --version 2>/dev/null)
        [[ -n "$lxd_version" ]] && echo "lxd_version:${lxd_version}" && debug_verbose "LXD version: $lxd_version"
    fi
    
    # Common paths
    [[ -d /var/lib/lxc ]] && echo "lxc_path:/var/lib/lxc" && debug_verbose "LXC path: /var/lib/lxc"
    [[ -d /var/lib/lxd ]] && echo "lxd_path:/var/lib/lxd" && debug_verbose "LXD path: /var/lib/lxd"
    
    debug_function_exit "get_lxc_details"
}

# ============================================================================
# NETWORK INTERFACES
# ============================================================================

net_info() {
    debug_function_enter "net_info"

    LAN_ARRAY=()
    WLAN_ARRAY=()
    VIRTUAL_ARRAY=()
    local iface_count=0

    debug_log "Gathering network interface information from /sys/class/net"

    # Get all IP addresses in one go
    declare -A ip_addrs
    while read -r line; do
        local iface
        iface=$(echo "$line" | awk '{print $2}')
        local ip
        ip=$(echo "$line" | awk '{print $4}' | cut -d/ -f1)
        ip_addrs["$iface"]="$ip"
    done < <(ip -o -4 addr show 2>/dev/null)

    # Iterate over all network interfaces in /sys/class/net
    for iface_path in /sys/class/net/*; do
        local iface
        iface=$(basename "$iface_path")
        
        [[ "$iface" == "lo" ]] && continue
        ((iface_count++))

        local ip_addr="${ip_addrs[$iface]}"
        local state
        state=$(<"$iface_path/operstate")
        
        local display_ip
        if [[ "$state" == "down" ]]; then
            display_ip="down"
        else
            display_ip="${ip_addr:-no IP}"
        fi

        debug_verbose "Processing interface: $iface, State: $state, IP: $display_ip"

        # Categorize the interface
        if [[ -d "$iface_path/wireless" ]]; then
            WLAN_ARRAY+=("$iface ($display_ip)")
            debug_verbose "  → Classified as WLAN"
        elif [[ ! -d "$iface_path/device" || "$(readlink -f "$iface_path/device")" == *"/virtual/"* ]]; then
            VIRTUAL_ARRAY+=("$iface ($display_ip)")
            debug_verbose "  → Classified as Virtual"
        else
            LAN_ARRAY+=("$iface ($display_ip)")
            debug_verbose "  → Classified as LAN"
        fi
    done

    debug_info "Processed $iface_count network interface(s)"
    debug_function_exit "net_info" "${#LAN_ARRAY[@]} LAN, ${#WLAN_ARRAY[@]} WLAN, ${#VIRTUAL_ARRAY[@]} Virtual"
}
# ============================================================================
# DISPLAY FUNCTIONS - Enhanced with Section Markers
# ============================================================================

print_section_header() {
    local title="$1"
    debug_log "Displaying section: $title"
    echo ""
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${WHITE}$title${RESET}"
}

display_system_info() {
    print_section_header "SYSTEM OVERVIEW"
    print_info "Hostname" "$HOSTNAME"
    print_info "Host/Model" "$HOST_MODEL"
    print_info "Distribution" "$DISTRO"
    print_info "Kernel" "$KERNEL"
    print_info "Architecture" "$ARCH"
    print_info "Uptime" "$UPTIME"
    print_info "Shell" "$SHELL_VERSION"
}

display_hardware_info() {
    print_section_header "HARDWARE"
    print_info "CPU" "$CPU_INFO"
    if [[ ${#GPU_ARRAY[@]} -gt 0 ]]; then
        print_info_multiline "GPU" "${GPU_ARRAY[@]}"
    else
        print_info "GPU" "Unable to detect"
    fi
}

display_mem_info() {
    print_section_header "MEMORY & STORAGE"
    print_info "RAM" "$MEMORY_INFO"
    print_info "Swap" "$SWAP_INFO"
    echo ""
    echo -e "${CYAN}Disk Usage Summary:${RESET}"
    if [[ ${#DISK_SUMMARY[@]} -gt 0 ]]; then
        for disk in "${DISK_SUMMARY[@]}"; do
            echo -e "  ${GREEN}→${RESET} $disk"
        done
    else
        echo -e "  ${YELLOW}Unable to detect${RESET}"
    fi
    echo ""
    echo -e "${CYAN}Key Partitions:${RESET}"
    if [[ ${#PARTITIONS[@]} -gt 0 ]]; then
        for part in "${PARTITIONS[@]}"; do
            echo -e "  ${GREEN}→${RESET} $part"
        done
    else
        echo -e "  ${YELLOW}Unable to detect${RESET}"
    fi
}

display_core_info() {
    print_section_header "CORE SYSTEM COMPONENTS"
    print_info "Init System" "$INIT_DISPLAY"
    print_info "Network Manager" "$NETWORK_DISPLAY"
    print_info "Time Sync" "$TIME_DISPLAY"
    print_info "Firewall" "$FIREWALL_DISPLAY"
    print_info "DNS Resolver" "$DNS_RESOLVER"
    print_info "Cron/Scheduler" "$CRON_SYS"
    print_info "Security Framework" "$SECURITY_DISPLAY"
    print_info "Display Server" "$DISPLAY_SERVER"
    print_info "Bootloader" "$BOOTLOADER"
}

display_net_info() {
    print_section_header "NETWORK INTERFACES"
    if [[ ${#LAN_ARRAY[@]} -gt 0 ]]; then
        print_info_multiline "LAN Interfaces" "${LAN_ARRAY[@]}"
    else
        print_info "LAN Interfaces" "None detected"
    fi
    if [[ ${#WLAN_ARRAY[@]} -gt 0 ]]; then
        print_info_multiline "WLAN Interfaces" "${WLAN_ARRAY[@]}"
    else
        print_info "WLAN Interfaces" "None detected"
    fi
    if [[ ${#VIRTUAL_ARRAY[@]} -gt 0 ]]; then
        print_info_multiline "Virtual Interfaces" "${VIRTUAL_ARRAY[@]}"
    else
        print_info "Virtual Interfaces" "None detected"
    fi
}

display_packages_info() {
    print_section_header "PACKAGE MANAGERS"
    print_info "Primary Package Manager" "$PKG_MGR"
    print_info "All Package Managers" "$PKG_MANAGERS"
}

display_alternatives_info() {
    print_section_header "ALTERNATIVE COMPONENTS (Installed)"
    echo -e "${CYAN}Network Managers:${RESET}"
    if [[ ${#NETWORK_ALTERNATIVES[@]} -gt 0 ]] && [[ "${NETWORK_ALTERNATIVES[0]}" != "None detected" ]]; then
        for alt in "${NETWORK_ALTERNATIVES[@]}"; do
            echo -e "  ${GREEN}→${RESET} $alt"
        done
    else
        echo -e "  ${YELLOW}None detected${RESET}"
    fi
    echo ""
    echo -e "${CYAN}Firewalls:${RESET}"
    if [[ ${#FIREWALL_ALTERNATIVES[@]} -gt 0 ]] && [[ "${FIREWALL_ALTERNATIVES[0]}" != "None detected" ]]; then
        for alt in "${FIREWALL_ALTERNATIVES[@]}"; do
            echo -e "  ${GREEN}→${RESET} $alt"
        done
    else
        echo -e "  ${YELLOW}None detected${RESET}"
    fi
    echo ""
    echo -e "${CYAN}Time Synchronization:${RESET}"
    if [[ ${#TIMESYNC_ALTERNATIVES[@]} -gt 0 ]] && [[ "${TIMESYNC_ALTERNATIVES[0]}" != "None detected" ]]; then
        for alt in "${TIMESYNC_ALTERNATIVES[@]}"; do
            echo -e "  ${GREEN}→${RESET} $alt"
        done
    else
        echo -e "  ${YELLOW}None detected${RESET}"
    fi
}

display_virt_info() {
    print_section_header "VIRTUALIZATION & CONTAINERS"
    print_info "KVM Status" "$KVM_STATUS"
    print_info "Container Runtimes" "$CONTAINER_RUNTIME"
    if command -v docker >/dev/null 2>&1; then
        local runtime_info
        runtime_info=$(detect_real_container_runtime)
        local docker_type
        docker_type=$(echo "$runtime_info" | grep -o 'docker_type:[^|]*' | cut -d: -f2)
        if [[ "$docker_type" == "docker" ]]; then
            echo ""
            echo -e "${CYAN}Docker Containers (Running):${RESET}"
            if [[ ${#DOCKER_ARRAY[@]} -gt 0 ]]; then
                for container in "${DOCKER_ARRAY[@]}"; do
                    echo -e "  ${GREEN}→${RESET} $container"
                done
                if [[ ${#DOCKER_DETAILS[@]} -gt 0 ]]; then
                    echo ""
                    echo -e "${CYAN}Docker Configuration:${RESET}"
                    [[ -n "${DOCKER_DETAILS[version]}" ]] && echo -e "  ${BLUE}Version:${RESET} ${DOCKER_DETAILS[version]}"
                    [[ -n "${DOCKER_DETAILS[runRoot]}" ]] && echo -e "  ${BLUE}Root Dir:${RESET} ${DOCKER_DETAILS[runRoot]}"
                    [[ -n "${DOCKER_DETAILS[volumePath]}" ]] && echo -e "  ${BLUE}Volume Path:${RESET} ${DOCKER_DETAILS[volumePath]}"
                    [[ -n "${DOCKER_DETAILS[registries]}" ]] && echo -e "  ${BLUE}Registries:${RESET} ${DOCKER_DETAILS[registries]}"
                fi
            else
                echo -e "  ${YELLOW}None running${RESET}"
            fi
        fi
    fi
    if command -v podman >/dev/null 2>&1 || (command -v docker >/dev/null 2>&1 && [[ "$(detect_real_container_runtime)" == *"podman-docker"* ]]); then
        echo ""
        echo -e "${CYAN}Podman Containers (Running):${RESET}"
        if [[ ${#PODMAN_ARRAY[@]} -gt 0 ]]; then
            for container in "${PODMAN_ARRAY[@]}"; do
                echo -e "  ${GREEN}→${RESET} $container"
            done
            if [[ ${#PODMAN_DETAILS[@]} -gt 0 ]]; then
                echo ""
                echo -e "${CYAN}Podman Configuration:${RESET}"
                [[ -n "${PODMAN_DETAILS[note]}" ]] && echo -e "  ${MAGENTA}Note:${RESET} ${PODMAN_DETAILS[note]}"
                [[ -n "${PODMAN_DETAILS[version]}" ]] && echo -e "  ${BLUE}Version:${RESET} ${PODMAN_DETAILS[version]}"
                [[ -n "${PODMAN_DETAILS[runRoot]}" ]] && echo -e "  ${BLUE}Run Root:${RESET} ${PODMAN_DETAILS[runRoot]}"
                [[ -n "${PODMAN_DETAILS[volumePath]}" ]] && echo -e "  ${BLUE}Volume Path:${RESET} ${PODMAN_DETAILS[volumePath]}"
                [[ -n "${PODMAN_DETAILS[registries]}" ]] && echo -e "  ${BLUE}Registries:${RESET} ${PODMAN_DETAILS[registries]}"
            fi
        else
            echo -e "  ${YELLOW}None running${RESET}"
        fi
    fi
    if command -v lxc-ls >/dev/null 2>&1 || command -v lxc >/dev/null 2>&1; then
        echo ""
        echo -e "${CYAN}LXC/LXD Containers (Running):${RESET}"
        if [[ ${#LXC_ARRAY[@]} -gt 0 ]]; then
            for container in "${LXC_ARRAY[@]}"; do
                echo -e "  ${GREEN}→${RESET} $container"
            done
            if [[ ${#LXC_DETAILS[@]} -gt 0 ]]; then
                echo ""
                echo -e "${CYAN}LXC/LXD Configuration:${RESET}"
                [[ -n "${LXC_DETAILS[lxc_version]}" ]] && echo -e "  ${BLUE}LXC Version:${RESET} ${LXC_DETAILS[lxc_version]}"
                [[ -n "${LXC_DETAILS[lxd_version]}" ]] && echo -e "  ${BLUE}LXD Version:${RESET} ${LXC_DETAILS[lxd_version]}"
                [[ -n "${LXC_DETAILS[lxc_path]}" ]] && echo -e "  ${BLUE}LXC Path:${RESET} ${LXC_DETAILS[lxc_path]}"
                [[ -n "${LXC_DETAILS[lxd_path]}" ]] && echo -e "  ${BLUE}LXD Path:${RESET} ${LXC_DETAILS[lxd_path]}"
            fi
        else
            echo -e "  ${YELLOW}None running${RESET}"
        fi
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    debug_function_enter "main"
    debug_info "${BOLD}${BRIGHT_CYAN}=== SYSINFO SCRIPT EXECUTION START ===${RESET}"
    debug_info "Script invoked with arguments: $*"

    # Step 1: Parse command-line arguments
    debug_log "Step 1: Parsing command-line arguments..."
    parse_arguments "$@"
    debug_verbose "Arguments parsed. Debug=$DEBUG_MODE, Verbose=$VERBOSE_MODE, Trace=$TRACE_COMMANDS, Colors=$USE_COLORS"

    # Step 2: Initialize color scheme
    debug_log "Step 2: Initializing color scheme..."
    init_colors
    debug_verbose "Color scheme initialized (USE_COLORS=$USE_COLORS)"

    # Step 3: Detect init system and set environment
    debug_log "Step 3: Detecting init system and setting environment..."
    detect_init_and_set_env
    debug_info "Init system detection complete: IS_SYSTEMD=$IS_SYSTEMD"
    
    # Header
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║${RESET}                  ${BOLD}${WHITE}LINUX SYSTEM CONFIGURATION INFO${RESET}                   ${BLUE}║${RESET}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${RESET}"


    # Step 4: Collect and display information for each requested section
    for section in "${SECTIONS_TO_SHOW[@]}"; do
        case "$section" in
            system)
                get_system_info
                display_system_info
                ;;
            hardware)
                get_hardware_info
                display_hardware_info
                ;;
            mem)
                get_mem_info
                display_mem_info
                ;;
            core)
                get_core_info
                display_core_info
                ;;
            net)
                get_net_info
                display_net_info
                ;;
            packages)
                get_packages_info
                display_packages_info
                ;;
            alternatives)
                get_alternatives_info
                display_alternatives_info
                ;;
            virt)
                get_virt_info
                display_virt_info
                ;;
        esac
    done
    
    # ========================================================================
    # FOOTER
    # ========================================================================
    # Calculate total elapsed time
    local end_time
    end_time=$(date +%s)
    local total_elapsed=$((end_time - SCRIPT_START_TIME))
    local execution_time="${GRAY}(ExecutionTime: ${total_elapsed}s)${RESET}"
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║${RESET}                   ${BOLD}${WHITE}END SYSTEM CONFIGURATION INFO ${RESET}                   ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}                  ${BOLD}${WHITE}      ${execution_time}${RESET}                         ${BLUE}║${RESET}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""

    # Execution summary
    end_time=$(date +%s)
    local total_time=$((end_time - SCRIPT_START_TIME))
    
    debug_info "${BOLD}${BRIGHT_CYAN}=== SYSINFO SCRIPT EXECUTION END ===${RESET}"
    debug_info "Total execution time: ${total_time}s"
    debug_info "Total debug steps executed: $DEBUG_STEP"
    
    debug_function_exit "main" "exit_code=0"
    
    return 0
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Trap for cleanup on exit (useful for debugging)
trap 'debug_log "Script terminated with exit code: $?"' EXIT

# Execute main function with all script arguments
main "$@"
exit $?
