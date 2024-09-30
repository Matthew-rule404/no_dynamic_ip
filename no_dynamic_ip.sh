#!/bin/bash

# =====================================================================================
# Script Name: no_dynamic_ip.sh
# Description: Removes dynamic IP addresses from network interfaces based on static
#              IPs and gateway information defined in Netplan YAML configuration files.
# Usage: sudo ./no_dynamic_ip.sh [-D|--debug [x]] [-S|--silent] [-DRY|--dry-run]
# Options:
#   -D, --debug [x]       Enable debug mode. Use 'x' for line debug mode.
#   -S, --silent          Enable silent mode. No confirmation and no console output.
#   -DRY, --dry-run       Enable dry-run mode. No changes will be made.
# =====================================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Initialize variables for debug, silent, and dry-run modes
debug_mode=false
line_debug_mode=false
silent_mode=false
dry_run_mode=false

# Log file path
LOGFILE="/var/log/no_dynamic_ip.log"

# Function to detect system language
detect_locale() {
    if [[ "$LANG" =~ ^en ]]; then
        LANGUAGE='EN'
    else
        LANGUAGE='JP'
    fi
}

# Function to retrieve localized messages
get_message() {
    local key=$1
    case "$LANGUAGE" in
        'EN')
            case "$key" in
                'usage')
                    echo "Usage: $0 [-D|--debug [x]] [-S|--silent] [-DRY|--dry-run]"
                    ;;
                'debug_on')
                    echo "DEBUG mode is ON"
                    ;;
                'line_debug_on')
                    echo "LINE DEBUG mode is ON"
                    ;;
                'dry_run_on')
                    echo "DRY-RUN mode is ON. No changes will be made."
                    ;;
                'run_as_root')
                    echo "Please run as root."
                    ;;
                'cmd_not_installed')
                    echo "Error: $2 is not installed. Please install $2 to proceed."
                    ;;
                'processing_yaml')
                    echo "Processing YAML file: $2"
                    ;;
                'display_yaml')
                    echo "Displaying contents of $2:"
                    ;;
                'error_read_yaml')
                    echo "Error: Failed to read $2"
                    ;;
                'extracted_static')
                    echo "Extracted Static IPs and Gateways from YAML:"
                    ;;
                'device')
                    echo "Device: $2"
                    ;;
                'static_ipv4')
                    echo -n "  Static IPv4: "
                    ;;
                'static_ipv6')
                    echo -n "  Static IPv6: "
                    ;;
                'gateway4')
                    echo -n "  Gateway4: "
                    ;;
                'gateway6')
                    echo -n "  Gateway6: "
                    ;;
                'none')
                    echo "None"
                    ;;
                'no_static_ips')
                    echo "No valid static IP addresses found in netplan YAML configuration."
                    ;;
                'dynamic_ips_to_delete')
                    echo "The following dynamic IP addresses will be deleted:"
                    ;;
                'ipv4_routes_via')
                    echo "  - IPv4 Routes via $2:"
                    ;;
                'ipv6_routes_via')
                    echo "  - IPv6 Routes via $2:"
                    ;;
                'ipv6_link_local')
                    echo "      - $2 (Using link-local address. Will not be deleted.)"
                    ;;
                'routes_to_be_added')
                    echo "The following routes will be re-added after deletion:"
                    ;;
                'no_routes_to_add')
                    echo "No routes will be re-added after deletion."
                    ;;
                'no_dynamic_ips')
                    echo "No dynamic IP addresses found to delete."
                    ;;
                'confirm_prompt')
                    echo -n "Are you sure you want to delete dynamic IP addresses? (y/N): "
                    ;;
                'operation_cancelled')
                    echo "Operation cancelled by user."
                    ;;
                'deleted_dynamic_ipv4')
                    echo "Deleted dynamic IPv4 address: $2 from $3"
                    ;;
                'deleted_dynamic_ipv6')
                    echo "Deleted dynamic IPv6 address: $2 from $3"
                    ;;
                'dry_run_deleted_dynamic_ipv4')
                    echo "[DRY-RUN] Would delete dynamic IPv4 address: $2 from $3"
                    ;;
                'dry_run_deleted_dynamic_ipv6')
                    echo "[DRY-RUN] Would delete dynamic IPv6 address: $2 from $3"
                    ;;
                'dry_run_no_deletion')
                    echo "[DRY-RUN] No dynamic IP addresses were actually removed for $2."
                    ;;
                'dynamic_removed')
                    echo "Dynamic IP addresses have been removed for $2."
                    ;;
                'default_route_removed')
                    echo "WARNING: Default route '$2' has been removed."
                    ;;
                'readded_default_route_ipv4')
                    echo "Re-added default route: default via $2 dev $3"
                    ;;
                'dry_run_readded_default_route_ipv4')
                    echo "[DRY-RUN] Would re-add default route: default via $2 dev $3"
                    ;;
                'readded_default_route_ipv6')
                    echo "Re-added IPv6 default route: default via $2 dev $3"
                    ;;
                'dry_run_readded_default_route_ipv6')
                    echo "[DRY-RUN] Would re-add IPv6 default route: default via $2 dev $3"
                    ;;
                'route_not_readded_ipv6_link_local')
                    echo "  - Using link-local address, no need to re-add."
                    ;;
                'warning_no_static_gateway_ipv4')
                    echo "WARNING: No static gateway information available for device '$2'. Cannot re-add default route."
                    ;;
                'warning_no_static_ipv4_subnet')
                    echo "WARNING: No static IPv4 address found in the same subnet as '$2'. Cannot re-add default route."
                    ;;
                'warning_no_static_gateway_ipv6')
                    echo "WARNING: No static IPv6 gateway information available for device '$2'. Cannot re-add IPv6 default route."
                    ;;
                'newly_added_routes')
                    echo "--------------------------------------"
                    echo "Newly added routes after deletion:"
                    ;;
                'route_entry')
                    echo "  - $2"
                    ;;
                'debug_off')
                    echo "DEBUG mode is OFF"
                    ;;
                'line_debug_off')
                    echo "LINE DEBUG mode is OFF"
                    ;;
                'managing_interface')
                    echo "Managing IP addresses for interface: $2"
                    ;;
                'current_ipv4_addresses')
                    echo "Current IPv4 addresses on $2:"
                    ;;
                'current_ipv6_addresses')
                    echo "Current IPv6 addresses on $2:"
                    ;;
                'invalid_input')
                    echo "Please answer yes (y) or no (n)."
                    ;;
                *)
                    echo "Unknown message key: $1"
                    ;;
            esac
            ;;
        'JP')
            case "$key" in
                'usage')
                    echo "使用法: $0 [-D|--debug [x]] [-S|--silent] [-DRY|--dry-run]"
                    ;;
                'debug_on')
                    echo "デバッグモードが有効です。"
                    ;;
                'line_debug_on')
                    echo "ラインデバッグモードが有効です。"
                    ;;
                'dry_run_on')
                    echo "DRY-RUNモードが有効です。変更は行われません。"
                    ;;
                'run_as_root')
                    echo "rootとして実行してください。"
                    ;;
                'cmd_not_installed')
                    echo "エラー: $2 がインストールされていません。$2 をインストールしてください。"
                    ;;
                'processing_yaml')
                    echo "YAMLファイルを処理中: $2"
                    ;;
                'display_yaml')
                    echo "$2 の内容を表示:"
                    ;;
                'error_read_yaml')
                    echo "エラー: $2 を読み取れませんでした。"
                    ;;
                'extracted_static')
                    echo "YAMLから抽出された静的IPとゲートウェイ:"
                    ;;
                'device')
                    echo "デバイス: $2"
                    ;;
                'static_ipv4')
                    echo -n "  静的IPv4: "
                    ;;
                'static_ipv6')
                    echo -n "  静的IPv6: "
                    ;;
                'gateway4')
                    echo -n "  Gateway4: "
                    ;;
                'gateway6')
                    echo -n "  Gateway6: "
                    ;;
                'none')
                    echo "なし"
                    ;;
                'no_static_ips')
                    echo "netplan YAML設定ファイルに有効な静的IPアドレスが見つかりませんでした。"
                    ;;
                'dynamic_ips_to_delete')
                    echo "以下の動的IPアドレスが削除されます:"
                    ;;
                'ipv4_routes_via')
                    echo "  - $2 経由のIPv4ルート:"
                    ;;
                'ipv6_routes_via')
                    echo "  - $2 経由のIPv6ルート:"
                    ;;
                'ipv6_link_local')
                    echo "      - $2 (リンクローカルアドレスを使用しています。削除されません。)"
                    ;;
                'routes_to_be_added')
                    echo "削除後に再追加されるルート:"
                    ;;
                'no_routes_to_add')
                    echo "削除後に再追加されるルートはありません。"
                    ;;
                'no_dynamic_ips')
                    echo "削除対象の動的IPアドレスが見つかりませんでした。"
                    ;;
                'confirm_prompt')
                    echo -n "動的IPアドレスを削除してもよろしいですか？ (y/N): "
                    ;;
                'operation_cancelled')
                    echo "ユーザーによって操作がキャンセルされました。"
                    ;;
                'deleted_dynamic_ipv4')
                    echo "動的IPv4アドレス: $2 を $3 から削除しました。"
                    ;;
                'deleted_dynamic_ipv6')
                    echo "動的IPv6アドレス: $2 を $3 から削除しました。"
                    ;;
                'dry_run_deleted_dynamic_ipv4')
                    echo "[DRY-RUN] 動的IPv4アドレス: $2 を $3 から削除します。"
                    ;;
                'dry_run_deleted_dynamic_ipv6')
                    echo "[DRY-RUN] 動的IPv6アドレス: $2 を $3 から削除します。"
                    ;;
                'dry_run_no_deletion')
                    echo "[DRY-RUN] $2 の動的IPアドレスは実際には削除されませんでした。"
                    ;;
                'dynamic_removed')
                    echo "動的IPアドレスが $2 から削除されました。"
                    ;;
                'default_route_removed')
                    echo "警告: デフォルトルート '$2' が削除されました。"
                    ;;
                'readded_default_route_ipv4')
                    echo "デフォルトルートを再追加しました: default via $2 dev $3"
                    ;;
                'dry_run_readded_default_route_ipv4')
                    echo "[DRY-RUN] デフォルトルートを再追加します: default via $2 dev $3"
                    ;;
                'readded_default_route_ipv6')
                    echo "IPv6デフォルトルートを再追加しました: default via $2 dev $3"
                    ;;
                'dry_run_readded_default_route_ipv6')
                    echo "[DRY-RUN] IPv6デフォルトルートを再追加します: default via $2 dev $3"
                    ;;
                'route_not_readded_ipv6_link_local')
                    echo "  - リンクローカルアドレスを使用しているため、再追加は不要です。"
                    ;;
                'warning_no_static_gateway_ipv4')
                    echo "警告: デバイス '$2' に対する静的ゲートウェイ情報がありません。デフォルトルートを再追加できません。"
                    ;;
                'warning_no_static_ipv4_subnet')
                    echo "警告: '$2' と同じサブネット内に静的IPv4アドレスが見つかりません。デフォルトルートを再追加できません。"
                    ;;
                'warning_no_static_gateway_ipv6')
                    echo "警告: デバイス '$2' に対する静的IPv6ゲートウェイ情報がありません。IPv6デフォルトルートを再追加できません。"
                    ;;
                'newly_added_routes')
                    echo "--------------------------------------"
                    echo "削除後に再追加されたルート:"
                    ;;
                'route_entry')
                    echo "  - $2"
                    ;;
                'debug_off')
                    echo "デバッグモードが無効です。"
                    ;;
                'line_debug_off')
                    echo "ラインデバッグモードが無効です。"
                    ;;
                'managing_interface')
                    echo "インターフェース $2 のIPアドレスを管理しています。"
                    ;;
                'current_ipv4_addresses')
                    echo "インターフェース $2 の現在のIPv4アドレス:"
                    ;;
                'current_ipv6_addresses')
                    echo "インターフェース $2 の現在のIPv6アドレス:"
                    ;;
                'invalid_input')
                    echo "はい (y) または いいえ (n) で答えてください。"
                    ;;
                *)
                    echo "不明なメッセージキー: $1"
                    ;;
            esac
            ;;
        *)
            echo "Unsupported language. Defaulting to English."
            case "$key" in
                'usage')
                    echo "Usage: $0 [-D|--debug [x]] [-S|--silent] [-DRY|--dry-run]"
                    ;;
                # Add default English messages if necessary
                *)
                    echo "Unknown message key: $1"
                    ;;
            esac
            ;;
    esac
}

# Function to display usage
usage() {
    echo "$(get_message 'usage')"
    exit 1
}

# Function to log messages to console and log file
log() {
    if [[ $silent_mode == true ]]; then
        echo "$*" >> "$LOGFILE"
    else
        echo "$*" | tee -a "$LOGFILE"
    fi
}

# Function to calculate network address from IP and CIDR using ipcalc
get_network() {
    local ip_cidr=$1
    local network
    network=$(ipcalc -n "$ip_cidr" | awk -F= '/NETWORK/ {print $2}')
    echo "$network"
}

# Function to find a static IPv4 in the same subnet as the dynamic IP
find_static_ipv4_in_same_subnet() {
    local dynamic_ip_cidr=$1
    local dynamic_network
    dynamic_network=$(get_network "$dynamic_ip_cidr")
    for dev in "${DEVICE_NAMES[@]}"; do
        for static_ip in ${STATIC_IPV4_YAML[$dev]}; do
            local static_network
            static_network=$(get_network "$static_ip")
            if [[ "$dynamic_network" == "$static_network" ]]; then
                echo "$dev"
                return 0
            fi
        done
    done
    return 1
}

# Parse arguments using a while loop
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -D|--debug)
            debug_mode=true
            # Check if the next argument exists and is 'x'
            if [[ -n "$2" && "$2" != -* ]]; then
                if [[ "$2" == "x" ]]; then
                    line_debug_mode=true
                    shift  # Shift past 'x'
                else
                    echo "$(get_message 'cmd_not_installed' "$2")"
                    usage
                fi
            fi
            shift  # Shift past '-D' or '--debug'
            ;;
        -S|--silent)
            silent_mode=true
            shift
            ;;
        -DRY|--dry-run)
            dry_run_mode=true
            shift
            ;;
        *)
            echo "$(get_message 'cmd_not_installed' "$1")"
            usage
            ;;
    esac
done

# Detect system locale
detect_locale

# Enable debug mode if specified
if [[ $debug_mode == true ]]; then
    if [[ $line_debug_mode == true ]]; then
        # Set custom PS4 to display detailed debug information
        export PS4='+ ${BASH_SOURCE}:${LINENO}:${FUNCNAME[0]}: '
        log "$(get_message 'line_debug_on')"
    else
        # Set PS4 for standard debug mode
        export PS4='+ '
        log "$(get_message 'debug_on')"
    fi
    set -x
fi

# Inform about dry-run mode
if [[ $dry_run_mode == true ]]; then
    log "$(get_message 'dry_run_on')"
fi

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
    log "$(get_message 'run_as_root')"
    exit 1
fi

# Check if required commands are installed
for cmd in yq ipcalc ip; do
    if ! command -v $cmd &> /dev/null; then
        log "$(get_message 'cmd_not_installed' "$cmd")"
        exit 1
    fi
done

# Function to parse netplan configuration and extract static IP addresses and gateways using yq
get_static_config() {
    local netplan_file=$1
    local device
    local static_ipv4s
    local static_ipv6s
    local gateway4
    local gateway6

    # Display the contents of the YAML file before processing
    log "$(get_message 'display_yaml' "$netplan_file")"
    if ! cat "$netplan_file" | log; then
        log "$(get_message 'error_read_yaml' "$netplan_file")"
        exit 1
    fi
    log "--------------------------------------"

    # Extract the list of ethernet devices
    device_names=$(yq e '.network.ethernets | keys | .[]' "$netplan_file")

    # Iterate over each device to extract IP addresses and gateways
    for device in $device_names; do
        # Extract IPv4 addresses (matches CIDR notation, e.g., 192.168.1.100/24)
        static_ipv4s=$(yq e ".network.ethernets.$device.addresses[] | select(test(\"^[0-9]{1,3}(\\.[0-9]{1,3}){3}/([1-9]|[12][0-9]|3[0-2])\$\"))" "$netplan_file")
        # Extract IPv6 addresses (matches CIDR notation, e.g., 2400:4051:3ec1:2700::1/64)
        static_ipv6s=$(yq e ".network.ethernets.$device.addresses[] | select(test(\"^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){1,7}/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])\$\"))" "$netplan_file")
        # Extract gateway4, replace 'empty' with '""' to avoid yq error
        gateway4=$(yq e ".network.ethernets.$device.gateway4 // \"\"" "$netplan_file")
        # Extract gateway6, replace 'empty' with '""' to avoid yq error
        gateway6=$(yq e ".network.ethernets.$device.gateway6 // \"\"" "$netplan_file")
        
        # Add device and its static IPs and gateways to arrays
        if [[ -n "$device" ]]; then
            DEVICE_NAMES+=("$device")
            if [[ -n "$static_ipv4s" ]]; then
                STATIC_IPV4_YAML["$device"]+="$static_ipv4s "
            fi
            if [[ -n "$static_ipv6s" ]]; then
                STATIC_IPV6_YAML["$device"]+="$static_ipv6s "
            fi
            if [[ -n "$gateway4" && "$gateway4" != "" ]]; then
                GATEWAY4_YAML["$device"]="$gateway4"
            fi
            if [[ -n "$gateway6" && "$gateway6" != "" ]]; then
                GATEWAY6_YAML["$device"]="$gateway6"
            fi
        fi
    done
}

# Directory containing netplan configuration files
netplan_dir="/etc/netplan"

# Declare associative arrays to hold static IPs and gateways
declare -A STATIC_IPV4_YAML
declare -A STATIC_IPV6_YAML
declare -A GATEWAY4_YAML
declare -A GATEWAY6_YAML

# Declare an array to hold device names
declare -a DEVICE_NAMES

# Iterate over YAML files in the netplan directory
for filename in "$netplan_dir"/*.yaml; do
    if [[ -f $filename ]]; then
        log "$(get_message 'processing_yaml' "$filename")"
        get_static_config "$filename"
    fi
done

# If no static IPs are found in YAML, print a message and exit the script
if [[ ${#DEVICE_NAMES[@]} -eq 0 ]]; then
    log "$(get_message 'no_static_ips')"
    exit 1
fi

# Display extracted static IPs and gateways
if [[ ${#DEVICE_NAMES[@]} -gt 0 ]]; then
    log "$(get_message 'extracted_static')"
    for device in "${DEVICE_NAMES[@]}"; do
        log "$(get_message 'device' "$device")"
        log "$(get_message 'static_ipv4')${STATIC_IPV4_YAML[$device]:-$(get_message 'none')}"
        log "$(get_message 'static_ipv6')${STATIC_IPV6_YAML[$device]:-$(get_message 'none')}"
        log "$(get_message 'gateway4')${GATEWAY4_YAML[$device]:-$(get_message 'none')}"
        log "$(get_message 'gateway6')${GATEWAY6_YAML[$device]:-$(get_message 'none')}"
    done
fi

# Save current default routes
mapfile -t SAVED_DEFAULT_ROUTES < <(ip route show default)
mapfile -t SAVED_DEFAULT_ROUTES_V6 < <(ip -6 route show default)

# Function to check if an element exists in an array
element_in_array() {
    local element
    local array=("${!2}")
    for element in "${array[@]}"; do
        if [[ "$element" == "$1" ]]; then
            return 0
        fi
    done
    return 1
}

# Collect dynamic IPs to delete
declare -a DYNAMIC_IPV4_TO_DELETE=()
declare -a DYNAMIC_IPV6_TO_DELETE=()

for device in "${DEVICE_NAMES[@]}"; do
    INTERFACE=$device
    # Get current IPv4 addresses
    CURRENT_IPV4=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+')
    # Get current IPv6 addresses (exclude link-local addresses by specifying scope global)
    CURRENT_IPV6=$(ip -6 addr show "$INTERFACE" scope global | grep -oP '(?<=inet6\s)[\da-f:]+/\d+')

    # Identify dynamic IPv4 addresses to delete
    for addr in $CURRENT_IPV4; do
        if ! [[ " ${STATIC_IPV4_YAML[$INTERFACE]} " =~ " $addr " ]]; then
            DYNAMIC_IPV4_TO_DELETE+=("$addr")
        fi
    done

    # Identify dynamic IPv6 addresses to delete
    for addr in $CURRENT_IPV6; do
        if ! [[ " ${STATIC_IPV6_YAML[$INTERFACE]} " =~ " $addr " ]]; then
            DYNAMIC_IPV6_TO_DELETE+=("$addr")
        fi
    done
done

# Combine dynamic IPs to delete
declare -a ALL_DYNAMIC_IPS_TO_DELETE=("${DYNAMIC_IPV4_TO_DELETE[@]}" "${DYNAMIC_IPV6_TO_DELETE[@]}")

# Function to retrieve routes related to a specific IP
get_routes_via_ip() {
    local ip=$1
    local ip_version=$2
    if [[ "$ip_version" == "4" ]]; then
        ip route show | grep -E "via $ip|src $ip"
    elif [[ "$ip_version" == "6" ]]; then
        ip -6 route show | grep -E "via $ip|src $ip"
    fi
}

# Display dynamic IPs to delete and associated routes before confirmation
if [[ ${#ALL_DYNAMIC_IPS_TO_DELETE[@]} -gt 0 ]]; then
    log "$(get_message 'dynamic_ips_to_delete')"
    for ip in "${ALL_DYNAMIC_IPS_TO_DELETE[@]}"; do
        log "  - $ip"
    done

    # Display the routes that will be affected by deletion
    log "--------------------------------------"
    log "Routes associated with dynamic IP addresses:"
    for ip in "${ALL_DYNAMIC_IPS_TO_DELETE[@]}"; do
        # Determine if IPv4 or IPv6
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
            ip_version="4"
        else
            ip_version="6"
        fi

        # Find all routes via this IP
        matched_routes=$(get_routes_via_ip "$ip" "$ip_version" || true)
        if [[ -n "$matched_routes" ]]; then
            if [[ "$ip_version" == "4" ]]; then
                log "$(get_message 'ipv4_routes_via' "$ip")"
                while IFS= read -r route; do
                    log "      - $route"
                done <<< "$matched_routes"
            else
                # For IPv6, check if routes are global or link-local
                global_routes=$(echo "$matched_routes" | grep -v "fe80::")
                link_local_routes=$(echo "$matched_routes" | grep "fe80::")

                if [[ -n "$global_routes" ]]; then
                    log "$(get_message 'ipv6_routes_via' "$ip")"
                    while IFS= read -r route; do
                        log "      - $route"
                    done <<< "$global_routes"
                fi

                if [[ -n "$link_local_routes" ]]; then
                    while IFS= read -r route; do
                        log "$(get_message 'ipv6_link_local' "$route")"
                    done <<< "$link_local_routes"
                fi
            fi
        fi
    done
    log "--------------------------------------"

    # Prepare routes to be re-added
    declare -A ROUTES_TO_BE_ADDED_V4=()
    declare -A ROUTES_TO_BE_ADDED_V6=()

    for saved_route in "${SAVED_DEFAULT_ROUTES[@]}"; do
        # Extract 'via' and 'dev' from the saved route
        via=$(echo "$saved_route" | awk '/via/ {print $3}')
        dev=$(echo "$saved_route" | awk '/dev/ {print $5}')
        ROUTES_TO_BE_ADDED_V4["$via"]="$dev"
    done

    for saved_route in "${SAVED_DEFAULT_ROUTES_V6[@]}"; do
        # Extract 'via' and 'dev' from the saved route
        via=$(echo "$saved_route" | awk '/via/ {print $3}')
        dev=$(echo "$saved_route" | awk '/dev/ {print $5}')
        ROUTES_TO_BE_ADDED_V6["$via"]="$dev"
    done

    # Display the routes that will be re-added
    if [[ ${#ROUTES_TO_BE_ADDED_V4[@]} -gt 0 || ${#ROUTES_TO_BE_ADDED_V6[@]} -gt 0 ]]; then
        log "$(get_message 'routes_to_be_added')"
        for via in "${!ROUTES_TO_BE_ADDED_V4[@]}"; do
            dev=${ROUTES_TO_BE_ADDED_V4[$via]}
            log "  - default via $via dev $dev"
        done
        for via in "${!ROUTES_TO_BE_ADDED_V6[@]}"; do
            dev=${ROUTES_TO_BE_ADDED_V6[$via]}
            if [[ "$via" =~ ^fe80:: ]]; then
                log "$(get_message 'ipv6_link_local' "default via $via dev $dev")"
            else
                log "  - default via $via dev $dev"
            fi
        done
    else
        log "$(get_message 'no_routes_to_add')"
    fi
else
    log "$(get_message 'no_dynamic_ips')"
fi

# Function to prompt user for confirmation
confirm_action() {
    while true; do
        echo -n "$(get_message 'confirm_prompt')"
        read -r confirm
        case "$confirm" in
            [Yy]*) return 0 ;;
            [Nn]*|'') return 1 ;;
            *) echo "$(get_message 'invalid_input')" ;;
        esac
    done
}

# Prompt user for confirmation if not in dry-run or silent mode
if [[ $dry_run_mode == false && $silent_mode == false ]]; then
    if [[ ${#ALL_DYNAMIC_IPS_TO_DELETE[@]} -gt 0 ]]; then
        if ! confirm_action; then
            log "$(get_message 'operation_cancelled')"
            # Disable debug mode if it was enabled
            if [[ $debug_mode == true ]]; then
                set +x
                if [[ $line_debug_mode == true ]]; then
                    log "$(get_message 'line_debug_off')"
                else
                    log "$(get_message 'debug_off')"
                fi
            fi
            exit 0
        fi
    fi
fi

# Iterate over each device to manage IP addresses
for device in "${DEVICE_NAMES[@]}"; do
    INTERFACE=$device
    log "--------------------------------------"
    log "$(get_message 'managing_interface' "$INTERFACE")"

    # Get current IPv4 addresses
    CURRENT_IPV4=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+')
    # Get current IPv6 addresses (exclude link-local addresses by specifying scope global)
    CURRENT_IPV6=$(ip -6 addr show "$INTERFACE" scope global | grep -oP '(?<=inet6\s)[\da-f:]+/\d+')

    log "$(get_message 'current_ipv4_addresses') $CURRENT_IPV4"
    log "$(get_message 'current_ipv6_addresses') $CURRENT_IPV6"

    # Delete dynamic IPv4 addresses
    for addr in $CURRENT_IPV4; do
        # Check if the current address is not in the static IPv4 list
        if ! [[ " ${STATIC_IPV4_YAML[$INTERFACE]} " =~ " $addr " ]]; then
            if [[ $dry_run_mode == false ]]; then
                ip addr del "$addr" dev "$INTERFACE"
                log "$(get_message 'deleted_dynamic_ipv4' "$addr" "$INTERFACE")"
            else
                log "$(get_message 'dry_run_deleted_dynamic_ipv4' "$addr" "$INTERFACE")"
            fi
        fi
    done

    # Delete dynamic IPv6 addresses
    for addr in $CURRENT_IPV6; do
        # Check if the current address is not in the static IPv6 list
        if ! [[ " ${STATIC_IPV6_YAML[$INTERFACE]} " =~ " $addr " ]]; then
            if [[ $dry_run_mode == false ]]; then
                ip -6 addr del "$addr" dev "$INTERFACE"
                log "$(get_message 'deleted_dynamic_ipv6' "$addr" "$INTERFACE")"
            else
                log "$(get_message 'dry_run_deleted_dynamic_ipv6' "$addr" "$INTERFACE")"
            fi
        fi
    done

    if [[ $dry_run_mode == true ]]; then
        log "$(get_message 'dry_run_no_deletion' "$INTERFACE")"
    else
        log "$(get_message 'dynamic_removed' "$INTERFACE")"
    fi
done

# Save current default routes after deletion
mapfile -t CURRENT_DEFAULT_ROUTES < <(ip route show default)
mapfile -t CURRENT_DEFAULT_ROUTES_V6 < <(ip -6 route show default)

# Prepare arrays to store routes to be re-added
declare -a ROUTES_TO_BE_ADDED=()

# Compare saved default routes with current default routes and re-add if necessary
for saved_route in "${SAVED_DEFAULT_ROUTES[@]}"; do
    if ! element_in_array "$saved_route" CURRENT_DEFAULT_ROUTES[@]; then
        log "$(get_message 'default_route_removed' "$saved_route")"

        # Extract 'via' and 'dev' from the saved route
        via=$(echo "$saved_route" | awk '/via/ {print $3}')
        dev=$(echo "$saved_route" | awk '/dev/ {print $5}')

        if [[ -z "$via" || -z "$dev" ]]; then
            log "Error: Could not parse 'via' or 'dev' from saved route '$saved_route'. Skipping re-addition."
            continue
        fi

        # Attempt to re-add the IPv4 default route
        if [[ $dry_run_mode == false ]]; then
            ip route add default via "$via" dev "$dev"
            log "$(get_message 'readded_default_route_ipv4' "$via" "$dev")"
            ROUTES_TO_BE_ADDED+=("default via $via dev $dev")
        else
            log "$(get_message 'dry_run_readded_default_route_ipv4' "$via" "$dev")"
            ROUTES_TO_BE_ADDED+=("default via $via dev $dev")
        fi
    fi
done

for saved_route in "${SAVED_DEFAULT_ROUTES_V6[@]}"; do
    if ! element_in_array "$saved_route" CURRENT_DEFAULT_ROUTES_V6[@]; then
        log "$(get_message 'default_route_removed' "$saved_route")"

        # Extract 'via' and 'dev' from the saved route
        via=$(echo "$saved_route" | awk '/via/ {print $3}')
        dev=$(echo "$saved_route" | awk '/dev/ {print $5}')

        if [[ -z "$via" || -z "$dev" ]]; then
            log "Error: Could not parse 'via' or 'dev' from saved route '$saved_route'. Skipping re-addition."
            continue
        fi

        # Check if the 'via' IP is a link-local address
        if [[ "$via" =~ ^fe80:: ]]; then
            log "$(get_message 'route_not_readded_ipv6_link_local')"
            continue
        fi

        # Attempt to re-add the IPv6 default route
        if [[ $dry_run_mode == false ]]; then
            ip -6 route add default via "$via" dev "$dev"
            log "$(get_message 'readded_default_route_ipv6' "$via" "$dev")"
            ROUTES_TO_BE_ADDED+=("default via $via dev $dev")
        else
            log "$(get_message 'dry_run_readded_default_route_ipv6' "$via" "$dev")"
            ROUTES_TO_BE_ADDED+=("default via $via dev $dev")
        fi
    fi
done

# Display newly added routes after deletion
if [[ ${#ROUTES_TO_BE_ADDED[@]} -gt 0 ]]; then
    log "$(get_message 'newly_added_routes')"
    for route in "${ROUTES_TO_BE_ADDED[@]}"; do
        log "$(get_message 'route_entry' "$route")"
    done
    log "--------------------------------------"
fi

# Disable debug mode if it was enabled
if [[ $debug_mode == true ]]; then
    set +x
    if [[ $line_debug_mode == true ]]; then
        log "$(get_message 'line_debug_off')"
    else
        log "$(get_message 'debug_off')"
    fi
fi
