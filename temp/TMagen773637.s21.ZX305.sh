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
orig_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')

# Get real IP & country before Nipe
real_ip=$(curl -s http://ip-api.com/json | python3 -c "import sys, json; print(json.load(sys.stdin)['query'])")
real_country=$(curl -s http://ip-api.com/json | python3 -c "import sys, json; print(json.load(sys.stdin)['country'])")



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
    printf "\r%-60s\r\n" ""
    echo ""
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

    # Show current working directory
    echo -e "\e[30m\e[107mCurrent working directory: $current_dir\e[0m\n"

    # Display original IP and country
    echo -e "\n\e[31m[*]\e[0m\e[32m Your IP before nipe.pl: \e[0m$real_ip"
    sleep 0.5
    echo -e "\e[31m[*]\e[0m\e[32m Your country before nipe.pl: \e[0m$real_country"
    sleep 0.5

    # Display original MAC address
    echo -e "\e[31m[*]\e[0m\e[32m Original MAC address: \e[0m$orig_mac\n"
    sleep 0.5

    # Prepare world lists directory
    data="$current_dir/world_lists"
    mkdir -p "$data"

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
    local utilities_for_check="curl ftp hydra nmap rdesktop ssh sshpass telnet tor macchanger fping zip enscript"
    
    # Iterate through the list and verify each utility
    for i in $utilities_for_check; do
        if ! command -v "$i" > /dev/null 2>&1; then

            # Utility not found, attempt installation
            echo -e "\e[91m\e[107m[!] '$i' is not installed.\e[0m"
            apt install "$i" -y || { echo -e "\e[91m\e[107m[!] Failed to install '$i'.\e[0m"; exit 1; }
        else
            # Utility is already installed
            echo -e "\e[32m[✔] $i\e[0m"
        fi
        sleep 0.3
    done

    CHECK_NIPE
}


# NIPE CHECKING & INSTALLATION
# This function checks if nipe.pl exists and installs it if missing.
CHECK_NIPE() {
    # Search for nipe.pl in /opt/nipe
    nipe_path=$(find /opt/nipe -type f -name nipe.pl 2>/dev/null)

    if [[ -z "$nipe_path" ]]; then
        # nipe.pl not found, proceed to install
        echo -e "\e[91m\e[107m[!] 'nipe.pl' not found.\e[0m"
        echo -e "\e[31m[*]\e[0m\e[34m Installing nipe...\e[0m"

        # Ensure /opt directory exists
        [[ ! -d /opt ]] && mkdir -p /opt || true
        cd /opt

        # Clone nipe repository
        git clone https://github.com/htrgouvea/nipe.git || { echo -e "\e[91m\e[107m[!] Failed to clone nipe.\e[0m"; exit 1; }
        cd nipe

        # Install required Perl modules via CPAN
        yes | cpan install Try::Tiny Config::Simple JSON || { echo -e "\e[91m\e[107m[!] Failed to install CPAN modules.\e[0m"; exit 1; }

        # Run nipe installation script
        perl nipe.pl install || { echo -e "\e[91m\e[107m[!] Failed to install nipe.\e[0m"; exit 1; }
        echo -e "\e[31m[*]\e[0m\e[32m nipe installed successfully\e[0m"

        # Update path variable after installation
        nipe_path=$(find /opt/nipe -type f -name nipe.pl 2>/dev/null)
    else
        # nipe.pl already exists
        echo -e "\e[32m[✔] nipe\e[0m"
    fi

    # Proceed to change MAC address
    CHANGE_MAC
}


# CHANGE_MAC
# Changes the MAC address of the active network interface and requests a new IP via DHCP.
CHANGE_MAC() {
    # Display message about MAC change
    echo -e "\n\e[31m[*]\e[0m\e[34m Changing MAC on $iface...\e[0m"
    sleep 1

    # Bring the network interface down
    ip link set "$iface" down

    # Randomize the MAC address
    macchanger -r "$iface" > /dev/null 2>&1

    # Bring the network interface back up
    ip link set "$iface" up
    sleep 5

    # Request a new IP address via DHCP
    dhclient -v "$iface" > /dev/null 2>&1
    sleep 15

    # Get and store the new MAC address
    new_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')

    # Start Nipe with the new MAC
    RUN_NIPE
}



# RUN_NIPE
# Starts nipe and verifies if the IP is anonymized.
# It fetches and displays the new IP, country, and MAC address after activation.
RUN_NIPE() {    
    # Inform user about starting nipe
    echo -e "\e[31m[*]\e[0m\e[34m Starting Nipe...\e[0m"

    # Change directory to nipe installation
    cd /opt/nipe

    # Start nipe in background (suppress output)
    perl nipe.pl start > /dev/null 2>&1

    # Loop to check if nipe successfully anonymized the connection
    for i in {1..10}; do
        # Check nipe status
        nipe_status=$(perl nipe.pl status 2>/dev/null | grep -i "status" | awk '{print $3}')
        if [[ "$nipe_status" == "true" ]]; then
            # Anonymity achieved
            echo -e "\e[31m[!]\e[0m\e[32m You are anonymous!\e[0m"
            break
        else
            # Wait and attempt restart if not anonymous
            echo -e "\e[31m[$i]\e[0m\e[34m Waiting for Nipe...\e[0m"
            perl nipe.pl restart > /dev/null 2>&1
        fi
    done
    sleep 10
    # Fetch new public IP and country after nipe activation
    new_ip=$(curl -s http://ip-api.com/json | python3 -c "import sys, json; print(json.load(sys.stdin)['query'])")
    new_country=$(curl -s http://ip-api.com/json | python3 -c "import sys, json; print(json.load(sys.stdin)['country'])")

    # Display new network details
    echo -e "\e[31m[*]\e[0m\e[32m NEW IP: \e[0m$new_ip"
    echo -e "\e[31m[*]\e[0m\e[32m NEW country: \e[0m$new_country"
    echo -e "\e[31m[*]\e[0m\e[32m New MAC address: \e[0m$new_mac\n"

    # Proceed to select scanning method
    SELECT_SCAN_METOD
}



# SCAN SELECTION
# Prompts the user for scan parameters, sets up the environment,
# validates input, and starts either a basic internediate or full scan.
SELECT_SCAN_METOD() {

    cd "$current_dir"

    # Prompt the user to enter an IP address to scan
    read -r -p $'\e[31m[!]\e[0m\e[34m Enter network address/mask (CIDR), e.g., 192.168.0.0/24: \e[0m' network

    if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "\e[91m[!] Wrong format. Example: 192.168.0.0/24\e[0m\n"
        SELECT_SCAN_METOD    
    fi

    local mode_name="scanning"
    local level=""
    while true; do
        # Prompt the user to choose scan mode: Basic or Full
        read -r -p $'\e[31m[?]\e[0m\e[34m Choose level for '"${mode_name}"$'\e[0m: [B]asic, [I]ntermediate, [A]dvanced: ' user_input       
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
            fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v $(hostname -I | awk '{print $1}') > "$working_dir/live_hosts.txt"

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
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting BASIC scan...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/basic_scan_${ip}.txt"

        # Write header with a single newline
        echo -e "BASIC SCANNING RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        # Run TCP scan
        nmap -Pn ${ip} | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!

        # Convert TXT results to PDF
        pdf_file="$host_dir/basic_scan_${ip}.pdf"
        (enscript -B -f Courier10 -p - "$scan_result_txt" | ps2pdf - "$pdf_file") > /dev/null 2>&1
    done

    ENUMERATION_MODE_SELECTOR
}


# INTERMEDIATE_SCAN
# Performs a more thorough TCP scan on all 65535 ports of live hosts.
# Includes version detection and vulnerability scripts. Results saved in TXT->PDF.
INTERMEDIATE_SCAN() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting INTERMEDIATE scan...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/intermediate_scan_${ip}.txt"

        # Write header with a single newline
        echo -e "INTERMEDIATE SCANNING RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -p- ${ip} | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!

        # Convert TXT results to PDF
        pdf_file="$host_dir/intermediate_scan_${ip}.pdf"
        (enscript -B -f Courier10 -p - "$scan_result_txt" | ps2pdf - "$pdf_file") > /dev/null 2>&1
    done

    ENUMERATION_MODE_SELECTOR
}


# FULL_SCAN
# Performs the most comprehensive scan: TCP SYN scan on all ports with OS detection,
# plus UDP scan on top 20 ports. Uses vulnerability scripts and saves results in TXT->PDF.
FULL_SCAN() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting FULL scan...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/full_scan_${ip}.txt"

        # Write header with a single newline
        echo -e "FULL SCANNING RESULT FOR ${ip}\n" >>"$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -p- ${ip} | grep -E 'Nmap scan report|^PORT|/tcp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!

        # UDP scan: top 20 ports + vuln scripts
        nmap -Pn -sU --top-ports 20 ${ip} | grep -E 'Nmap scan report|^PORT|/udp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!

        # Convert TXT results to PDF
        pdf_file="$host_dir/full_scan_${ip}.pdf"
        (enscript -B -f Courier10 -p - "$scan_result_txt" | ps2pdf - "$pdf_file") > /dev/null 2>&1
    done

  ENUMERATION_MODE_SELECTOR
}


# ENUMERATION_MODE_SELECTOR
# Prompts the user to select an enumeration level: Basic, Intermediate, or Advanced.
# Depending on the choice, it calls the corresponding enumeration function (BASIC, INTERMEDIATE, or FULL).
ENUMERATION_MODE_SELECTOR() {

    while true; do
        # Ask the user to choose the scan level with colored prompt
        read -r -p $'\e[31m[?]\e[0m\e[34m Choose level for enumeration: [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_choice

        # Run the corresponding enumeration function based on user choice
        if [[ "$user_choice" =~ ^[Bb]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting BASIC ENUMERATION...\e[0m"
            BASIC_ENUMERATION
            for txt_file in "$host_dir"/enumeration_*.txt; do
                pdf_file="${txt_file%.txt}.pdf"
                (enscript -B -f Courier10 -p - "$txt_file" | ps2pdf - "$pdf_file") > /dev/null 2>&1
            done
            break

        elif [[ "$user_choice" =~ ^[Ii]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting INTERMEDIATE ENUMERATION...\e[0m"
            INTERMEDIATE_ENUMERATION
            # Convert the *.txt into a PDF
            for txt_file in "$host_dir"/enumeration_*.txt; do
                pdf_file="${txt_file%.txt}.pdf"
                (enscript -B -f Courier10 -p - "$txt_file" | ps2pdf - "$pdf_file") > /dev/null 2>&1
            done
            break

        elif
            [[ "$user_choice" =~ ^[Aa]$ ]]; then

            echo -e "\n\e[31m============================================================"
            echo -e "   ⚠️  ATTENTION: Advanced Enumeration Requirements  ⚠️"
            echo -e "============================================================"
            echo -e " Userlist AND Password List are REQUIRED."
            echo -e " - If no custom userlist is provided, default userlist will be used."
            echo -e " - If no custom password list is provided, rockyou.txt will be used."
            echo -e "============================================================\e[0m\n"
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

            # Convert the *.txt into a PDF
            for txt_file in "$host_dir"/enumeration_*.txt; do
                pdf_file="${txt_file%.txt}.pdf"
                (enscript -B -f Courier10 -p - "$txt_file" | ps2pdf - "$pdf_file") > /dev/null 2>&1
            done
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

    local host_dir="$working_dir/$host"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        
        # Define TXT file for this host
        enumeration_result_txt="$host_dir/enumeration_${ip}.txt"
        
        # Ensure TXT file exists; if not, create it with a header
        if [ ! -f "$enumeration_result_txt" ]; then
            echo -e "\n INTERMEDIATE ENUMERATION RESULT FOR ${ip}\n" > "$enumeration_result_txt"
        fi

        # Write header
        echo -e "\n BASIC ENUMERATION RESULT FOR ${ip}\n" >> "$enumeration_result_txt" 2>/dev/null

        # TCP enumeration
        if [ "$(grep -c '/tcp' "$scan_result_txt")" -gt 0 ]; then
            tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
            nmap -Pn -sV -p "$tcp_ports" ${ip} | grep -E '^PORT|/tcp|open' >>  "$enumeration_result_txt" 2>/dev/null
        fi

        # UDP enumeration
        if [ "$(grep -c '/udp' "$scan_result_txt")" -gt 0 ]; then
            udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
            nmap -Pn -sV -p "$udp_ports" ${ip} | grep -E '^PORT|/tcp|open' >>  "$enumeration_result_txt" 2>/dev/null
        fi

        # Domain Controller detection
        if grep -q "ldap.*Active Directory" "$enumeration_result_txt" \
            && grep -q "88/tcp" "$enumeration_result_txt" \
            && grep -q "3268/tcp" "$enumeration_result_txt"; then

            msg="[+] DOMAIN CONTROLLER DETECTED ${ip}"
            echo -e "\n$msg" >> "$enumeration_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"
        fi
    done

        
     # Automatically determine the active network interface
    interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
        
    # DHCP server detection
    dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)

    # Check if a DHCP server was found and log it
    if echo "$dhcp_output" | grep -q "Server Identifier:"; then
        dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
        msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
        echo -e "\n$msg" >> "$enumeration_result_txt" 2>/dev/null
        echo -e "\e[33m$msg\e[0m"
    fi    
}



# INTERMEDIATE_ENUMERATION
# Performs intermediate host enumeration: expands on BASIC_ENUMERATION results for each live host.
# This function appends results to the TXT file already created in BASIC_ENUMERATION.
INTERMEDIATE_ENUMERATION() {
    
    local host_dir="$working_dir/$host"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        
        # Define TXT file for this host
        enumeration_result_txt="$host_dir/enumeration_${ip}.txt"

        # Write header
        echo -e "\n INTERMEDIATE ENUMERATION RESULT FOR ${ip}\n" >> "$enumeration_result_txt" 2>/dev/null

        # TCP enumeration
        if [ "$(grep -c '/tcp' "$scan_result_txt")" -gt 0 ]; then
            tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
            nmap -Pn -sV -p "$tcp_ports" ${ip} | grep -E '^PORT|/tcp|open' >>  "$enumeration_result_txt" 2>/dev/null
        fi

        # UDP enumeration
        if [ "$(grep -c '/udp' "$scan_result_txt")" -gt 0 ]; then
            udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
            nmap -Pn -sV -p "$udp_ports" ${ip} | grep -E '^PORT|/tcp|open' >>  "$enumeration_result_txt" 2>/dev/null
        fi

        # Define ports for intermediate scanning
        # These ports are commonly used for services relevant to enumeration:
        # 21 (FTP), 22 (SSH), 139/445 (SMB), 389/636 (LDAP), 3389 (RDP), 5985/5986 (WinRM)
        ports=21,22,139,445,389,636,3389,5985,5986
        #   - smb-enum-shares: enumerate SMB shares
        #   - smb-enum-users: enumerate SMB users
        # Skip the first three lines of nmap output (header) for cleaner results in the TXT file
        nmap -Pn -sV -p "$ports" --script smb-os-discovery,smb-enum-shares,smb-enum-users,ldap-search,smb-enum-domains,nbstat "${ip}" | awk 'NR > 3'>> "$enumeration_result_txt" 2>/dev/null
      

        # Domain Controller detection
        if grep -q "ldap.*Active Directory" "$enumeration_result_txt" \
            && grep -q "88/tcp" "$enumeration_result_txt" \
            && grep -q "3268/tcp" "$enumeration_result_txt"; then

            msg="[+] DOMAIN CONTROLLER DETECTED ${ip}"
            echo -e "\n$msg" >> "$enumeration_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"
        fi

        
         # Automatically determine the active network interface
        interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
        
        # DHCP server detection
        dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)


    done

            # Check if a DHCP server was found and log it
        if echo "$dhcp_output" | grep -q "Server Identifier:"; then
            dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
            msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
            echo -e "\n$msg" >> "$enumeration_result_txt" 2>/dev/null
            echo -e "\e[33m$msg\e[0m"
        fi
}






# STOP - Stops the Nipe service, restores original IP and MAC address, and cleans up.
STOP() {
    # Stop the Nipe service
    cd /opt/nipe  2>/dev/null
    perl nipe.pl stop 2>/dev/null

    # Reset iptables rules and policies to default
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t nat -X 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null

    # Display the current public IP and country
    echo -e "\n\e[91m[!] Nipe is stopped. You are not anonymous. \e[0m\n"
    sleep 0.5
    echo -e "\e[31m[*]\e[0m\e[32m Your IP: \e[0m$real_ip"
    sleep 0.5
    echo -e "\e[31m[*]\e[0m\e[32m Your country: \e[0m$real_country"
    sleep 0.5

    # Restore original MAC address
    ip link set "$iface" down > /dev/null 2>&1
    macchanger -p "$iface" > /dev/null 2>&1
    ip link set "$iface" up > /dev/null 2>&1

    # Display restored MAC address
    orig_mac=$(ip link show "$iface" | grep ether | awk '{print $2}')
    echo -e "\e[31m[*]\e[0m\e[32m Original MAC restored: \e[0m$orig_mac"
    sleep 0.5

    # Remove temporary data directory
    rm -rf "$data"

    # Record script end time and calculate duration
    local script_end=$(date +%s)
    local duration=$((script_end - script_start))
    echo -e "\e[31m[*]\e[0m\e[32m Script finished. \e[0mDuration: $((duration / 60)) min $((duration % 60)) sec"
    sleep 0.5
}

# AUTO TRAP
# Sets a trap to automatically call the STOP function when the script exits.
trap STOP EXIT

START
