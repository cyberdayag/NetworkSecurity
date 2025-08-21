#!/bin/bash


#+-----------------------------------------------------------------------------------------+
#|                                                                                         |
#|                     Bash Script for Penetration Testing                                 |
#|                                                                                         |
#|  ▸ Checks for required utilities and internet connection                                |
#|  ▸ Automatically installs and starts 'nipe' to route traffic through the TOR network    |
#|  ▸ Masks your MAC address and requests a new IP address                                 |
#|  ▸ Gets user input: target network, output directory, and scan mode (Basic/Full)        |
#|  ▸ Basic mode: scans TCP/UDP, detects service versions, and checks weak passwords       |
#|  ▸ Full mode: includes NSE scripts and vulnerability mapping with Searchsploit          |
#|  ▸ Tests weak credentials for SSH, RDP, FTP, and TELNET                                 |
#|  ▸ Logs results, allows searching inside them, and saves everything to a ZIP archive    |
#|  ▸ Metasploitable2 was used as a testbed for development and debugging                  |
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
    figlet "PENETRATION TESTING"         # Display banner
    echo -e "\nOleksandr Shevchuk S21, TMagen773637, Erel Regev\n"

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

        # Download usernames and passwords lists to local directory
        wget --no-check-certificate -O "$data/usernames.lst" "https://drive.google.com/uc?export=download&id=1mPSHpfd-P35FNv4r4nQVxfJmAesVLER_" >/dev/null 2>&1
        wget --no-check-certificate -O "$data/passwords.lst" "https://drive.google.com/uc?export=download&id=1dCdCBwTg15ZeUmTyZ7YyU7oxb3mccGAu" >/dev/null 2>&1

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
    local utilities_for_check="curl ftp hydra nmap perl rdesktop ssh sshpass telnet tor tree xsltproc macchanger fping zip"
    
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
# validates input, and starts either a basic or full scan.
SELECT_SCAN_METOD() {

    cd "$current_dir"

    # Prompt the user to enter an IP address to scan
    read -p $'\e[31m[!]\e[0m\e[34m Enter network address/mask (CIDR), e.g., 192.168.0.0/24: \e[0m' network

    if [[ ! "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        echo -e "\e[91m[!] Wrong format. Example: 192.168.0.0/24\e[0m\n"
        SELECT_SCAN_METOD    
    fi

    while true; do
        # Prompt the user to choose scan mode: Basic or Full
        read -p $'\e[31m[?]\e[0m\e[34m Choose scan mode: [B]asic or [F]ull: \e[0m' scan_mode_raw
        # Normalize scan mode to readable form
        if [[ "$scan_mode_raw" =~ ^[Bb]$ ]]; then
            scan_mode="Basic"
            break
        elif [[ "$scan_mode_raw" =~ ^[Ff]$ ]]; then
            scan_mode="Full"
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: B or F\e[0m"
        fi
    done
    
    # Prompt the user to enter a folder name where scan results will be stored
    read -p $'\e[31m[!]\e[0m\e[34m Enter folder name for scan results: \e[0m' working_dir

    # Show summary and ask for confirmation
    echo -e "\n\e[31m[*]\e[0m\e[32m Please verify the entered data:\e[0m"
    echo ""
    echo -e "    Target network : $network"
    echo -e "    Scan mode      : $scan_mode"
    echo -e "    Output folder  : $working_dir"

    while true; do
        read -p $'\n\e[31m[?]\e[0m\e[34m Is everything correct? (Y/N): \e[0m' validation
        if [[ "$validation" =~ ^[Yy]$ ]]; then
            # Create output directory if it doesn't exist
            mkdir -p "$working_dir" > /dev/null 2>&1

            # Use fping to find live hosts in the target network and save IPs to live_hosts.txt
            fping -a -g "$network" 2>/dev/null | awk '{print $1}' | grep -v $(hostname -I | awk '{print $1}') > "$working_dir/live_hosts.txt"

            # Run the selected scan
            if [[ "$scan_mode" == "Basic" ]]; then
                BASIC_SCAN
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
# Runs a basic scan: TCP, version detection, and basic brute-force.
BASIC_SCAN()
{
    # Print starting message with color formatting
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting BASIC scan...\e[0m"

    # Loop over each live IP address found
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        # Create a separate directory for each IP to store its scan results
        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        # Run nmap scan with service/version detection and OS detection, output XML to the IP directory
        nmap -Pn -sS -sV ${ip} -oX "$host_dir/res_tcp_${ip}.xml" -oN "$host_dir/res_tcp_${ip}.txt" > /dev/null 2>&1 &
        SPINNER $!

        # Convert the XML output to a human-readable HTML report in the same directory
        xsltproc "$host_dir/res_tcp_${ip}.xml" -o "$host_dir/res_tcp_${ip}.html"
    done

    CONFIGURE_WORDLISTS
}



# FULL SCAN
# Performs a complete scan for each host in live_hosts.txt
FULL_SCAN() {

    # Print starting message in colored format
    echo -e "\n\e[31m[!]\e[0m\e[32m Starting FULL scan...\e[0m"

    # Loop over each live IP address found
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        # Inform user which IP is currently being scanned
        echo -e "\e[31m[*]\e[0m\e[32m Scanning: ${ip}\e[0m"

        # Create a separate directory for each IP to store its scan results
        host_dir="$working_dir/${ip}"
        mkdir -p "$host_dir"

        # TCP scan: service/version detection, OS detection
        nmap -Pn -sC -sV -O "${ip}" -oX "$host_dir/res_tcp_${ip}.xml" -oN "$host_dir/res_tcp_${ip}.txt" > /dev/null 2>&1 &
        SPINNER $!
        wait $!

        # UDP scan: top 10 ports, service detection
        nmap -Pn -sU --top-ports 10 -sV "${ip}" -oX "$host_dir/res_udp_${ip}.xml" -oN "$host_dir/res_udp_${ip}.txt" > /dev/null 2>&1 &
        SPINNER $!
        wait $!

        # Convert XML reports into readable HTML
        xsltproc "$host_dir/res_tcp_${ip}.xml" -o "$host_dir/res_tcp_${ip}.html"
        xsltproc "$host_dir/res_udp_${ip}.xml" -o "$host_dir/res_udp_${ip}.html"

        # Pass the current host IP ($i) to the MAPPING function
        MAPPING "${ip}"
    done

    CONFIGURE_WORDLISTS
}


# MAPPING
# Processes scan results, extracts open services, and runs vulnerability scan
MAPPING() {

    # Receive the IP argument passed from FULL_SCAN
    local host="$1"
    local host_dir="$working_dir/$host"

    echo -e "\e[33m[>>] Mapping for: $host\e[0m"

    # Extract all open TCP ports from the scan report
    ports=$(awk '/open/{print $1}' "$host_dir/res_tcp_${host}.txt" \
        | cut -d'/' -f1 | sort -n | tr '\n' ',' | sed 's/,$//')

    # If open ports exist, run nmap vulnerability scripts
    if [ -n "$ports" ]; then
        nmap -p"$ports" --script vuln "$host" -oX "$host_dir/mapping_tcp_${host}.xml" -oN "$host_dir/mapping_tcp_${host}.txt" > /dev/null 2>&1 &
        SPINNER $!
        wait $!

        # Convert XML report to HTML for easier reading
        xsltproc "$host_dir/mapping_tcp_${host}.xml" -o "$host_dir/mapping_tcp_${host}.html" > /dev/null 2>&1

        # Check if at least one CVE or vulnerability is found
        if grep -q "CVE-" "$host_dir/mapping_tcp_${host}.xml"; then
            echo -e "\e[32m[+] Vulnerable services found on $host (see: $host_dir/mapping_tcp_${host}.html)\e[0m"
        else
            echo -e "\e[90m[-] No vulnerabilities detected on $host\e[0m"
            rm -f "$host_dir/mapping_tcp_${host}.xml" "$host_dir/mapping_tcp_${host}.html"
        fi
    else
        # No open ports, skip vulnerability scan
        echo -e "\e[33m[!] No open ports found for $host, skipping vuln scan\e[0m"
    fi
}



# CONFIGURE_WORDLISTS
# Downloads or sets up required wordlists for brute-force operations.
CONFIGURE_WORDLISTS() { 
    while true; do
        # Prompt the user to choose between standard or custom password list
        read -p $'\n\e[31m[?]\e[0m\e[34m Choose password list: [S]tandard or [C]ustom: \e[0m' passwd_lst_raw
        if [[ "$passwd_lst_raw" =~ ^[Ss]$ ]]; then
            passwd_lst="$data/passwords.lst"
            break
        elif [[ "$passwd_lst_raw" =~ ^[Cc]$ ]]; then
            # Ask user to provide full path to their custom password list
            read -p $'\e[31m[!]\e[0m\e[34m Enter the full path to your custom password list: \e[0m' custom_passwd_lst
            echo ""
            passwd_lst="$custom_passwd_lst"
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: S or C\e[0m"
        fi
    done

    # Check that both username and password lists exist; if not, exit with error
    if [[ ! -f "$data/usernames.lst" || ! -f "$passwd_lst" ]]; then
        echo -e "\e[91m[!] Required wordlists not found. Exiting.\e[0m"
        exit 1
    fi

    # Proceed to the brute-force credential scanning function
    WEAK_CREDENTIALS
}



# WEAK_CREDENTIALS
# Attempts to discover weak credentials on open services using Nmap scripts and Hydra.
# SSH, FTP, and Telnet are scanned using Nmap scripts.
# RDP is scanned using Hydra because Nmap lacks RDP brute-force support.
WEAK_CREDENTIALS() {
    # Iterate over each IP address from the list of live hosts
    for ip in $(cat "$working_dir/live_hosts.txt"); do
        host_dir="$working_dir/$ip"
        tcp_file="$host_dir/res_tcp_${ip}.txt"

        echo -e "\e[31m[*]\e[0m\e[32m Searching for weak passwords on $ip...\e[0m"

        # Extract only open services that are relevant for brute force testing
        # Supported protocols: ftp, ssh, telnet, rdp
        grep -i "open" "$tcp_file" | grep -iE "\b(ftp|ssh|telnet|rdp)\b" | awk '{print $3}' | sort -u > "$host_dir/protocol_for_scan.txt"

        # Common script arguments for nmap brute-force scripts
        script_args="userdb=$data/usernames.lst,passdb=$passwd_lst,brute.threads=10"

        # Process each detected protocol individually
        for protocol in $(cat "$host_dir/protocol_for_scan.txt"); do
            echo -e "\e[33m[>>] Trying $protocol on $ip...\e[0m"

            if [[ "$protocol" == "ftp" ]]; then
                # Run FTP brute-force attack using nmap
                nmap -p 21 "$ip" --script ftp-brute --script-args "$script_args" -oN "$host_dir/nmap_ftp_brute_${ip}.txt" > /dev/null 2>&1 &
                SPINNER $!
                wait $!
                
                # Check if valid credentials were found without printing them
                if grep -q "Valid credentials" "$host_dir/nmap_ftp_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Weak FTP credentials found for $ip (see: $host_dir/nmap_ftp_brute_${ip}.txt)\e[0m"
                else
                    echo -e "\e[90m[-] No valid FTP credentials for $ip\e[0m"
                    rm -f "$host_dir/nmap_ftp_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "ssh" ]]; then
                # Run SSH brute-force attack using nmap
                nmap -p 22 "$ip" --script ssh-brute --script-args "$script_args" -oN "$host_dir/nmap_ssh_brute_${ip}.txt" > /dev/null 2>&1 &
                SPINNER $!
                wait $!

                if grep -q "Valid credentials" "$host_dir/nmap_ssh_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Weak SSH credentials found for $ip (see: $host_dir/nmap_ssh_brute_${ip}.txt)\e[0m"
                else
                    echo -e "\e[90m[-] No valid SSH credentials for $ip\e[0m"
                    rm -f "$host_dir/nmap_ssh_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "telnet" ]]; then
                # Run Telnet brute-force attack using nmap
                nmap -p 23 "$ip" --script telnet-brute --script-args "$script_args" -oN "$host_dir/nmap_telnet_brute_${ip}.txt" > /dev/null 2>&1 &
                SPINNER $!
                wait $!

                if grep -q "Valid credentials" "$host_dir/nmap_telnet_brute_${ip}.txt"; then
                    echo -e "\e[32m[+] Weak Telnet credentials found for $ip (see: $host_dir/nmap_telnet_brute_${ip}.txt)\e[0m"
                else
                    echo -e "\e[90m[-] No valid Telnet credentials for $ip\e[0m"
                    rm -f "$host_dir/nmap_telnet_brute_${ip}.txt"
                fi

            elif [[ "$protocol" == "rdp" ]]; then
                # Run RDP brute-force attack using Hydra (nmap does not support RDP brute)
                hydra -L "$data/usernames.lst" -P "$passwd_lst" -t 8 -o "$host_dir/hydra_rdp_${ip}.txt" rdp://$ip >/dev/null 2>&1 &
                SPINNER $!
                wait $!

                if grep -qE "login:|password:|\[SUCCESS\]" "$host_dir/hydra_rdp_${ip}.txt"; then
                    echo -e "\e[32m[+] Weak RDP credentials found for $ip (see: $host_dir/hydra_rdp_${ip}.txt)\e[0m"
                else
                    echo -e "\e[90m[-] No valid RDP credentials for $ip\e[0m"
                    rm -f "$host_dir/hydra_rdp_${ip}.txt"
                fi
            fi
        done
    done
    FINAL_REPORT
}



# FINAL_REPORT
# Displays scan completion, shows the directory structure of results
FINAL_REPORT() {
    echo -e "\n\e[31m[!]\e[0m\e[32m Scan completed.\e[0m"

    # Show working directory tree structure with all collected data
    echo -e "\e[31m[!]\e[0m\e[32m Directory structure and scan results:\e[0m\n"
    tree "$working_dir"

    SEARCH_RESULTS
}


# SEARCH_RESULTS
# Opens an interactive shell inside the scan results folder for post-scan searching and data processing.
# The shell is spawned inside this function, and the user must type 'exit' to return to the main program.
SEARCH_RESULTS() {
    while true; do
        # Ask the user if they want to open a console in the results folder
        read -p $'\n\e[31m[?]\e[0m\e[34m Do you want to check or perform manipulations on the scan results? (Y/N): \e[0m' choice
        
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo -e "\e[32m[!] Opening a shell in '$working_dir'.\e[0m"
            
            # Change directory to the working folder
            cd "$working_dir"
            
            # Start a temporary interactive shell with a custom intro message
            bash --rcfile <(echo "echo -e '\e[33m[!] This shell is opened inside the SEARCH_RESULTS function for search and post-scan result processing.\e[0m';
                                   echo -e '\e[33m[!] When finished, type exit and press Enter to return to the main program.\e[0m'\n")
            
            # Return to the previous directory after shell is closed
            cd - > /dev/null
            break
        elif [[ "$choice" =~ ^[Nn]$ ]]; then
            # Exit the loop if the user chooses No
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: Y or N\e[0m"
        fi
    done
    
    ZIP_RESULTS
}


# ZIP_RESULTS
# Offers the user an option to archive all scan results into a ZIP file named after the working directory.
# Provides a confirmation message when the archive is created.
ZIP_RESULTS() {
    while true; do
        # Ask user if they want to archive results
        read -p $'\n\e[31m[?]\e[0m\e[34m Save all results into a ZIP file? (Y/N): \e[0m' zip_choice
        if [[ "$zip_choice" =~ ^[Yy]$ ]]; then
            # Define ZIP file name based on working directory
            zip_file="${working_dir}.zip"
            # Create ZIP archive recursively, suppress output
            zip -r "$zip_file" "$working_dir" > /dev/null 2>&1
            echo -e "\n\e[31m[+]\e[0m\e[32m Results saved to: $zip_file \e[0m"

            break
        elif [[ "$zip_choice" =~ ^[Nn]$ ]]; then
            # Exit the ZIP loop if user chooses 'n'
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: Y or N\e[0m"
        fi
    done
    exit
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