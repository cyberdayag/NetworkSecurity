

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
        read -r -p $'\e[31m[?]\e[0m\e[34m Choose level for '"$mode_name"': [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_input
        
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
        pandoc "$scan_result_txt" -o "$pdf_file"
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
        pandoc "$scan_result_txt" -o "$pdf_file"
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
        pandoc "$scan_result_txt" -o "$pdf_file"
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

            (
                BASIC_ENUMERATION

                # Convert the *.txt into a PDF
                for txt_file in "$host_dir"/enumeration_*.txt; do
                pdf_file="${txt_file%.txt}.pdf"
                pandoc "$txt_file" -o "$pdf_file"
                done
            ) &
            SPINNER $!
            break

        elif [[ "$user_choice" =~ ^[Ii]$ ]]; then
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting INTERMEDIATE ENUMERATION...\e[0m"

            (
                BASIC_ENUMERATION
                INTERMEDIATE_ENUMERATION

                # Convert the *.txt into a PDF
                for txt_file in "$host_dir"/enumeration_*.txt; do
                    pdf_file="${txt_file%.txt}.pdf"
                    pandoc "$txt_file" -o "$pdf_file"
                done
            ) &
            SPINNER $!
            break

        elif
            [[ "$user_choice" =~ ^[Aa]$ ]]; then

            echo -e "\n\e[31m============================================================"
            echo -e "   ⚠️  ATTENTION: Advanced Enumeration Requirements  ⚠️"
            echo -e "============================================================"
            echo -e " Username AND Password List are REQUIRED."
            echo -e " - If no custom list is provided, rockyou.txt will be used."
            echo -e " - If username is missing, the script will return to menu."
            echo -e "============================================================\e[0m\n"

            # Prompt the user to enter a valid AD username
            read -r -p $'\e[34m[?]\e[0m Enter valid username: ' username

            # Check if the username is empty
            if [[ -z "$username" ]]; then
                 # Inform the user that no username was entered and return to the enumeration mode selection
                echo -e "\e[91m[!] No username entered. Returning to enumeration mode selection...\e[0m"
                ENUMERATION_MODE_SELECTOR
                return
            fi
            

            # Prompt the user to enter the full path to a password list
            read -r -p $'\e[34m[?]\e[0m Enter ful path to passwordlist: ' custom_passwdlist

            # If no custom password list is provided, use the default rockyou.txt
            if [[ -z "$custom_passwdlist" ]]; then
                passwdlist="/usr/share/wordlists/rockyou.txt"
            else
                # Otherwise, use the path provided by the user
                passwdlist="$custom_passwdlist"
            fi
            
            # Inform the user that Advanced Enumeration is starting
            echo -e "\n\e[31m[!]\e[0m\e[32m Starting ADVANCE ENUMERATION...\e[0m"

            (
                BASIC_ENUMERATION
                INTERMEDIATE_ENUMERATION
                ADVANCED_ENUMERATION
            
             # Convert the *.txt into a PDF
            for txt_file in "$host_dir"/enumeration_*.txt; do
                pdf_file="${txt_file%.txt}.pdf"
                pandoc "$txt_file" -o "$pdf_file"
            done
            ) &
            SPINNER $!
            break
        else
            echo -e "\e[91m[!] Wrong choice. Example: B, I or A\e[0m"

        fi
    done

    EXPLOITATION_MODE_SELECTOR
}



# BASIC_ENUMERATION
# Performs basic host enumeration: scans TCP and UDP ports from previous scan results,
# detects Domain Controllers and DHCP servers, logs findings to TXT, and converts logs to PDF.
BASIC_ENUMERATION() {

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
        
        # Define TXT file for this host
        enumeration_result_txt="$host_dir/enumeration_${ip}.txt"

        # Write header
        echo -e "BASIC ENUMERATION RESULT FOR ${ip}\n" >> "$enumeration_result_txt" 2>/dev/null

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
            echo -e "\e[32m$msg\e[0m"
        fi

        
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
    done
}


# INTERMEDIATE_ENUMERATION
# Performs intermediate host enumeration: expands on BASIC_ENUMERATION results for each live host.
# This function appends results to the TXT file already created in BASIC_ENUMERATION.
INTERMEDIATE_ENUMERATION() {

    for ip in $(cat "$working_dir/live_hosts.txt"); do
        echo -e "\e[31m[*]\e[0m\e[32m Enumeration: ${ip}\e[0m"
                
        # Write header
        echo -e "INTERMEDIATE ENUMERATION RESULT FOR ${ip}\n" >> "$enumeration_result_txt" 2>/dev/null

        # Define ports for intermediate scanning
        ports=21,22,139,445,389,636,3389,5985,5986

        # Run Nmap scripts:
        #   - vuln: check common vulnerabilities
        #   - smb-os-discovery: detect SMB server OS
        #   - smb-enum-shares: enumerate SMB shares
        #   - smb-enum-users: enumerate SMB users
        nmap -Pn -sV -p "$ports" --script vuln,smb-os-discovery,smb-enum-shares,smb-enum-users "${ip}" >> "$enumeration_result_txt" 2>/dev/null
    done
}



ADVANCED_ENUMERATION() {



}