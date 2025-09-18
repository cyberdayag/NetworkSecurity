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



INTERMEDIATE_ENUMERATION() {



}