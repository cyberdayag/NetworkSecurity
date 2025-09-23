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
        
        # Define TXT file for this host
        enumeration_result_txt="$host_dir/enumeration_${ip}.txt"

        # Set scan result file for this IP
        scan_result_txt="$host_dir/scan_${ip}.txt"

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


