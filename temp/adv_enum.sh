# ADVANCED_ENUMERATION
# Performs advanced Active Directory enumeration using provided credentials and password list
# Requires global variables: $username, $passwdlist
ADVANCED_ENUMERATION() {

    # AD username and password list are already set globally
    echo -e "\n\e[31m[!]\e[0m\e[32m Performing Advanced Enumeration with username '$username' and password list '$passwdlist'...\e[0m"

    # 3.3.1 Extract all users
    echo -e "\e[34m[*]\e[0m Enumerating all AD users..."
    crackmapexec smb "$target_ip" -u "$username" -p "$passwdlist" --users

    # 3.3.2 Extract all groups
    echo -e "\e[34m[*]\e[0m Enumerating all AD groups..."
    crackmapexec smb "$target_ip" -u "$username" -p "$passwdlist" --groups

    # 3.3.3 Extract all shares
    echo -e "\e[34m[*]\e[0m Enumerating shared folders..."
    crackmapexec smb "$target_ip" -u "$username" -p "$passwdlist" --shares

    # 3.3.4 Display password policy
    echo -e "\e[34m[*]\e[0m Displaying AD password policy..."
    rpcclient -U "$username%$passwdlist" "$target_ip" -c "getdompwinfo"

    # 3.3.5 Find disabled accounts
    echo -e "\e[34m[*]\e[0m Finding disabled accounts..."
    enum4linux-ng -u "$username" -p "$passwdlist" -a "$target_ip" | grep "Account Disabled"

    # 3.3.6 Find never-expired accounts
    echo -e "\e[34m[*]\e[0m Finding accounts with password never expires..."
    enum4linux-ng -u "$username" -p "$passwdlist" -a "$target_ip" | grep "Password never expires"

    # 3.3.7 Display accounts in Domain Admins group
    echo -e "\e[34m[*]\e[0m Listing members of Domain Admins group..."
    crackmapexec smb "$target_ip" -u "$username" -p "$passwdlist" --groups | grep "Domain Admins"

    echo -e "\n\e[32m[+] Advanced Enumeration completed.\e[0m"
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
