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