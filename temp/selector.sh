#!/bin/bash

# --- твоя функция выбора уровня ---
choose_level() {
    local mode_name="$1"
    local level=""
    
    while true; do
        read -p $'\e[31m[?]\e[0m\e[34m Choose level for '"$mode_name"': [B]asic, [I]ntermediate, [A]dvanced: \e[0m' user_input
        
        case "${user_input^^}" in
            B) level="Basic_$mode_name"; break;;
            I) level="Intermediate_$mode_name"; break;;
            A) level="Advanced_$mode_name"; break;;
            *) echo -e "\e[91m[!] Wrong choice. Use B, I, or A\e[0m";;
        esac
    done

    echo "$level"
}


# --- функции режимов ---
do_scanning() {
    local level="$1"
    [[ "$level" == *Basic* || "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Basic scanning tasks"
    [[ "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Intermediate scanning tasks"
    [[ "$level" == *Advanced* ]] && echo "Run Advanced scanning tasks"
}

do_enumeration() {
    local level="$1"
    [[ "$level" == *Basic* || "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Basic enumeration tasks"
    [[ "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Intermediate enumeration tasks"
    [[ "$level" == *Advanced* ]] && echo "Run Advanced enumeration tasks"
}

do_exploitation() {
    local level="$1"
    [[ "$level" == *Basic* || "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Basic exploitation tasks"
    [[ "$level" == *Intermediate* || "$level" == *Advanced* ]] && echo "Run Intermediate exploitation tasks"
    [[ "$level" == *Advanced* ]] && echo "Run Advanced exploitation tasks"
}

# --- main flow ---
scan_level=$(choose_level "Scanning")
enum_level=$(choose_level "Enumeration")
exploit_level=$(choose_level "Exploitation")

echo -e "\n--- Execution ---"
do_scanning "$scan_level"
do_enumeration "$enum_level"
do_exploitation "$exploit_level"
