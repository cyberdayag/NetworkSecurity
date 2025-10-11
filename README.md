![Image](image/image.png)
# NETWORK SECURITY | PROJECT: DOMAIN MAPPER

## Overview
**Domain Mapper** is an automated reconnaissance and enumeration framework for Windows domain environments.  
It provides staged workflows for **Scanning**, **Enumeration**, and **Exploitation** at three depth levels (Basic / Intermediate / Advanced). Higher levels automatically include the functionality of lower levels.

>This project was completed as part of the course "Cyber Security" (7736/37) — Information Security and Corporate Network Protection, at John Bryce College.

>This script is intended solely to demonstrate certain tools and techniques for working with Windows Domain Controllers (DC) and Active Directory (AD). All testing for this project was performed in a controlled laboratory environment on an educational DC that was specifically deployed for this purpose. Do not run this script against production systems or networks without explicit written authorization from the owner.

---

## Project structure (shortened)
This project follows a staged workflow. Each top-level step collects inputs, runs scans/enumeration, or performs exploitation, depending on the selected level.

1. **Getting the User Input**  
   Prompts the operator for the target network (CIDR), a folder name for results (working_dir), optional AD/domain credentials, user/password lists (with sensible defaults), and desired levels (Basic / Intermediate / Advanced) for Scanning, Enumeration, and Exploitation. A confirmation step validates settings before any network activity.

2. **Scanning Mode**  
   Executes Nmap-based scans according to the chosen level: quick host-assume scans (Basic), full TCP port sweeps (Intermediate), or comprehensive TCP+UDP scans (Advanced). Live hosts are discovered and per-host raw results are stored.

3. **Enumeration Mode**  
   Performs service/version discovery and targeted protocol enumeration. At higher levels the framework runs additional NSE scripts, enumerates shares/services, and — if AD credentials are provided — performs authenticated Active Directory queries (users, groups, policies, account flags).

4. **Exploitation Mode**  
   Runs active vulnerability checks and credential attacks based on the selected level: vuln scanning (Basic), controlled password-spraying (Intermediate), and Kerberos ticket extraction + offline cracking (Advanced). Results and discovered credentials are logged per host.

5. **Results & Post-processing**  
   All findings are saved per-host (`result_<IP>.txt`) during execution. The final cleanup step converts per-host text results to PDF, cleans temporary files, and prints a summary/runtime.

> **Note:** Choosing a higher level automatically includes the behaviours and checks of preceding levels.

---

## Scanning Mode

- **Basic**: Scans with `nmap -Pn` to assume hosts are online and skip host discovery (fast SYN scans).  
- **Intermediate**: Scans all 65,535 TCP ports with `-p-`.  
- **Advanced**: Performs full TCP scanning plus UDP scanning for comprehensive coverage.

---

## Enumeration Mode

- **Basic**: Service/version detection, DC and DHCP identification.  
- **Intermediate**: Targeted enumeration of key services (FTP, SSH, SMB, WinRM, LDAP, RDP), shared folders and NSE script checks.  
- **Advanced**: Authenticated AD enumeration (users, groups, shares, password policy, disabled/never-expire accounts, Domain Admins) when credentials are available.

---

## Exploitation Mode

- **Basic**: Run `nmap --script vuln` to identify known service vulnerabilities.  
- **Intermediate**: Perform controlled password-spraying to identify weak/reused credentials.  
- **Advanced**: Extract Kerberos ticket hashes (AS-REP/SPN) and attempt offline cracking with `hashcat`.

---

## Results

- Each run saves per-host outputs to `result_<IP>.txt`.  
- The `STOP` routine converts per-host `.txt` files to PDF and performs cleanup at the end of the session.


```bash
## Directory Structure

Horns&HoovesLLC/
|
├── 192.168.xx.xx/
│   |__ result_<IP>.pdf
│   
├── 192.168.xx.x1/
├── ...
└── live_hosts.txt
```
* **Horns&HoovesLLC**  is an example of the result folder name provided by the user.
- Each host has its own folder containing results.  
- live_hosts.txt contains all active hosts detected in the network.
---

## Installation

```bash
git clone https://github.com/cyberdayag/NetworkSecurity.git
```

---

## Usage

```bash
cd PenetrationTesting
chmod +x TMagen773637.s21.ZX305.sh
./TMagen773637.s21.ZX305.sh
```

### Follow the prompts:
1. Ensure required tools are installed (see **Requirements**).  
2. Run the main script as root.  
3. Provide target CIDR, optional AD credentials, userlist/passwordlist (or accept defaults), and levels for Scanning/Enumeration/Exploitation.  
4. Monitor console status messages and inspect per-host `result_<ip>.txt` files; final PDFs are produced by `STOP`.

---

## Requirements

- `nmap` (with NSE), `fping`, `enscript` + `ps2pdf`/Ghostscript, `kerbrute`, Impacket tools, `hashcat`, `crackmapexec`, `rpcclient`, `ldapsearch`, `wget`, and standard GNU utilities (`awk`, `grep`, `sed`, `tr`, `paste`).

---

## Disclaimer
> **WARNING:** Do not run this tool on networks you do not own. Execute it only in a controlled lab environment or with explicit written authorization from the network owner.

