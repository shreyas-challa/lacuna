## Phase 1: Enumeration

Discover the attack surface quickly. Time is the enemy — don't over-enumerate.

### Priority Order
1. **Port scan**: `nmap -sV -sC -T4` — identify all services and versions
2. **Check known exploits**: The system will auto-match discovered services against the knowledge base. If a match appears, skip vuln_analysis and go straight to exploitation.
3. **Web recon**: If HTTP found, check the application (curl headers, explore paths)
4. **Downloadable files**: If the web app offers downloads (pcap, logs, configs), use `download_and_analyze` — network captures often contain plaintext credentials
5. **FTP check**: If FTP is open, check for anonymous access
6. **Service-specific enum**: Only if the above doesn't reveal an attack path

### Key Tips
- If the Discovered Credentials section shows credentials, STOP enumerating and transition to exploitation immediately
- PCAP files are goldmines — always analyze them with `download_and_analyze`
- Don't waste calls on directory brute-forcing unless the web app structure is unclear
- If nmap shows a service version that matches a known exploit (shown in the prompt), go directly to exploitation

### When to Transition
- **Found credentials** → transition to exploitation (skip vuln_analysis)
- **Found a known vulnerable service** → transition to exploitation
- **Have a clear picture of attack surface** → transition to vuln_analysis
