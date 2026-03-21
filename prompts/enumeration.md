## Phase 1: Enumeration & Vulnerability Analysis

Discover the attack surface and identify vulnerabilities. Time is the enemy — don't over-enumerate.

### Priority Order
1. **Port scan**: `nmap -sV -sC -T4` — identify all services and versions
2. **Check known exploits**: The system will auto-match discovered services against the knowledge base. If a match appears, go straight to exploitation.
3. **Web recon**: If HTTP found, check the application (curl headers, explore paths, gobuster)
4. **Vuln scanning**: Use nuclei (`-severity critical,high`), searchsploit for service versions, or nikto for web servers
5. **Downloadable files**: If the web app offers downloads (pcap, logs, configs), use `download_and_analyze` — network captures often contain plaintext credentials
6. **FTP check**: If FTP is open, check for anonymous access
7. **SQL injection**: If web forms/params exist, try sqlmap_scan
8. **WordPress**: If WordPress detected, use wpscan
9. **Credential brute-force**: Use hydra_brute as a last resort when you have a service but no creds

### Knowledge Base
Use `query_kb` to instantly look up:
- GTFOBins privesc techniques for specific binaries
- Default credentials for discovered services
- Reverse shell one-liners for available languages
- Known exploits for service versions

### Key Tips
- If the Discovered Credentials section shows credentials, STOP enumerating and transition to exploitation immediately
- PCAP files are goldmines — always analyze them with `download_and_analyze`
- **IDOR check**: If you find URLs with numeric IDs (e.g. `/data/1`, `/download/3`, `/user/5`), ALWAYS try `/data/0` — ID 0 often contains pre-existing data from other users (captures, configs, credentials). This is a critical attack pattern.
- **Empty pcap?** If a downloaded pcap is empty, it's likely YOUR session's capture. Try downloading ID 0 instead — that's usually the admin's or another user's capture with credentials.
- Don't waste calls on directory brute-forcing unless the web app structure is unclear
- If nmap shows a service version that matches a known exploit (shown in the prompt), go directly to exploitation
- Focus on **application-specific** JS files (custom scripts), not generic libraries (jquery, bootstrap, chart libs). The "Discovered Web Assets" section filters generic libs automatically.

### When to Transition
- **Found credentials** → transition to exploitation
- **Found a known vulnerable service** → transition to exploitation
- **Have user access already** → transition to privesc
