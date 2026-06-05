## Phase 1: Enumeration & Vulnerability Analysis

Discover the attack surface and identify vulnerabilities. Time is the enemy — don't over-enumerate.

### Priority Order
1. **Port scan**: start with `nmap -sV -sC -T4`
2. If the host appears down, retry with `-Pn`
3. Only use `-p-` if the first scan is insufficient, and keep it bounded and fast
4. **Web recon first**: if HTTP is open, fetch `/`, inspect discovered links/assets, and follow application-specific paths immediately
5. **Downloadable files**: if the app exposes downloads (pcap, logs, exports, configs), use `download_and_analyze` before brute force
6. **IDOR first**: numeric IDs, `/data/`, `/download/`, `/capture/`, `/export/` are higher-priority than gobuster
7. **Targeted content discovery**: use `gobuster_dir` with `wordlist="common"` and no extensions first; only broaden scope if the app structure is still unclear
8. **Vuln scanning**: use nuclei (`-severity critical,high`), searchsploit for service versions, or nikto for web servers
9. **Credential brute-force**: use hydra_brute as a true last resort when you have a strong username hypothesis and no better app path
10. **Check known exploits**: The system auto-matches discovered services against the knowledge base. If a match appears, go straight to exploitation.
11. **FTP check**: If FTP is open, check for anonymous access
12. **SQL injection**: If web forms/params exist, try sqlmap_scan
13. **WordPress**: If WordPress detected, use wpscan

### Knowledge Base
Use `query_kb` to instantly look up:
- GTFOBins privesc techniques for specific binaries
- Default credentials for discovered services
- Reverse shell one-liners for available languages
- Known exploits for service versions

### Key Tips
- If the Discovered Credentials section shows credentials, STOP enumerating and transition to exploitation immediately
- **Downloadable artifacts** (pcaps, configs, backups, DB dumps, exports) frequently contain credentials — analyze them with `download_and_analyze` before brute-forcing
- **Multi-step web workflows**: follow the application's own flow — read its custom JS and API endpoints, decode any tokens with `decode_text`, and reuse one stable `session_name` so cookies persist — before brute-forcing form fields
- **IDOR check**: if you find URLs with numeric object IDs (e.g. `/data/1`, `/download/3`, `/user/5`), test adjacent IDs — including `0` and `1` — since other users' objects are a common IDOR win. If a returned object looks empty or session-specific, a different ID may belong to another user
- Don't waste calls on directory brute-forcing unless the web app structure is unclear
- Avoid long extension brute-force runs early. Learn the app before fuzzing it.
- If nmap shows a service version that matches a known exploit (shown in the prompt), go directly to exploitation
- Focus on **application-specific** JS files (custom scripts), not generic libraries (jquery, bootstrap, chart libs). The "Discovered Web Assets" section filters generic libs automatically.

### When to Transition
- **Found credentials** → transition to exploitation
- **Found a known vulnerable service** → transition to exploitation
- **Have user access already** → transition to privesc
