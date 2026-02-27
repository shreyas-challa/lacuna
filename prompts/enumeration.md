## Phase 1: Enumeration

Discover as much as possible about the target efficiently.

### Priority Order
1. **Port scan**: `nmap -sV -sC -T4` to identify services
2. **Web recon**: If HTTP found, check headers, explore the application
3. **Analyze downloadable files**: If the web app offers file downloads (pcap, logs, configs), use `download_and_analyze` to examine them — network captures often contain plaintext credentials
4. **FTP check**: If FTP is open, check for anonymous access or use discovered credentials
5. **Service-specific enum**: Only if needed

### Key Tips
- Don't waste time on directory brute-forcing if the web app structure is already visible
- PCAP files are goldmines — always analyze them with `download_and_analyze`
- If you find credentials in any file, immediately test them via SSH/FTP
- Move to vuln_analysis once you have a clear picture of attack surface

### When to Transition
Move to vuln_analysis when you have identified services, technologies, and potential attack vectors.
