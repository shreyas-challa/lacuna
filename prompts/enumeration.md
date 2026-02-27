## Phase 1: Enumeration

Your goal is to discover as much information as possible about the target:

1. **Port Scanning**: Start with a comprehensive nmap scan to identify open ports and services
2. **Service Identification**: Determine versions and technologies for each service
3. **Web Enumeration**: If web services are found, enumerate directories, technologies, and interesting endpoints
4. **Information Gathering**: Look for usernames, version numbers, configuration details

### Strategy
- Begin with a fast scan (`-sV -sC`) then follow up with a full port scan (`-p-`) if needed
- For each web service found, run whatweb and gobuster/ffuf
- Use curl to inspect interesting pages and headers
- Update the graph after each discovery

### When to Transition
Move to vuln_analysis when you have:
- A complete picture of open ports and services
- Enumerated web directories (if applicable)
- Identified technologies and versions
- Gathered potential usernames or credentials
