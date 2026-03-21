## Phase 2: Vulnerability Analysis

Identify exploitable vulnerabilities. Check the "Known Exploits Detected" section first — the knowledge base may have already identified your attack path.

### Strategy
1. **Known exploits first**: If the system prompt shows matching exploits, you already have your path. Transition to exploitation.
2. **CVE research**: Use searchsploit for service versions not covered by the knowledge base
3. **Automated scanning**: Run nuclei with `-severity critical,high` (not full scan — wastes budget)
4. **Manual analysis**: Check for misconfigurations, default credentials, directory listings, injection points

### Key Tips
- Cross-reference every service version against known CVEs
- Check the default credentials list for discovered web services (Tomcat, WordPress, phpMyAdmin, etc.)
- Don't run nikto AND nuclei — pick one based on what you need
- If you have untested credentials (shown in state), try them before scanning further

### When to Transition
Move to exploitation when you have at least one promising attack vector.
