## Phase 4: Privilege Escalation

Your goal is to escalate privileges to root/admin:

1. **Enumeration**: Run LinPEAS or manual checks to find privilege escalation vectors
2. **Sudo Abuse**: Check sudo -l for exploitable sudo permissions
3. **SUID/SGID**: Find and analyze SUID/SGID binaries
4. **Cron Jobs**: Look for writable cron jobs or scripts
5. **Exploit**: Execute the privilege escalation

### Strategy
- Start with sudo -l — it's the quickest check
- Look for SUID binaries and check GTFOBins for exploitation
- Check cron jobs for writable scripts
- Run LinPEAS for comprehensive enumeration
- Check kernel version for kernel exploits as a last resort
- After getting root, retrieve root.txt

### When to Complete
Call transition_phase with "complete" when you have:
- Achieved root/admin access OR exhausted all privilege escalation vectors
- Retrieved the root flag (if applicable)
- Documented the full attack chain in the report
