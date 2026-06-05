## Phase 3: Privilege Escalation

Escalate to root. ALL commands must be run on the TARGET via sshpass — check the attack graph for credentials.

### Command Template
Every command: `sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@TARGET 'COMMAND'`

### Enumerate before you exploit
Run these high-value checks early — they find most privesc paths. Order is a
guideline, not a ritual; follow the strongest lead as soon as you see it.
1. `check_sudo` — sudo permissions (a `sudo -l` GTFOBin is often instant root)
2. `check_capabilities` — Linux capabilities (cap_setuid = instant root)
3. `check_suid` — SUID binaries
4. `check_cron` — cron jobs and writable scheduled scripts
5. `run_linpeas` — broader sweep if the targeted checks come up empty
6. Do at least one of the checks above before launching a kernel/PwnKit/Metasploit exploit — don't blind-fire exploits
7. Use the dedicated check tools (they parse results into state) — not `execute_command`

### PwnKit / pkexec Safety Gate
- Seeing `/usr/bin/pkexec` alone is NOT evidence of vulnerability.
- Do not assume `pkexec --version` implies vulnerable or exploitable state.
- Only attempt pkexec/PwnKit exploitation after checklist completion and explicit corroborating evidence (unpatched distro/advisory evidence from target).
- If evidence is ambiguous, prioritize alternative privesc paths from `sudo`, capabilities, SUID, cron, or linpeas findings.

Use `query_kb` to look up GTFOBins techniques for any interesting binary you find.

### Exploiting Capabilities
If you find `cap_setuid` on python:
```
sshpass -p 'PASS' ssh -o StrictHostKeyChecking=no USER@TARGET '/usr/bin/python3 -c "import os; os.setuid(0); os.system(\"id; cat /root/root.txt\")"'
```

### After Getting Root
- Run `id` to confirm root
- Read root flag: `cat /root/root.txt`
- Call `append_report` with the full attack chain
- Call `transition_phase` with `next_phase: "complete"`

### IMPORTANT
When you have root and the root flag, call transition_phase with next_phase="complete" immediately. Do not continue scanning.
