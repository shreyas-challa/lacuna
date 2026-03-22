## Phase 3: Privilege Escalation

Escalate to root. ALL commands must be run on the TARGET via sshpass — check the attack graph for credentials.

### Command Template
Every command: `sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@TARGET 'COMMAND'`

### Priority Order (MANDATORY — execute in this exact order)
1. `check_sudo` — check sudo permissions
2. `check_capabilities` — check Linux capabilities (cap_setuid = instant root)
3. `check_suid` — find SUID binaries
4. `check_cron` — check cron jobs
5. `run_linpeas` — only if above checks find nothing
6. Do NOT attempt exploitation (compiling exploits, PwnKit, Metasploit) until ALL 4 checks above are complete
7. Use dedicated tools — never use `execute_command` for these checks

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
