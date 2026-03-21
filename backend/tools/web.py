from backend.tools.base import tool, run_command


@tool(
    name='sqlmap_scan',
    description='Run sqlmap SQL injection scanner against a target URL. Provide a URL with injectable parameters (e.g. http://target/page?id=1).',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL with parameters (e.g. "http://10.10.10.1/page.php?id=1")'},
            'flags': {
                'type': 'string',
                'description': 'Additional sqlmap flags (e.g. "--dbs", "--dump", "--os-shell", "--level=3 --risk=2", "--forms")',
                'default': '--batch --dbs',
            },
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def sqlmap_scan(url: str, flags: str = '--batch --dbs') -> str:
    return await run_command(f'sqlmap -u "{url}" {flags}', timeout=300)


@tool(
    name='hydra_brute',
    description='Run hydra credential brute-force against a target service. Supports ssh, ftp, http-post-form, mysql, smb, etc.',
    parameters={
        'type': 'object',
        'properties': {
            'target': {'type': 'string', 'description': 'Target IP or hostname'},
            'service': {
                'type': 'string',
                'description': 'Service to brute-force (ssh, ftp, http-post-form, mysql, smb, rdp, telnet)',
            },
            'username': {
                'type': 'string',
                'description': 'Username or username file (e.g. "admin" or "/usr/share/seclists/Usernames/top-usernames-shortlist.txt")',
            },
            'password': {
                'type': 'string',
                'description': 'Password or password file (e.g. "password123" or "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt")',
            },
            'flags': {
                'type': 'string',
                'description': 'Additional hydra flags (e.g. "-s 2222" for non-standard port, "-t 4" for threads)',
                'default': '',
            },
        },
        'required': ['target', 'service', 'username', 'password'],
    },
    phases=['enumeration'],
)
async def hydra_brute(target: str, service: str, username: str, password: str, flags: str = '') -> str:
    # Determine if username/password are files or single values
    import os
    user_flag = '-L' if os.path.isfile(username) else '-l'
    pass_flag = '-P' if os.path.isfile(password) else '-p'

    cmd = f'hydra {user_flag} "{username}" {pass_flag} "{password}" {flags} {target} {service}'
    return await run_command(cmd, timeout=300)


@tool(
    name='wpscan',
    description='Run WPScan WordPress vulnerability scanner. Enumerates users, plugins, themes, and known vulnerabilities.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target WordPress URL (e.g. "http://10.10.10.1/")'},
            'flags': {
                'type': 'string',
                'description': 'Additional wpscan flags (e.g. "--enumerate u,p,t", "--passwords /path/to/wordlist.txt")',
                'default': '--enumerate u,vp --no-banner',
            },
        },
        'required': ['url'],
    },
    phases=['enumeration'],
)
async def wpscan_scan(url: str, flags: str = '--enumerate u,vp --no-banner') -> str:
    return await run_command(f'wpscan --url "{url}" {flags}', timeout=300)
