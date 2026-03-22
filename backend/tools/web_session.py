import os
import re
import shlex
from urllib.parse import urlparse

from backend.tools.base import tool, run_command

SESSION_DIR = '/tmp/lacuna_web_sessions'


def _ensure_session(session_name: str, url: str = '') -> tuple[str, str]:
    os.makedirs(SESSION_DIR, exist_ok=True)
    parsed = urlparse(url) if url else None
    host = parsed.netloc if parsed else ''
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]+', '_', session_name or host or 'default')
    cookie_path = os.path.join(SESSION_DIR, f'{safe_name}.cookies')
    if not os.path.exists(cookie_path):
        open(cookie_path, 'a').close()
    return safe_name, cookie_path


@tool(
    name='web_request',
    description='Make a structured stateful HTTP request with a persistent cookie jar. '
                'Prefer this over execute_command for forms, JSON APIs, login flows, and session-based web apps.',
    parameters={
        'type': 'object',
        'properties': {
            'url': {'type': 'string', 'description': 'Target URL'},
            'method': {'type': 'string', 'description': 'HTTP method', 'default': 'GET'},
            'session_name': {'type': 'string', 'description': 'Cookie-jar session name', 'default': 'default'},
            'headers': {
                'type': 'array',
                'items': {'type': 'string'},
                'description': 'Headers like ["Content-Type: application/json", "X-Requested-With: XMLHttpRequest"]',
                'default': [],
            },
            'data': {'type': 'string', 'description': 'Raw form/body data', 'default': ''},
            'json_body': {'type': 'string', 'description': 'Raw JSON body string', 'default': ''},
            'follow_redirects': {'type': 'boolean', 'description': 'Follow redirects', 'default': True},
        },
        'required': ['url'],
    },
    phases=['enumeration', 'exploitation'],
)
async def web_request(
    url: str,
    method: str = 'GET',
    session_name: str = 'default',
    headers: list[str] | None = None,
    data: str = '',
    json_body: str = '',
    follow_redirects: bool = True,
) -> str:
    session_name, cookie_path = _ensure_session(session_name, url)
    req_id = re.sub(r'[^a-zA-Z0-9]+', '', session_name)[:16] or 'req'
    headers_file = f'/tmp/lacuna_{req_id}_headers.txt'
    body_file = f'/tmp/lacuna_{req_id}_body.txt'

    cmd_parts = [
        'curl', '-sS',
        '-D', headers_file,
        '-o', body_file,
        '-b', cookie_path,
        '-c', cookie_path,
        '--max-time', '20',
        '-X', (method or 'GET').upper(),
    ]

    if follow_redirects:
        cmd_parts.append('-L')

    normalized_headers = list(headers or [])
    if json_body and not any(h.lower().startswith('content-type:') for h in normalized_headers):
        normalized_headers.append('Content-Type: application/json')

    for header in normalized_headers:
        if header:
            cmd_parts.extend(['-H', header])

    if json_body:
        cmd_parts.extend(['--data', json_body])
    elif data:
        cmd_parts.extend(['--data', data])

    cmd_parts.extend([
        '-w',
        '__LACUNA_HTTP_STATUS__:%{http_code}\n__LACUNA_CONTENT_TYPE__:%{content_type}\n__LACUNA_REDIRECT_URL__:%{redirect_url}\n',
        url,
    ])

    marker_output = await run_command(' '.join(shlex.quote(part) for part in cmd_parts), timeout=30)
    header_output = await run_command(f'cat {shlex.quote(headers_file)}', timeout=5)
    body_output = await run_command(f'cat {shlex.quote(body_file)}', timeout=5)
    cookies_output = await run_command(
        f"awk 'BEGIN{{FS=\"\\t\"}} !/^#/ && NF >= 7 {{print $6}}' {shlex.quote(cookie_path)} | sort -u",
        timeout=5,
    )

    status = re.search(r'__LACUNA_HTTP_STATUS__:(\d+)', marker_output)
    content_type = re.search(r'__LACUNA_CONTENT_TYPE__:(.*)', marker_output)
    redirect_url = re.search(r'__LACUNA_REDIRECT_URL__:(.*)', marker_output)
    set_cookie_names = sorted(set(re.findall(r'(?im)^Set-Cookie:\s*([^=;\s]+)=', header_output)))

    parts = [
        f"Session: {session_name}",
        f"URL: {url}",
        f"Method: {(method or 'GET').upper()}",
        f"HTTP Status: {status.group(1) if status else 'unknown'}",
        f"Content-Type: {(content_type.group(1).strip() if content_type else '') or 'unknown'}",
    ]

    redirect_value = redirect_url.group(1).strip() if redirect_url else ''
    if redirect_value:
        parts.append(f"Redirect: {redirect_value}")

    cookie_names = [c for c in set_cookie_names if c]
    cookie_names.extend([c.strip() for c in cookies_output.splitlines() if c.strip() and c.strip() not in cookie_names])
    if cookie_names:
        parts.append(f"Cookies: {', '.join(cookie_names[:10])}")

    if header_output.strip():
        parts.append(f"Response Headers:\n{header_output.strip()}")
    if body_output.strip():
        parts.append(f"Response Body:\n{body_output.strip()}")

    return '\n'.join(parts)
