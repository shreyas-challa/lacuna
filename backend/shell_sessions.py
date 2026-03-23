"""Persistent shell sessions for repeated remote command execution."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import time
from dataclasses import dataclass


_MARKER_PREFIX = "__LACUNA_DONE__"


@dataclass(frozen=True)
class SSHSessionSpec:
    user: str
    host: str
    password: str
    port: int = 22
    options: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"


class PersistentShellSession:
    def __init__(self, spec: SSHSessionSpec):
        self.spec = spec
        self.proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._last_used = 0.0

    async def ensure_connected(self):
        if self.proc and self.proc.returncode is None:
            return

        cmd = [
            "sshpass",
            "-p",
            self.spec.password,
            "ssh",
            "-tt",
            "-p",
            str(self.spec.port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            *self.spec.options,
            f"{self.spec.user}@{self.spec.host}",
        ]
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._last_used = time.time()
        await asyncio.sleep(0.3)
        await self._drain_initial_output()

    async def execute(self, command: str, timeout: int = 90) -> str:
        async with self._lock:
            await self.ensure_connected()
            assert self.proc and self.proc.stdin and self.proc.stdout

            marker = f"{_MARKER_PREFIX}_{int(time.time() * 1000)}_{os.getpid()}"
            wrapped = f"{command}\nprintf '\\n{marker}:%s\\n' $? \n"
            self.proc.stdin.write(wrapped.encode())
            await self.proc.stdin.drain()

            chunks: list[str] = []
            status = "0"
            try:
                while True:
                    line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=timeout)
                    if not line:
                        break
                    text = line.decode("utf-8", errors="replace")
                    if marker in text:
                        status_match = re.search(rf"{re.escape(marker)}:(\d+)", text)
                        if status_match:
                            status = status_match.group(1)
                        break
                    chunks.append(text)
            except asyncio.TimeoutError:
                return f"[TIMEOUT after {timeout}s]"

            self._last_used = time.time()
            output = _sanitize_output("".join(chunks))
            if status != "0":
                return f"{output}\n[remote exit status: {status}]".strip()
            return output.strip()

    async def close(self):
        if not self.proc or self.proc.returncode is not None:
            return
        if self.proc.stdin:
            self.proc.stdin.write(b"exit\n")
            try:
                await self.proc.stdin.drain()
            except Exception:
                pass
        try:
            await asyncio.wait_for(self.proc.wait(), timeout=2)
        except Exception:
            self.proc.kill()
            await self.proc.wait()

    async def _drain_initial_output(self):
        if not self.proc or not self.proc.stdout:
            return
        try:
            await asyncio.wait_for(self.proc.stdout.read(256), timeout=0.5)
        except Exception:
            return


class ShellSessionManager:
    def __init__(self):
        self._sessions: dict[str, PersistentShellSession] = {}

    async def execute(self, spec: SSHSessionSpec, command: str, timeout: int = 90) -> str:
        session = self._sessions.get(spec.key)
        if not session:
            session = PersistentShellSession(spec)
            self._sessions[spec.key] = session
        return await session.execute(command, timeout=timeout)

    async def close_all(self):
        for session in list(self._sessions.values()):
            await session.close()
        self._sessions.clear()


def parse_sshpass_ssh_command(command: str) -> tuple[SSHSessionSpec, str] | None:
    """Parse a common sshpass SSH invocation into a reusable session spec."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if len(tokens) < 6 or tokens[0] != "sshpass" or tokens[1] != "-p":
        return None
    if "ssh" not in tokens:
        return None

    password = tokens[2]
    ssh_index = tokens.index("ssh")
    port = 22
    options: list[str] = []
    remote = ""
    remote_cmd = ""
    i = ssh_index + 1

    while i < len(tokens):
        token = tokens[i]
        if token == "-p" and i + 1 < len(tokens):
            try:
                port = int(tokens[i + 1])
            except ValueError:
                return None
            i += 2
            continue
        if token == "-o" and i + 1 < len(tokens):
            options.extend(["-o", tokens[i + 1]])
            i += 2
            continue
        if token.startswith("-"):
            options.append(token)
            i += 1
            continue
        remote = token
        if i + 1 < len(tokens):
            remote_cmd = " ".join(tokens[i + 1 :])
        break

    if not remote or "@" not in remote:
        return None
    user, host = remote.split("@", 1)
    if not user or not host:
        return None

    spec = SSHSessionSpec(
        user=user,
        host=host,
        password=password,
        port=port,
        options=tuple(options),
    )
    return spec, remote_cmd.strip()


def _sanitize_output(output: str) -> str:
    cleaned = output.replace("\r", "")
    cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", cleaned)
    lines = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped:
            lines.append("")
            continue
        if stripped.startswith("Warning: Permanently added"):
            continue
        if stripped == "Connection to localhost closed.":
            continue
        lines.append(line)
    return "\n".join(lines).strip()
