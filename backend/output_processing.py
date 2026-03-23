"""Structured tool-output summarization for planner consumption."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ProcessedOutput:
    summary: str
    significance: str = "low"
    notable: list[str] = field(default_factory=list)
    follow_up: list[str] = field(default_factory=list)


class OutputProcessor:
    """Convert raw tool output into compact, planner-friendly observations."""

    def process(self, tool_name: str, args: dict, result: str, target: str) -> ProcessedOutput:
        if result.startswith("[ERROR]") or result.startswith("[TIMEOUT"):
            return ProcessedOutput(
                summary=f"{tool_name} failed: {result.splitlines()[0][:180]}",
                significance="medium",
                follow_up=[f"Reassess why {tool_name} failed before repeating it."],
            )

        if tool_name == "nmap_scan":
            return self._process_nmap(result)
        if tool_name in {"curl_request", "web_request"}:
            return self._process_web(tool_name, args, result)
        if tool_name == "download_and_analyze":
            return self._process_download(args, result)
        if tool_name in {"execute_command", "check_sudo", "check_capabilities", "check_suid", "check_cron", "run_linpeas"}:
            return self._process_shell(tool_name, result, target)
        if tool_name in {"hydra_brute", "sqlmap_scan", "wpscan"}:
            return self._process_security_tool(tool_name, result)

        return ProcessedOutput(summary=f"{tool_name} completed.", significance="low")

    def _process_nmap(self, result: str) -> ProcessedOutput:
        services = []
        notable = []
        for match in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", result):
            port, _, service, version = match.groups()
            label = f"{service}/{port}"
            if version.strip():
                label += f" ({version.strip()})"
            services.append(label)
        if "Anonymous FTP login allowed" in result:
            notable.append("Anonymous FTP access detected.")
        redirect = re.search(r"Did not follow redirect to (https?://\S+)", result)
        if redirect:
            notable.append(f"HTTP redirect observed: {redirect.group(1)}")
        summary = "Discovered services: " + (", ".join(services[:6]) if services else "no open services parsed.")
        return ProcessedOutput(
            summary=summary,
            significance="high" if services else "medium",
            notable=notable,
            follow_up=["Choose one exposed service and pursue the most likely foothold."],
        )

    def _process_web(self, tool_name: str, args: dict, result: str) -> ProcessedOutput:
        url = args.get("url", "")
        status = re.search(r"(?m)^HTTP Status:\s*(\d+)", result)
        redirect = re.search(r"(?m)^Redirect:\s*(\S+)", result)
        api_paths = sorted(set(re.findall(r"/api/[A-Za-z0-9_./-]+", result)))
        numeric_paths = sorted(set(re.findall(r"/[A-Za-z0-9_./-]*/\d+(?:\b|[/?#])", result)))
        downloads = sorted(set(re.findall(r"/[A-Za-z0-9_./-]*(?:download|export|raw|file|pcap)[A-Za-z0-9_./-]*", result, re.IGNORECASE)))
        notable = []
        if redirect:
            notable.append(f"Redirects to {redirect.group(1)}")
        if api_paths:
            notable.append(f"API paths: {', '.join(api_paths[:4])}")
        if numeric_paths:
            notable.append(f"Numeric object paths: {', '.join(numeric_paths[:4])}")
        if downloads:
            notable.append(f"Download paths: {', '.join(downloads[:4])}")
        if "invite" in result.lower():
            notable.append("Invite-based workflow evidence detected.")
        if "set-cookie" in result.lower() or re.search(r"(?m)^Cookies:\s+\S", result):
            notable.append("Session cookies were observed.")

        status_text = status.group(1) if status else "unknown"
        summary = f"{tool_name} fetched {url or 'web content'} with status {status_text}."
        if api_paths:
            summary += f" Found {len(api_paths)} API endpoint hint(s)."
        significance = "medium"
        if numeric_paths or downloads or "invite" in result.lower():
            significance = "high"
        return ProcessedOutput(
            summary=summary,
            significance=significance,
            notable=notable,
            follow_up=[item for item in [
                "Test adjacent numeric IDs and sibling download endpoints." if numeric_paths else "",
                "Use the same web session for the next workflow step." if "set-cookie" in result.lower() else "",
                "Fetch and analyze any unfamiliar JS or download path." if api_paths or downloads else "",
            ] if item],
        )

    def _process_download(self, args: dict, result: str) -> ProcessedOutput:
        filename = args.get("filename", "downloaded file")
        notable = []
        if re.search(r"(?:^|\s)USER\s+\S+", result, re.MULTILINE) and re.search(r"(?:^|\s)PASS\s+\S+", result, re.MULTILINE):
            notable.append("Cleartext credentials were found in analyzed content.")
        if ".pcap" in filename or "tcpdump" in result.lower():
            notable.append("Packet capture content analyzed.")
        summary = f"Analyzed {filename}."
        if notable:
            summary += " " + " ".join(notable[:2])
        return ProcessedOutput(
            summary=summary,
            significance="high" if notable else "medium",
            notable=notable,
            follow_up=["Test any recovered credentials on SSH and other exposed services."] if notable else [],
        )

    def _process_shell(self, tool_name: str, result: str, target: str) -> ProcessedOutput:
        notable = []
        significance = "medium"
        uid_match = re.search(r"uid=(\d+)\(([^)]+)\)", result)
        if uid_match:
            uid, user = uid_match.groups()
            notable.append(f"Shell context: {user} (uid {uid}) on {target}.")
            significance = "high"
        if "cap_setuid" in result:
            notable.append("cap_setuid capability detected.")
            significance = "critical"
        if "NOPASSWD" in result or "(ALL)" in result or "(root)" in result:
            notable.append("Potentially exploitable sudo rule detected.")
            significance = "critical"
        if "root.txt" in result:
            notable.append("Root flag path or contents referenced.")
            significance = "critical"
        if "user.txt" in result:
            notable.append("User flag path or contents referenced.")
            significance = "high"
        summary = f"{tool_name} returned shell output."
        if uid_match:
            summary = f"Shell command confirmed execution as {uid_match.group(2)}."
        return ProcessedOutput(
            summary=summary,
            significance=significance,
            notable=notable,
            follow_up=["Pivot from shell confirmation into the privesc checklist."] if uid_match else [],
        )

    def _process_security_tool(self, tool_name: str, result: str) -> ProcessedOutput:
        lower = result.lower()
        notable = []
        significance = "medium"
        if "login:" in lower and "password:" in lower:
            notable.append("Verified credential pair recovered.")
            significance = "high"
        if "vulnerable" in lower or "sql injection" in lower:
            notable.append("Exploitable finding detected.")
            significance = "high"
        if "title:" in lower and tool_name == "wpscan":
            notable.append("WordPress vulnerability findings detected.")
            significance = "high"
        summary = f"{tool_name} completed with security-relevant output."
        return ProcessedOutput(summary=summary, significance=significance, notable=notable)
