#!/usr/bin/env python3
"""Analyze Lacuna run logs for control-loop failures and workflow drift."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


LOG_DIR = Path(__file__).resolve().parents[1] / "logs"


def load_log(path_arg: str | None) -> Path:
    if path_arg:
        path = Path(path_arg).expanduser().resolve()
        if not path.exists():
            raise SystemExit(f"log not found: {path}")
        return path

    candidates = sorted(LOG_DIR.glob("*.log"))
    if not candidates:
        raise SystemExit(f"no logs found under {LOG_DIR}")
    return candidates[-1]


def analyze_log(path: Path) -> dict:
    lines = path.read_text(errors="ignore").splitlines()

    tool_counts = Counter()
    tool_history: list[tuple[int, str, str]] = []
    repeated_calls = Counter()
    phase_resets: list[str] = []
    clue_iterations: dict[str, int] = {}
    drift_after_clue: defaultdict[str, list[str]] = defaultdict(list)

    current_phase = ""
    last_phase_counter: dict[str, int] = {}
    iteration = 0

    for line in lines:
        if "Phase: " in line:
            current_phase = line.split("Phase: ", 1)[1].strip().lower()

        iter_match = re.search(r"Iteration (\d+)/\d+ \(phase: (\d+)/(\d+)\)", line)
        if iter_match:
            iteration = int(iter_match.group(1))
            phase_counter = int(iter_match.group(2))
            previous = last_phase_counter.get(current_phase)
            if previous is not None and phase_counter < previous:
                phase_resets.append(
                    f"{current_phase}: phase counter reset from {previous} to {phase_counter} at global iteration {iteration}"
                )
            last_phase_counter[current_phase] = phase_counter

        tool_match = re.search(r"Tool: ([a-zA-Z0-9_]+) \| (.+)$", line)
        if tool_match:
            name = tool_match.group(1)
            args = tool_match.group(2).strip()
            tool_counts[name] += 1
            tool_history.append((iteration, name, args))
            repeated_calls[(name, args)] += 1

        lower = line.lower()
        if "/api/v1/invite/how/to/generate" in lower and "invite_path" not in clue_iterations:
            clue_iterations["invite_path"] = iteration
        if "invite code decoded" in lower and "invite_code" not in clue_iterations:
            clue_iterations["invite_code"] = iteration
        if "shell access:" in lower and "shell_access" not in clue_iterations:
            clue_iterations["shell_access"] = iteration

    invite_anchor = clue_iterations.get("invite_path") or clue_iterations.get("invite_code")
    if invite_anchor:
        noisy_tools = {"gobuster_dir", "ffuf_fuzz", "hydra_brute", "nuclei_scan", "nikto_scan"}
        for tool_iter, name, args in tool_history:
            if tool_iter < invite_anchor:
                continue
            if name in noisy_tools:
                drift_after_clue["invite_workflow"].append(
                    f"iteration {tool_iter}: {name} {args}"
                )
            if name == "execute_command" and not any(
                path_fragment in args
                for path_fragment in (
                    "/invite",
                    "/api/v1/invite/",
                    "/api/v1/user/register",
                    "/api/v1/user/login",
                    "inviteapi",
                )
            ):
                drift_after_clue["invite_workflow"].append(
                    f"iteration {tool_iter}: execute_command {args}"
                )

    cached_hits = sum(1 for line in lines if "[CACHED" in line)
    error_hits = sum(1 for line in lines if "[ERROR]" in line)
    repetition_hits = sum(1 for line in lines if "Repetition detector:" in line)

    return {
        "path": str(path),
        "iterations_seen": max((it for it, _, _ in tool_history), default=0),
        "tool_counts": tool_counts,
        "top_repeated_calls": repeated_calls.most_common(10),
        "phase_resets": phase_resets,
        "clue_iterations": clue_iterations,
        "drift_after_clue": dict(drift_after_clue),
        "cached_hits": cached_hits,
        "error_hits": error_hits,
        "repetition_hits": repetition_hits,
    }


def render_report(report: dict):
    print(f"log: {report['path']}")
    print(f"iterations observed: {report['iterations_seen']}")
    print()

    print("tool counts:")
    for name, count in report["tool_counts"].most_common():
        print(f"  {name}: {count}")
    print()

    if report["clue_iterations"]:
        print("first critical clues:")
        for key, value in sorted(report["clue_iterations"].items(), key=lambda item: item[1]):
            print(f"  {key}: iteration {value}")
        print()

    if report["phase_resets"]:
        print("phase budget resets:")
        for item in report["phase_resets"]:
            print(f"  - {item}")
        print()

    if report["drift_after_clue"]:
        print("workflow drift after clue:")
        for key, items in report["drift_after_clue"].items():
            print(f"  {key}:")
            for item in items[:20]:
                print(f"    - {item}")
        print()

    print("other signals:")
    print(f"  cached hits: {report['cached_hits']}")
    print(f"  error hits: {report['error_hits']}")
    print(f"  repetition detector hits: {report['repetition_hits']}")
    print()

    print("top repeated tool calls:")
    for (name, args), count in report["top_repeated_calls"]:
        if count < 2:
            continue
        print(f"  {count}x {name} {args}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", help="Path to a specific log file. Defaults to latest log.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of a text report.")
    args = parser.parse_args()

    report = analyze_log(load_log(args.log))
    if args.as_json:
        print(json.dumps(report, indent=2, default=lambda x: dict(x) if isinstance(x, Counter) else x))
        return
    render_report(report)


if __name__ == "__main__":
    main()
