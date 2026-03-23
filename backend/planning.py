"""Persistent planning and working-memory primitives for Lacuna.

This module introduces a task-tree-based reasoning layer that survives
conversation compression. The current agent loop can consume these
structures incrementally without a full rewrite.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field

from backend.llm import chat_completion, extract_usage, get_active_model


TASK_OPEN = {"pending", "active", "blocked"}


@dataclass
class PlanTask:
    id: str
    title: str
    description: str = ""
    status: str = "pending"
    priority: int = 50
    parent_id: str | None = None
    tool_hints: list[str] = field(default_factory=list)
    success_criteria: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "parent_id": self.parent_id,
            "tool_hints": list(self.tool_hints),
            "success_criteria": self.success_criteria,
            "evidence": list(self.evidence),
        }


@dataclass
class AttackPlan:
    objective: str
    tasks: list[PlanTask] = field(default_factory=list)
    source: str = "template"
    rationale: str = ""
    updated_at: float = field(default_factory=time.time)

    def ordered_tasks(self) -> list[PlanTask]:
        status_rank = {"active": 0, "pending": 1, "blocked": 2, "done": 3, "abandoned": 4}
        return sorted(
            self.tasks,
            key=lambda task: (status_rank.get(task.status, 9), task.priority, task.title.lower()),
        )

    def active_task(self) -> PlanTask | None:
        for task in self.ordered_tasks():
            if task.status == "active":
                return task
        for task in self.ordered_tasks():
            if task.status == "pending":
                task.status = "active"
                return task
        return None

    def open_tasks(self) -> list[PlanTask]:
        return [task for task in self.ordered_tasks() if task.status in TASK_OPEN]

    def get_task(self, task_id: str) -> PlanTask | None:
        for task in self.tasks:
            if task.id == task_id:
                return task
        return None

    def set_status(self, task_id: str, status: str, evidence: str = ""):
        task = self.get_task(task_id)
        if not task:
            return
        task.status = status
        if evidence and evidence not in task.evidence:
            task.evidence.append(evidence)

    def ensure_single_active(self):
        active_tasks = [task for task in self.ordered_tasks() if task.status == "active"]
        if active_tasks:
            leader = active_tasks[0]
            for task in active_tasks[1:]:
                task.status = "pending"
            return leader
        return self.active_task()

    def to_dict(self) -> dict:
        return {
            "objective": self.objective,
            "source": self.source,
            "rationale": self.rationale,
            "updated_at": self.updated_at,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    def render_summary(self, limit: int = 8) -> str:
        if not self.tasks:
            return "## Active Plan\nNo tasks yet."

        lines = ["## Active Plan"]
        if self.rationale:
            lines.append(f"Planner rationale: {self.rationale}")
        for task in self.ordered_tasks()[:limit]:
            marker = task.status.upper()
            detail = f" — {task.success_criteria}" if task.success_criteria else ""
            lines.append(f"- [{marker}] {task.title}{detail}")
        remaining = len(self.tasks) - min(len(self.tasks), limit)
        if remaining > 0:
            lines.append(f"- ... {remaining} more task(s)")
        return "\n".join(lines)

    @classmethod
    def from_dict(cls, data: dict, fallback_objective: str) -> "AttackPlan":
        tasks = []
        for item in data.get("tasks", []):
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()
            task_id = str(item.get("id", "")).strip() or _slugify(title)
            if not title or not task_id:
                continue
            tasks.append(
                PlanTask(
                    id=task_id,
                    title=title,
                    description=str(item.get("description", "")).strip(),
                    status=str(item.get("status", "pending")).strip() or "pending",
                    priority=int(item.get("priority", 50) or 50),
                    parent_id=(str(item.get("parent_id", "")).strip() or None),
                    tool_hints=_clean_list(item.get("tool_hints")),
                    success_criteria=str(item.get("success_criteria", "")).strip(),
                    evidence=_clean_list(item.get("evidence")),
                )
            )
        return cls(
            objective=str(data.get("objective", "")).strip() or fallback_objective,
            tasks=tasks,
            source=str(data.get("source", "")).strip() or "llm",
            rationale=str(data.get("rationale", "")).strip(),
            updated_at=time.time(),
        )


@dataclass
class Observation:
    tool_name: str
    summary: str
    significance: str = "low"
    notable: list[str] = field(default_factory=list)
    follow_up: list[str] = field(default_factory=list)
    raw_ref: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "summary": self.summary,
            "significance": self.significance,
            "notable": list(self.notable),
            "follow_up": list(self.follow_up),
            "raw_ref": self.raw_ref,
            "timestamp": self.timestamp,
        }


class WorkingMemory:
    """Persistent scratchpad independent of prompt history compression."""

    def __init__(self):
        self.hypotheses: list[str] = []
        self.dead_ends: list[str] = []
        self.key_findings: list[str] = []
        self.pending_questions: list[str] = []
        self.observations: list[Observation] = []
        self.current_plan: AttackPlan | None = None
        self.last_plan_reason: str = ""

    def set_plan(self, plan: AttackPlan, reason: str = ""):
        self.current_plan = plan
        self.last_plan_reason = reason

    def record_observation(self, observation: Observation):
        if not observation.summary:
            return
        self.observations.append(observation)
        self.observations = self.observations[-16:]

        if observation.significance in {"high", "critical"}:
            self._append_unique(self.key_findings, observation.summary)
        for item in observation.follow_up[:3]:
            self._append_unique(self.pending_questions, item)

    def record_dead_end(self, description: str):
        self._append_unique(self.dead_ends, description)
        self.dead_ends = self.dead_ends[-10:]

    def sync_from_state(self, state) -> None:
        for hyp in state.hypotheses.values():
            if hyp.status in {"active", "validated"}:
                self._append_unique(self.hypotheses, hyp.description)

        for finding in state.findings:
            self._append_unique(self.key_findings, f"[{finding.severity}] {finding.title}")

        for note in state.notes[-6:]:
            if any(marker in note.lower() for marker in ("next step", "decoded", "redirect", "succeeded")):
                self._append_unique(self.key_findings, note)

    def get_prompt_summary(self) -> str:
        sections = []
        if self.current_plan:
            sections.append(self.current_plan.render_summary())

        active = self.current_plan.active_task() if self.current_plan else None
        if active:
            lines = [
                "## Operator Focus",
                f"Current task: {active.title}",
            ]
            if active.description:
                lines.append(f"Task detail: {active.description}")
            if active.success_criteria:
                lines.append(f"Success: {active.success_criteria}")
            if active.tool_hints:
                lines.append(f"Suggested tools: {', '.join(active.tool_hints[:4])}")
            sections.append("\n".join(lines))

        if self.key_findings:
            sections.append("## Working Findings\n" + "\n".join(f"- {item}" for item in self.key_findings[-6:]))

        if self.dead_ends:
            sections.append("## Dead Ends\n" + "\n".join(f"- {item}" for item in self.dead_ends[-5:]))

        recent = [obs for obs in self.observations[-6:] if obs.significance in {"medium", "high", "critical"}]
        if recent:
            sections.append(
                "## Structured Observations\n" + "\n".join(
                    f"- {obs.tool_name}: {obs.summary}" for obs in recent[-4:]
                )
            )

        if self.pending_questions:
            sections.append("## Pending Questions\n" + "\n".join(f"- {item}" for item in self.pending_questions[-4:]))

        return "\n\n".join(sections)

    def to_snapshot(self) -> dict:
        return {
            "hypotheses": list(self.hypotheses[-10:]),
            "dead_ends": list(self.dead_ends[-10:]),
            "key_findings": list(self.key_findings[-12:]),
            "pending_questions": list(self.pending_questions[-8:]),
            "observations": [obs.to_dict() for obs in self.observations[-8:]],
            "current_plan": self.current_plan.to_dict() if self.current_plan else None,
            "last_plan_reason": self.last_plan_reason,
        }

    def _append_unique(self, collection: list[str], value: str):
        cleaned = str(value or "").strip()
        if cleaned and cleaned not in collection:
            collection.append(cleaned)


@dataclass
class PlanBuildResult:
    plan: AttackPlan
    source: str
    usage: dict = field(default_factory=dict)
    error: str = ""


class Planner:
    """Hybrid planner: deterministic templates with optional LLM refinement."""

    def __init__(self, client, target: str):
        self.client = client
        self.target = target
        configured = os.getenv("LACUNA_PLANNER_MODEL", "").strip()
        self.model_override = configured or self._default_planner_model()
        self.backend_override = self._choose_backend(configured)

    async def build_plan(self, phase: str, state_snapshot: dict, memory_snapshot: dict) -> PlanBuildResult:
        seed = self._build_template_plan(phase, state_snapshot, memory_snapshot)
        if not self.model_override:
            return PlanBuildResult(plan=seed, source=seed.source)

        try:
            response = await self._refine_with_llm(seed, phase, state_snapshot, memory_snapshot)
        except Exception as exc:
            return PlanBuildResult(plan=seed, source=seed.source, error=str(exc))

        content = response.choices[0].message.content or ""
        proposed = _parse_json_plan(content, seed)
        plan = _merge_seed_plan(seed, proposed)
        usage = extract_usage(response, model=plan.source == "llm" and self.model_override or get_active_model())
        if not plan.tasks:
            plan = seed
        return PlanBuildResult(plan=plan, source=plan.source, usage=usage)

    async def _refine_with_llm(self, seed: AttackPlan, phase: str, state_snapshot: dict, memory_snapshot: dict):
        system = (
            "You are Lacuna's strategic planner. Refine the provided seed attack task tree. "
            "Respond with JSON only: "
            '{"objective":"...","source":"llm","rationale":"...","tasks":[{"id":"...","title":"...",'
            '"description":"...","status":"active|pending|blocked|done","priority":10,'
            '"parent_id":null,"tool_hints":["..."],"success_criteria":"...","evidence":["..."]}]}. '
            "Rules: reuse only task ids that already exist in seed_plan; do not invent or rename milestones; "
            "use the state as the authority for what is already complete; refine descriptions, evidence, "
            "tool_hints, and ordering so the next active step is strategically correct."
        )
        user = {
            "phase": phase,
            "state": state_snapshot,
            "memory": memory_snapshot,
            "seed_plan": seed.to_dict(),
        }
        return await chat_completion(
            self.client,
            [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user, indent=2)},
            ],
            tools=None,
            backend_override=self.backend_override,
            model_override=self.model_override,
            max_tokens=2200,
        )

    def _build_template_plan(self, phase: str, state: dict, memory: dict) -> AttackPlan:
        tasks: list[PlanTask] = []
        objective = f"Compromise {self.target}"
        services = state.get("services", [])
        service_names = {svc.get("name", "") for svc in services}
        web_services = [svc for svc in services if svc.get("name") in {"http", "https", "http-proxy"}]
        has_access = bool(state.get("accesses"))
        has_root = any(access.get("level") == "root" for access in state.get("accesses", []))
        workflow_markers = set(state.get("workflow_markers", []))
        loot = state.get("loot", {})
        notes_blob = "\n".join(state.get("notes", []))
        hypotheses = {item.get("key"): item for item in state.get("hypotheses", []) if isinstance(item, dict)}

        self._add_task(
            tasks,
            "enum-services",
            "Enumerate exposed services",
            status="done" if services else "active",
            priority=5,
            tool_hints=["nmap_scan"],
            success="Produce a port/service/version map for the target.",
        )

        if web_services:
            self._add_task(
                tasks,
                "enum-web",
                "Investigate the web application",
                status="active" if phase == "enumeration" and not has_access else "done" if has_access else "pending",
                priority=10,
                tool_hints=["curl_request", "web_request", "gobuster_dir", "ffuf_fuzz"],
                success="Identify an attack path, auth workflow, or download surface.",
            )

        if hypotheses.get("invite_workflow") or "invite" in notes_blob.lower():
            self._add_task(
                tasks,
                "invite-howto",
                "Resolve the invite generation workflow",
                status="done" if "invite_code_obtained" in workflow_markers else "active",
                priority=12,
                parent_id="enum-web",
                tool_hints=["curl_request", "web_request", "decode_text"],
                success="Recover a valid invite code and the API steps required to use it.",
            )
            self._add_task(
                tasks,
                "invite-verify",
                "Verify the invite code",
                status="done" if "invite_verified" in workflow_markers else "active" if "invite_code_obtained" in workflow_markers else "pending",
                priority=13,
                parent_id="invite-howto",
                tool_hints=["web_request"],
                success="A verification request succeeds with the recovered invite code.",
                evidence=[loot.get("invite_code", "")] if loot.get("invite_code") else [],
            )
            self._add_task(
                tasks,
                "invite-register",
                "Register and log in with the recovered invite",
                status="done" if "authenticated_session" in workflow_markers else "active" if "invite_verified" in workflow_markers else "pending",
                priority=14,
                parent_id="invite-verify",
                tool_hints=["web_request"],
                success="Authenticated session is established and stored in a named web session.",
            )

        numeric_paths = set()
        for asset in state.get("web_assets", {}).get("api_endpoints", []):
            if re.search(r"/\d+(?:$|[/?#])", asset):
                numeric_paths.add(asset)
        if numeric_paths or "/data/" in notes_blob or "/download/" in notes_blob:
            self._add_task(
                tasks,
                "idor-paths",
                "Test adjacent numeric object IDs and sibling download paths",
                status="active" if not state.get("credentials") and "ssh" in service_names else "pending",
                priority=16,
                parent_id="enum-web",
                tool_hints=["curl_request", "download_and_analyze"],
                success="Find another user's data or a downloadable file that yields credentials.",
                evidence=sorted(numeric_paths)[:4],
            )

        if state.get("credentials"):
            status = "done" if has_access else "active"
            self._add_task(
                tasks,
                "test-creds",
                "Test discovered credentials on exposed services",
                status=status,
                priority=20,
                tool_hints=["execute_command", "web_request"],
                success="Verify credentials on SSH, FTP, or the web app and gain shell or authenticated access.",
            )

        if "ssh" in service_names and state.get("credentials") and not has_access:
            self._add_task(
                tasks,
                "ssh-foothold",
                "Use recovered credentials to obtain an SSH foothold",
                status="active",
                priority=22,
                tool_hints=["execute_command"],
                success="Run commands successfully as a low-privilege user over SSH.",
            )

        if has_access and not has_root:
            self._add_task(
                tasks,
                "privesc-sudo",
                "Check sudo privileges",
                status="done" if self._has_finding(state, "Sudo:") else "active" if phase == "privesc" else "pending",
                priority=30,
                tool_hints=["check_sudo"],
                success="Capture any sudo rules or confirm lack of sudo access.",
            )
            self._add_task(
                tasks,
                "privesc-caps",
                "Check Linux capabilities",
                status="done" if self._has_finding(state, "cap_setuid") else "pending",
                priority=31,
                tool_hints=["check_capabilities"],
                success="Detect cap_setuid or other exploitable capabilities.",
            )
            self._add_task(
                tasks,
                "privesc-suid",
                "Check SUID binaries",
                status="done" if self._has_finding(state, "SUID:") else "pending",
                priority=32,
                tool_hints=["check_suid"],
                success="Find exploitable SUID binaries.",
            )
            self._add_task(
                tasks,
                "privesc-cron",
                "Check cron jobs and scheduled tasks",
                status="pending",
                priority=33,
                tool_hints=["check_cron"],
                success="Identify writable scripts or privileged scheduled execution.",
            )

        if has_root:
            self._add_task(
                tasks,
                "collect-root-flag",
                "Collect the root flag and finalize the engagement",
                status="done" if loot.get("root_flag") else "active",
                priority=40,
                tool_hints=["execute_command", "transition_phase"],
                success="Read /root/root.txt and complete the run.",
            )

        if not tasks:
            self._add_task(
                tasks,
                "fallback-enum",
                "Run focused enumeration for one high-signal surface",
                status="active",
                priority=10,
                tool_hints=["nmap_scan", "curl_request"],
                success="Identify at least one actionable service or application workflow.",
            )

        rationale = "Task tree derived from structured state, workflow markers, and common HTB attack templates."
        if memory.get("dead_ends"):
            rationale += " Recent dead ends were preserved to discourage loops."
        return AttackPlan(objective=objective, tasks=tasks, source="template", rationale=rationale)

    @staticmethod
    def _default_planner_model() -> str:
        if os.getenv("MINIMAX_API_KEY"):
            return os.getenv("LACUNA_MINIMAX_MODEL", "").strip() or "MiniMax-M2.7"
        return ""

    @staticmethod
    def _choose_backend(configured_model: str) -> str | None:
        forced = os.getenv("LACUNA_PLANNER_BACKEND", "").strip().lower()
        if forced:
            return forced
        if configured_model and "minimax" in configured_model.lower():
            return "minimax"
        if configured_model and "codex" in configured_model.lower():
            return "codex"
        if os.getenv("MINIMAX_API_KEY"):
            return "minimax"
        return None

    @staticmethod
    def _has_finding(state: dict, needle: str) -> bool:
        return any(needle.lower() in finding.get("title", "").lower() for finding in state.get("findings", []))

    @staticmethod
    def _add_task(
        tasks: list[PlanTask],
        task_id: str,
        title: str,
        *,
        status: str,
        priority: int,
        tool_hints: list[str],
        success: str,
        parent_id: str | None = None,
        evidence: list[str] | None = None,
    ):
        tasks.append(
            PlanTask(
                id=task_id,
                title=title,
                status=status,
                priority=priority,
                parent_id=parent_id,
                tool_hints=tool_hints,
                success_criteria=success,
                evidence=[item for item in (evidence or []) if item],
            )
        )


def _parse_json_plan(content: str, seed: AttackPlan) -> AttackPlan:
    match = re.search(r"\{.*\}", content or "", re.DOTALL)
    if not match:
        return seed
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return seed
    plan = AttackPlan.from_dict(data, fallback_objective=seed.objective)
    if not plan.tasks:
        return seed
    return plan


def _merge_seed_plan(seed: AttackPlan, proposed: AttackPlan) -> AttackPlan:
    merged = AttackPlan.from_dict(seed.to_dict(), fallback_objective=seed.objective)
    merged.objective = proposed.objective or seed.objective
    merged.source = proposed.source or seed.source
    merged.rationale = proposed.rationale or seed.rationale
    merged.updated_at = time.time()

    proposed_by_id = {task.id: task for task in proposed.tasks}
    for task in merged.tasks:
        update = proposed_by_id.get(task.id)
        if not update:
            continue
        if update.title:
            task.title = update.title
        if update.description:
            task.description = update.description
        if update.parent_id in {item.id for item in merged.tasks} or update.parent_id is None:
            task.parent_id = update.parent_id
        if update.tool_hints:
            task.tool_hints = update.tool_hints[:6]
        if update.success_criteria:
            task.success_criteria = update.success_criteria
        if update.priority:
            task.priority = max(1, min(99, int(update.priority)))
        for item in update.evidence:
            if item and item not in task.evidence:
                task.evidence.append(item)
        task.status = _merge_status(task.status, update.status)

    merged.ensure_single_active()
    return merged


def _merge_status(seed_status: str, proposed_status: str) -> str:
    normalized_seed = (seed_status or "pending").strip().lower()
    normalized_proposed = (proposed_status or "").strip().lower()
    if not normalized_proposed:
        return normalized_seed
    if normalized_seed == "done":
        return "done"
    if normalized_proposed == "done":
        return "done"
    if normalized_seed == "active" and normalized_proposed == "pending":
        return "active"
    if normalized_seed == "blocked" and normalized_proposed == "pending":
        return "blocked"
    if normalized_seed == "pending" and normalized_proposed == "blocked":
        return "blocked"
    if normalized_seed == "pending" and normalized_proposed == "active":
        return "active"
    if normalized_seed == "active" and normalized_proposed == "blocked":
        return "blocked"
    return normalized_seed


def _clean_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        text = str(item or "").strip()
        if text:
            result.append(text)
    return result


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned[:48]
