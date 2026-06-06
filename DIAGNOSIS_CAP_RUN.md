# Cap Run Diagnosis — 2026-06-05 (log `20260605_205533_10_129_15_120`)

> **STATUS (2026-06-06): all items resolved.** C1, H2, M3, M4, M5, L8 fixed and
> pushed. L7 was a false alarm (significance *is* logged, just nested under
> `payload.observation.significance`). L6 (FTP probes) left as-is — harmless
> exploration. See per-item "✅ Fixed" notes below. Re-run Cap to confirm.

**Outcome:** SUCCESS. Rooted Cap end-to-end in 10 iterations / 19 tool calls / 9 planner calls.
user_flag `2b4162c3…` and root_flag `84decb30…` both captured. Cost $0.1477, 136,653 in / 27,770 out tokens.

Attack chain executed correctly: nmap → http `/data` IDOR → `/download/0` pcap → creds `nathan:Buck3tH4TF0RM3!` → SSH → `getcap` finds `cap_setuid` on python3.8 → root.

The path-finding works. The problems below are about **reporting, the graph, and efficiency** — not capability.

---

## CRITICAL

### C1 — Pentest report is empty (only the title)  ✅ Fixed (commit cd24606)
- **Symptom:** report contains just `# Penetration Test Report: 10.129.15.120`, nothing else.
- **Root cause:** the report is built *only* when the model voluntarily calls the `append_report` meta-tool (`backend/agent.py:1535`, `backend/report.py`). Across this run — and the two prior Cap runs — `append_report` was called **0 times**.
- **Why the model skips it:** the prompts both ask for it *and* tell it to bail the instant it roots:
  - `prompts/system.md:50` "After significant findings, call `append_report`"
  - `prompts/system.md:52` "If you achieve root and read root.txt, **STOP IMMEDIATELY** and transition to complete."
  - `prompts/privesc.md:36` asks for `append_report` but `:39-40` again says transition immediately.
  The "stop immediately" instruction wins; M3 races to `transition_phase(complete)` and never narrates.
- **Fix direction (not yet done):** stop depending on the LLM for the report. **Auto-synthesize it from state at completion** — `StateManager` already holds services, creds, access, loot, web_sessions, hypotheses, notes, and `GraphManager` holds the chain. Build a deterministic report (executive summary, service table, attack chain, credentials, flags, privesc method) in the COMPLETE block (`backend/agent.py:~1394-1408`). Keep `append_report` as an *optional augmentation* layered on top, not the sole source.

---

## HIGH (user-flagged)

### H2 — Attack graph is a star, not a chain (no provenance)  ✅ Fixed (commit 4d444bd)
- **Symptom:** the `nathan` credential node links **directly to the machine node**, not to the HTTP service / pcap that produced it. Everything radiates from the machine, which defeats the point of the graph.
- **Root cause:** **every parser hardcodes `source: target`** (the machine) for its edges:
  - `backend/parsers.py` — `parse_nmap:28`, `parse_gobuster:45`, `parse_ffuf:72`, `parse_nuclei:89`, `parse_pcap_analysis:120/128/132`, `parse_hydra:169`, etc.
  - `backend/analyzer.py` `_parse_command_output_for_graph:262-301` — user/cred/cap_setuid/root all edge from `target`.
  The parsers only receive `(output, target)`. They have **no idea which artifact produced the finding** (which URL, which port, which file), so they can only anchor to the machine.
- **What the chain *should* look like:**
  `machine → service:80(http) → /data IDOR → capture.pcap → cred:nathan → ssh → user:nathan → cap_setuid(python3.8) → root`
- **Fix direction (not yet done):** thread **provenance** into graph building.
  1. Give each parser the originating context (the tool's `args.url`/port/filename) so it can anchor edges to the *source artifact node* instead of always the machine.
  2. Maintain a "current source node" cursor in `Analyzer` (e.g. the service/endpoint the active task is working) and chain new nodes off it.
  3. Ensure intermediate nodes exist: http service node (from nmap), the IDOR endpoint, the pcap file node — then link cred → pcap → endpoint → service → machine.
  - Lowest-effort first cut: when a cred is found from a downloaded file, edge `pcap-file → cred` and `service → pcap-file`, rather than `machine → cred`.

---

## MEDIUM (cost / efficiency)

### M3 — Planner LLM ran 9 of 10 iterations (main cost driver)  ✅ Fixed (commit 1ed575d)
- `_refresh_plan` (`backend/agent.py:582`) fires whenever `_plan_refresh_required` is set, which nearly every state change / high-significance / web-asset event sets (15+ `_request_plan_refresh()` call sites). No dedup, no throttle.
- **This is the pending Tier-2 work.** Throttle LLM refine to (a) phase changes and (b) genuinely new high-significance findings, with a state-fingerprint guard so identical state doesn't re-refine. Fall back to the template plan otherwise. Likely cuts planner token spend by more than half.

### M4 — Cache hit rate is 1.6% (2,166 of 136,653 input tokens)  ✅ Fixed (commit 877d6cb)
- Almost no prefix caching. The prompt prefix changes every turn (state summary / graph / memory injected near the top), so the cached-input price (`$0.15` vs `$0.60`) almost never applies.
- **Fix direction:** restructure prompts so the **stable** content (system prompt, tool schemas, target) is a fixed prefix and the **volatile** content (state, graph, recent observations) comes last. With MiniMax/OpenAI-style prefix caching this is most of the input cost.

### M5 — Redundant re-fetches of the same resource  ✅ Fixed (commit 8db2ca5)
- `/data/0` fetched **3×**, `/capture` **2×**, `/download/0` **2×**, across `web_request`, `curl_request`, and `download_and_analyze`.
- The repeat-guard (`_stateful_call_counts`, `backend/agent.py:362`) only blocks *identical* calls to *stateful* tools — it doesn't dedup the **same URL across different fetch tools**, and plain GETs may not count as stateful.
- **Fix direction:** a small per-URL fetch cache keyed by normalized URL (regardless of which fetch tool), returning the cached body with a note instead of re-hitting the target. Also collapses the overlapping roles of `curl_request -o` vs `download_and_analyze` (see L8).

---

## LOW / observations

- **L6 — FTP dead-ends:** anonymous FTP probe (`curl ftp://…anonymous`) and later `ftp://nathan:…@` were tried though FTP isn't the path. Harmless exploration, ~2 wasted calls.
- **L7 — `significance` not logged:** ✅ FALSE ALARM — every `analysis` event in the jsonl has `significance: '?'` — the journal isn't recording the analyzer's significance value. Hurts future log-driven debugging; cheap to fix in `journal`/analysis logging.
- **L8 — Overlapping fetch tools:** ✅ Fixed (commit a77663c) — `curl_request` (with `-o`), `download_and_analyze`, and raw `execute_command(curl)` all pull files. The model used two different tools to grab the same pcap. Consolidating fetch responsibility would reduce confusion and redundancy (ties into M5).

---

## Suggested priority order
1. **C1** (empty report — auto-generate from state) — highest impact, the report is the deliverable.
2. **H2** (graph provenance chaining) — your flagged correctness issue.
3. **M3 + M4** (planner throttle + cache-friendly prompt layout) — biggest cost wins, aligns with the cost-efficiency priority.
4. **M5 / L7 / L8** — cleanups.
