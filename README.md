# Lacuna

Lacuna is an AI-powered autonomous penetration testing agent for conducting authorized security assessments. It combines multi-backend LLM support with an attack orchestration framework that autonomously progresses through three phases — **Enumeration**, **Exploitation**, and **Privilege Escalation** — to obtain root access and capture target flags.

The system features real-time attack graph visualization, structured state tracking, token-optimized context management, adaptive task planning, and tool execution with built-in safety guardrails.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Frontend (Browser)                         │
│   D3.js Attack Graph  │  Activity Log  │  Intel Panel  │  Report   │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ WebSocket
┌────────────────────────────────┴────────────────────────────────────┐
│                     FastAPI Server (server.py)                      │
├─────────────────────────────────────────────────────────────────────┤
│                        Agent Core Loop                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Planner  │→ │ Operator │→ │  Tools   │→ │    Analyzer       │  │
│  │          │  │          │  │ Registry │  │ (State+Graph Ext) │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────────┘  │
│       ↕              ↕             ↕               ↕               │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  StateManager  │  GraphManager  │  LLM Client  │  Context   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
lacuna/
├── backend/
│   ├── agent.py              # Core autonomous loop and phase orchestration
│   ├── llm.py                # Multi-backend LLM client (OpenAI, Anthropic, MiniMax, Codex)
│   ├── planning.py           # Task tree planning and working memory
│   ├── parsers.py            # Tool output parsing for graph/state extraction
│   ├── state.py              # Structured state manager (credentials, services, findings)
│   ├── knowledge.py          # Offensive security knowledge base (GTFOBins, exploits, creds)
│   ├── analyzer.py           # Tool output analysis and state update layer
│   ├── shell_sessions.py     # Persistent SSH session management
│   ├── context.py            # Token optimization and message compression
│   ├── output_processing.py  # Tool output summarization
│   ├── operator.py           # Tactical single-task executor
│   ├── server.py             # FastAPI WebSocket server
│   ├── graph.py              # Attack graph node/edge management
│   ├── ws_manager.py         # WebSocket broadcast manager
│   ├── journal.py            # Run event logging
│   ├── report.py             # Penetration test report builder
│   └── tools/                # Tool modules
│       ├── base.py           # Tool decorator and registry
│       ├── enumeration.py    # nmap, gobuster, ffuf, whatweb, nuclei, nikto
│       ├── exploitation.py   # Metasploit, reverse shells, payloads
│       ├── privesc.py        # LinPEAS, sudo, SUID, cron, capabilities
│       ├── web.py            # sqlmap, hydra, wpscan
│       ├── web_session.py    # Stateful HTTP session handling
│       └── vuln_analysis.py  # Vulnerability assessment tools
├── frontend/
│   ├── index.html            # Main interface
│   ├── app.js                # WebSocket orchestration and phase stepper
│   ├── graph.js              # D3.js force-directed attack graph
│   ├── toolpanel.js          # Activity log rendering
│   ├── intel.js              # Intelligence panel (credentials, services, findings)
│   ├── report.js             # Markdown report viewer
│   └── style.css             # Phosphor-themed UI
├── prompts/
│   ├── system.md             # Master agent directive
│   ├── enumeration.md        # Phase 1 guidance
│   ├── exploitation.md       # Phase 2 guidance
│   └── privesc.md            # Phase 3 guidance
├── scripts/
│   └── analyze_log.py        # Post-run log analysis
├── run.py                    # Entry point
├── requirements.txt          # Python dependencies
└── .env.example              # Configuration template
```

## Core Components

### Agent (`agent.py`)

The central orchestrator that runs the autonomous attack loop. Each iteration:

1. **Plan** — The Planner generates or updates an attack plan based on current state
2. **Execute** — The Operator executes the highest-priority task via LLM-selected tool calls
3. **Analyze** — The Analyzer extracts structured data (credentials, services, vulnerabilities) from tool output and updates the state and attack graph
4. **Transition** — Phase transitions are evaluated based on discovered access levels
5. **Broadcast** — Real-time updates are pushed to the frontend over WebSocket

The agent enforces per-phase iteration budgets, tool call caching to prevent duplicate work, and stagnation detection to avoid repeating failed approaches.

### LLM Client (`llm.py`)

Supports four backends with automatic detection and failover:

| Backend | Auth Method | Model Examples |
|---------|------------|----------------|
| OpenAI | API key | gpt-4.1-mini |
| Anthropic | API key or Claude Code OAuth | claude-sonnet-4-20250514 |
| MiniMax | API key | MiniMax-M2.7 |
| Codex | ChatGPT OAuth | gpt-5.1-codex-mini |

Features:
- **Auto-detection** picks the first available backend from configured credentials
- **Auto-fallback** transparently switches backends on quota or rate limit errors
- **Cost tracking** accumulates token spend per model across the run
- **Prompt caching** support for Anthropic models

### Planner (`planning.py`)

Maintains a structured attack plan as a task tree:

- Each `PlanTask` has an id, title, description, status, priority, tool hints, and success criteria
- The plan is regenerated at phase boundaries and updated incrementally as findings emerge
- A `WorkingMemory` module tracks observations, hypotheses, and assumptions

### Operator (`operator.py`)

Executes individual tasks with a narrow, focused context window. Receives only the active task's description, success criteria, relevant state summary, and phase-specific tool subset — preventing context bloat from the full attack history.

### State Manager (`state.py`)

Tracks all discovered data as structured objects:

- **Credentials** — username, password, source, verified/failed service lists
- **Access** — host, user, privilege level, access method
- **Services** — host, port, protocol, name, version
- **Findings** — title, severity, CVE, evidence, remediation
- **Web Sessions** — named sessions with cookies and auth state
- **Hypotheses** — tracked assumptions with validation status

### Analyzer (`analyzer.py`)

Bridges raw tool output and structured state. For each tool execution:

1. Runs tool-specific extractors to populate the StateManager
2. Runs graph parsers to add nodes/edges to the GraphManager
3. Detects web assets, IDOR signals, and hostname references
4. Produces an observation summary with significance assessment and follow-up suggestions

### Tool System (`tools/`)

Tools are registered via a `@tool()` decorator that specifies the tool's name, schema, and valid phases. The registry provides OpenAI-format function schemas filtered by the current phase.

**Enumeration:** nmap, gobuster, ffuf, whatweb, nuclei, nikto, curl, file download/analysis, knowledge base queries, text decoding

**Exploitation:** Metasploit, reverse shell listeners, payload delivery, stateful HTTP requests (forms, cookies, JSON APIs), arbitrary command execution (target-scoped)

**Privilege Escalation:** LinPEAS, sudo checks, SUID binary discovery, cron job enumeration, Linux capabilities checks

**Meta (all phases):** phase transitions, report appending

All tools execute asynchronously with configurable timeouts, output capping at 8KB, and error-specific recovery hints.

### Knowledge Base (`knowledge.py`)

An embedded offensive security reference containing:

- **GTFOBins** — 50+ binaries with sudo, SUID, and capability exploitation commands
- **Service exploits** — Version-to-CVE mappings with exploitation templates
- **Default credentials** — Common passwords for FTP, HTTP, admin panels
- **Reverse shell payloads** — Bash, Python, Perl, Node.js, Ruby one-liners

The knowledge base is queried via the `query_kb` tool to avoid wasting iteration budget on external lookups.

### Context Manager (`context.py`)

Optimizes token usage by compressing message history:

- **Recent iterations** (last 4–5) retain full detail with tool results capped at 4KB
- **Older iterations** are compressed to 400-character summaries
- The system prompt and initial engagement message are always preserved
- MiniMax-compliant tool call ordering is enforced

### Parsers (`parsers.py`)

Extract structured data from tool outputs:

- `parse_nmap` — open ports, services, versions
- `parse_gobuster` / `parse_ffuf` — discovered directories and files
- `parse_nuclei` — matched vulnerability templates
- Credential extractors from nmap scripts, curl responses, config files, and PCAP analysis

### Graph Manager (`graph.py`)

Maintains the attack graph as a set of typed nodes (machine, service, user, vulnerability, root) and relationship edges. Provides text summaries for LLM context and JSON serialization for frontend rendering.

## Frontend

The frontend is a single-page application built with vanilla JavaScript and D3.js:

- **Phase Stepper** — Three-phase progression indicator (Recon → Exploit → Privesc)
- **Attack Graph** — Real-time D3.js force-directed graph with color-coded nodes
- **Activity Log** — Chronological tool call history with input, output, and elapsed time
- **Intelligence Panel** — Tables for credentials, services, findings, web assets, and hypotheses
- **Report Viewer** — Rendered markdown penetration test report
- **Command Bar** — Target IP, LHOST, and engagement controls with live metrics

All panels update in real-time over a WebSocket connection.

## Phase System

| Phase | Budget | Goal |
|-------|--------|------|
| Enumeration | 20 iterations | Discover services, credentials, and attack surface |
| Exploitation | 40 iterations | Achieve user-level access via credential reuse, exploits, or web attacks |
| Privilege Escalation | 15 iterations | Escalate to root and capture the flag |

Phases can be skipped when findings justify it (e.g., discovered credentials skip directly to exploitation; an existing user shell skips to privilege escalation). A reserve of 30 additional iterations provides overflow capacity. Total maximum: 105 iterations.

## Setup

### Prerequisites

- Python 3.10+
- Security tools: nmap, gobuster, ffuf, sqlmap, hydra, metasploit-framework, nuclei, nikto, wpscan, sshpass, linpeas
- At least one LLM API key or OAuth session (see `.env.example`)

### Installation

```bash
git clone <repo-url> && cd lacuna
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys / backend preference
```

### Running

```bash
python run.py
```

The server starts on `http://localhost:8080`. Open the frontend, enter the target IP, and click **ENGAGE**.

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
LACUNA_BACKEND=auto          # auto, openai, anthropic, codex, or minimax
OPENAI_API_KEY=sk-...        # OpenAI API key
ANTHROPIC_API_KEY=sk-ant-... # Anthropic API key
MINIMAX_API_KEY=...          # MiniMax API key
LACUNA_FALLBACK=true         # Enable automatic backend fallback
```

Backend auto-detection priority: configured backend → MiniMax → OpenAI → Anthropic → Codex.

## Logging

- **Run logs:** `logs/{timestamp}_{target}.log` — plaintext execution trace
- **Run journal:** `logs/{timestamp}_{target}.jsonl` — structured event stream
- **Web sessions:** `/tmp/lacuna_web_sessions/*.cookies` — curl cookie jars
- **Shell output:** `/tmp/nc_{port}.log` — reverse shell captures

## Reliability Features

- **Tool caching** — Deduplicates identical tool calls across the run
- **Budget enforcement** — Per-phase iteration limits prevent runaway loops
- **Stagnation detection** — Blocks repeating the same failing tool
- **Credential tracking** — Records which services each credential has been tested against
- **Phase gating** — Prevents privilege escalation attempts without confirmed user access
- **Context compression** — Progressive message summarization reduces token spend
- **Auto-fallback** — Seamless LLM backend switching on quota or rate limit errors
- **Persistent sessions** — Reuses SSH connections for sequential target commands
- **Hypothesis tracking** — Records and validates assumptions throughout the engagement
