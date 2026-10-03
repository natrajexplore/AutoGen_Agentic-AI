<div align="center">

# 🛡️ ConfigGuard

**Multi-agent security compliance auditing for Cisco IOS / IOS-XE configurations**

Built with [Microsoft AutoGen](https://github.com/microsoft/autogen) AgentChat · deterministic rule engine · human in the loop

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![AutoGen](https://img.shields.io/badge/AutoGen%20AgentChat-0.7.5-5C2D91)
![FastAPI](https://img.shields.io/badge/FastAPI-web%20UI-009688?logo=fastapi&logoColor=white)
![Tests](https://img.shields.io/badge/tests-232%20passing-2ea44f)
![Accuracy](https://img.shields.io/badge/accuracy-140%2F140%20verdicts-2ea44f)

</div>

---

ConfigGuard reads network device running configs, checks them against a YAML security baseline,
**cites the exact config line behind every finding**, explains each risk in plain language for
auditors, and drafts IOS remediation for engineers to review.

> **It never pushes changes to a device.** Every remediation is a reviewed draft, gated by a human.

## Contents

- [Why ConfigGuard](#why-configguard)
- [Highlights](#highlights)
- [How it works](#how-it-works)
- [Meet the agents](#meet-the-agents)
- [Results](#results)
- [Quick start](#quick-start)
- [Web UI](#web-ui)
- [Command line](#command-line)
- [Configuration](#configuration)
- [Outputs](#outputs)
- [Sample output](#sample-output)
- [The baseline](#the-baseline)
- [Security and safeguards](#security-and-safeguards)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

## Why ConfigGuard

Network configurations drift away from security baselines over time. Manual audits across many
devices are slow, inconsistent, and hard to evidence. Asking an LLM to "review this config" is fast
but untrustworthy: it can miss violations, invent ones that aren't there, and see every password
in the file.

ConfigGuard combines the two approaches. **Code decides what is compliant; agents explain it and
fix it; a human approves.**

| Audience | What they get |
|---|---|
| **Network and security engineers** | Exact evidence lines, verified IOS remediation scripts, lockout warnings |
| **Compliance auditors** | A plain-language "what this means" summary for every failed control |
| **Teams running many devices** | Batch audits, a CSV summary, a full audit trail, token and cost tracking |

## Highlights

- 🎯 **No made-up findings.** Verdicts come from a deterministic rule engine. A FAIL can't exist
  without a cited config line or a "required line is missing" statement.
- 🔒 **Secrets never reach the model.** Passwords, keys and SNMP communities are masked before any
  text leaves a tool, and default communities show as `<MASKED:weak-default>`.
- ✅ **Remediation is checked, not trusted.** Every fix is syntax-checked, then applied to an
  in-memory copy of the config, and the rule is re-run to prove the fix resolves the finding.
- ⚠️ **Lockout-aware.** Changes that could cut off management access (vty transport, ACLs, AAA)
  must carry a `LOCKOUT WARNING` that names a recovery path.
- 🧑‍⚖️ **Human in the loop.** Nothing is exported or overwritten without explicit approval, in the
  terminal or as buttons in the web UI.
- 👀 **Watch the agents work.** A local web UI streams every agent message and tool call live,
  with full history and replay.
- 💸 **Spend-safe.** Hard caps on tokens, time and reply length for every audit. Each run logs
  its tokens and cost.
- ⏸️ **Pause and resume.** Audits are checkpointed and can be resumed. A checkpoint refuses to resume
  against a config that has changed.
- 🔌 **Model-agnostic.** OpenAI by default. Switch to Anthropic or Ollama with one setting.

## How it works

```mermaid
flowchart LR
    CFG[/"running-config"/] --> P

    subgraph TEAM["AutoGen RoundRobinGroupChat"]
        direction LR
        P["🧩 ConfigParser<br/><small>load · mask · parse</small>"] --> C["📏 ComplianceChecker<br/><small>rule engine</small>"]
        C --> R["🛠️ RemediationEngineer<br/><small>risk · fixes</small>"]
        R --> K["🔍 Critic<br/><small>quality gate</small>"]
        K -- "ISSUES" --> P
    end

    K -- "AUDIT_APPROVED" --> H{"🧑‍⚖️ HumanApprover"}
    H --> REP[/"Markdown report<br/>CSV summary"/]
    H -- "export approved" --> SCR[/"Remediation script<br/>REVIEW BEFORE APPLYING"/]
```

1. **Parse.** The config is loaded and every secret is masked. `ciscoconfparse2` builds a
   structured inventory. The LLM never parses raw configs itself.
2. **Check.** Each of the 14 baseline rules is evaluated **in code**. Each finding records its
   status, severity, evidence lines and line numbers.
3. **Remediate.** For each FAIL, an agent explains the risk in plain language and drafts IOS
   commands. The fix is rejected unless it passes syntax and mode checks **and** actually resolves
   the finding when re-checked against a patched copy of the config.
4. **Review.** The Critic checks the recorded results (not chat claims) for completeness, evidence
   and safety, then approves or sends work back.
5. **Approve.** You decide which remediation scripts to export. Reports are built from the
   recorded data, never from what the agents said in chat.

> **Design rule:** the LLM never decides a verdict and never sees a secret. See
> [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Meet the agents

| Agent | Job | Tools | What it must never do |
|---|---|---|---|
| 🧩 **ConfigParser** | Load the config, mask secrets, build the inventory | `load_config`, `mask_secrets`, `parse_ios_config` | Judge compliance or repeat raw config text |
| 📏 **ComplianceChecker** | Evaluate every rule and report the failures with evidence | `load_baseline`, `check_rule`, `find_config_lines` | Change a verdict, or report a FAIL without evidence |
| 🛠️ **RemediationEngineer** | Explain each risk and draft verified IOS fixes | `get_fail_findings`, `validate_ios_syntax`, `record_remediation` | Use real secrets, or risk a lockout without a warning |
| 🔍 **Critic** | Review the recorded audit; approve or send it back | `get_audit_record` (read-only) | Fix anything or change verdicts |
| 🧑‍⚖️ **HumanApprover** | Final gate before exporting or overwriting | AutoGen `UserProxyAgent` | — |

Only the Critic can end a run, so an `AUDIT_APPROVED` string planted in a config can't stop an
audit early.

## Results

Measured on 10 synthetic IOS-XE configs with **39 seeded violations** (`tests/fixtures/`), using gpt-4o:

| Success criterion | Result |
|---|---|
| Detects 100% of seeded violations | ✅ **140/140** verdicts correct (39/39 violations found) |
| Zero hallucinated violations | ✅ **0** false positives; every evidence line verified against the file |
| Every remediation is valid IOS | ✅ All pass syntax and mode checks, and resolve their finding when re-checked |
| One audit in under 90 seconds | ✅ **13–58 s** per audit (typically 14–28 s) |

**Typical cost:** about **$0.03–0.08 per device** with gpt-4o (9k–29k tokens). A full 10-device
run costs about $0.47. The token optimisations cut usage by 19% and cost by 21% with no loss of
accuracy.

## Quick start

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/) (or pip), and an OpenAI API key.

```bash
git clone https://github.com/natrajexplore/AutoGen_Agentic-AI.git
cd AutoGen_Agentic-AI
uv sync                                   # installs pinned dependencies
cp .env.example .env                      # then set OPENAI_API_KEY in .env

uv run configguard ui                     # open http://127.0.0.1:8000 and run an audit
# or, in the terminal:
uv run configguard audit tests/fixtures/r10-mixed.cfg
```

<details>
<summary><b>Using pip instead of uv</b></summary>

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
pip install -e .
configguard ui
```
</details>

<details>
<summary><b>Optional: AutoGen source as a read-only reference</b></summary>

AutoGen is installed from PyPI with pinned versions. Its source is handy for checking APIs:

```bash
git clone --depth 1 https://github.com/microsoft/autogen.git ./reference/autogen
```

`reference/` is gitignored. Useful paths: `python/packages/autogen-agentchat/src/autogen_agentchat/`
(agents, teams, conditions, ui) and `python/samples/`. AutoGen is in maintenance mode, with
Microsoft Agent Framework as its successor. ConfigGuard keeps AutoGen confined to four files so it
can be ported later (see *Portability* in the architecture doc).
</details>

## Web UI

```bash
uv run configguard ui            # http://127.0.0.1:8000   (--port to change)
```

```
┌ 🛡️ ConfigGuard     Run · History · Baseline                 openai · gpt-4o ┐
├───────────────┬──────────────────────────────────────────────────────────────┤
│ Configs       │ ● Parser ✓ → ● Checker ✓ → ◌ Remediation … → ○ Critic → ○ You │
│ ☑ r10-mixed   │──────────────────────────────────────────────────────────────│
│ ☐ r02-all     │ ComplianceChecker  requests 14 tool calls                    │
│ ☐ r09-bait    │   ▸ check_rule  {"rule_id":"CG-001"}            [FAIL]       │
│ [Upload]      │   ▸ check_rule  {"rule_id":"CG-003"}            [PASS]       │
│ [Run audit]   │ RemediationEngineer → record_remediation ▸   [recorded]      │
├───────────────┴──────────────────────────────────────────────────────────────┤
│ Findings: 7 FAIL · 7 PASS          [Export selected]  [Export none]          │
└──────────────────────────────────────────────────────────────────────────────┘
```

| Tab | What you can do |
|---|---|
| **Run** | Pick or upload a config (or several for a batch) and watch each agent's messages and tool calls stream live. Expand any tool call to see its arguments and result. Then review the findings and remediation, and approve the export with buttons. |
| **History** | Browse every past audit: findings, remediation, a replay of the agent conversation, links to the report and script, and **Resume** for paused or unapproved audits. |
| **Baseline** | Read the 14 rules. Click one to see its check definition and remediation hint. |

The UI is **local-only by design**. It listens on `127.0.0.1`, rejects other Host headers (DNS
rebinding) and cross-origin requests, so other web pages can't drive it or spend your API credits.
Closing the tab mid-audit saves the audit as paused.

## Command line

```bash
uv run configguard audit  tests/fixtures/r10-mixed.cfg       # one device, streams the agents
uv run configguard batch  tests/fixtures                     # every *.cfg in a folder, one review step
uv run configguard batch  ./configs --pattern "*.txt"        # custom file pattern
uv run configguard resume 5f5d60172f2e                       # continue a paused / unapproved audit
uv run configguard ui     --port 8000                        # local web UI
python main.py audit tests/fixtures/r10-mixed.cfg            # same as `configguard`
```

| Option | Applies to | Effect |
|---|---|---|
| `--baseline PATH` | all (before the subcommand) | Use a different baseline YAML |
| `--no-remediation-export` | all (before the subcommand) | Reports only; never write remediation scripts |
| `--quiet` | `audit`, `resume` | Don't stream the agent conversation |
| `--stream` | `batch` | Stream each audit's conversation |
| `--pattern GLOB` | `batch` | File pattern (default `*.cfg`) |
| `--port N` | `ui` | Port for the web UI (default 8000) |

**Pause and resume:** press **Ctrl+C** during an audit to save it to `state/<audit_id>.json`. An
audit that ends without approval is saved the same way. Run `configguard resume <audit_id>` to
continue.

**Exit codes:** `0` all approved · `2` any audit not approved or failed · `130` interrupted (state saved) · `1` usage error.

## Configuration

All settings live in `.env` (copy from [`.env.example`](.env.example)). Only the API key is required.

| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | — | Required for `MODEL_PROVIDER=openai` |
| `MODEL_PROVIDER` | `openai` | `openai`, `anthropic` or `ollama` |
| `MODEL` | `gpt-4o` | Model name for the chosen provider |
| `ANTHROPIC_API_KEY` / `OLLAMA_HOST` | — / `http://localhost:11434` | For the other providers |
| `PRICE_INPUT_PER_MTOK` / `PRICE_OUTPUT_PER_MTOK` | `2.50` / `10.00` | USD per 1M tokens, for cost tracking |
| `MAX_TOKENS_PER_AUDIT` | `150000` | Hard token cap per audit |
| `AUDIT_TIMEOUT_S` | `300` | Hard time cap per audit |
| `MAX_REPLY_TOKENS` | `2048` | Cap on each model reply |
| `REQUEST_TIMEOUT_S` | `60` | Timeout per API request (2 retries) |
| `MAX_MESSAGES` | `25` | Message cap per audit |
| `BASELINE_PATH` | `baselines/cisco_ios_v1.yaml` | Baseline file |
| `CONFIGS_DIR` / `UPLOADS_DIR` | `tests/fixtures` / `uploads` | Configs offered in the web UI |
| `REPORTS_DIR` · `REMEDIATION_DIR` · `LOGS_DIR` · `STATE_DIR` | `reports` · `remediation` · `logs` · `state` | Output folders |

> **Switching models:** Anthropic and Ollama also need `uv add "autogen-ext[anthropic]==0.7.5"` or
> `"autogen-ext[ollama]==0.7.5"`. An Ollama model must support tool calling. Update the price
> settings to match.

## Outputs

| Path | Contents |
|---|---|
| `reports/<device>.md` | Per-device report: summary for auditors, all findings with line numbers, risk and remediation for each FAIL |
| `reports/summary-<timestamp>.csv` | `device, rule_id, severity, status, evidence` for every rule on every device |
| `reports/batch-summary-<timestamp>.md` | Batch table (also printed) |
| `remediation/<device>_<audit_id>_remediation.txt` | Approved script, headed **REVIEW BEFORE APPLYING** |
| `logs/<audit_id>.jsonl` | Every agent message, tool call and result, the human review, tokens and cost |
| `state/<audit_id>.json` | Checkpoint for resume (contains no config text) |

ConfigGuard asks before overwriting an existing report. If you decline, the new report is written
next to the old one. Remediation script names include the audit ID, so scripts never overwrite
each other.

## Sample output

<details open>
<summary><b>Batch run</b></summary>

```text
[1/3] auditing r01-compliant.cfg ...
    approved: FAIL 0 PASS 14 N/A 0 (12s, $0.0390)
[2/3] auditing r02-all-violations.cfg ...
    approved: FAIL 14 PASS 0 N/A 0 (31s, $0.0870)
[3/3] auditing r04-snmp-ssh-cdp.cfg ...
    approved: FAIL 3 PASS 11 N/A 0 (18s, $0.0542)

========================================================================
HUMAN REVIEW
========================================================================
 1. EDGE-R01             FAIL  0  PASS 14  N/A  0  [approved]
 2. EDGE-R02             FAIL 14  PASS  0  N/A  0  [approved]
      CG-001: 3 command(s)  LOCKOUT WARNING
      ...
 3. BR-R04               FAIL  3  PASS 11  N/A  0  [approved]

Export remediation scripts (marked "REVIEW BEFORE APPLYING")?
Eligible: 2=EDGE-R02, 3=BR-R04
> all

| Device | Approved | PASS | FAIL | N/A | Critical/High FAIL | Time | Tokens | Cost |
|---|---|---|---|---|---|---|---|---|
| EDGE-R01 | yes | 14 | 0 | 0 | 0 | 12s | 12,418 | $0.0390 |
| EDGE-R02 | yes | 0 | 14 | 0 | 7 | 31s | 27,067 | $0.0870 |
| BR-R04 | yes | 11 | 3 | 0 | 2 | 18s | 17,584 | $0.0542 |
| **Total (3)** | | | | | | | 57,069 | $0.1802 |
```
</details>

<details>
<summary><b>Report excerpt</b> (<code>reports/EDGE-R10.md</code>)</summary>

```markdown
## Summary for auditors

**7 of 14 controls failed**, 7 passed, 0 not applicable.

| Severity | Control | What this means |
|---|---|---|
| CRITICAL | CG-006 No default SNMP community strings | The device uses a default SNMP community string, which is a common target for attackers ... |

| Rule | Severity | Status | Line(s) | Evidence |
|---|---|---|---|---|
| CG-006 | critical | **FAIL** | 68 | `snmp-server host 10.1.1.60 version 2c <MASKED:weak-default>` |
```
</details>

<details>
<summary><b>Remediation script excerpt</b></summary>

```text
!========================================================================
! REVIEW BEFORE APPLYING
! ConfigGuard draft remediation. NOT applied to any device.
! Apply in global configuration mode (configure terminal), in a maintenance window,
! with console or out-of-band access available. Replace every <PLACEHOLDER> first.
!========================================================================
!
! LOCKOUT WARNINGS
!   CG-001: LOCKOUT WARNING: Ensure a console session is active before applying ...
!
! --- CG-006 No default SNMP community strings [critical]
snmp-server group <SNMP_GROUP> v3 priv
snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_SECRET> priv aes 128 <PRIV_SECRET>
no snmp-server host 10.1.1.60 version 2c <CURRENT_COMMUNITY>
```
</details>

## The baseline

[`baselines/cisco_ios_v1.yaml`](baselines/cisco_ios_v1.yaml) contains 14 rules written in
ConfigGuard's own wording, informed by public Cisco hardening guidance:

| Rule | Control | Severity |
|---|---|---|
| CG-001 | Remote terminal access limited to SSH (no Telnet on vty) | 🔴 critical |
| CG-002 | SSH protocol version 2 enforced | 🟠 high |
| CG-003 | Password encryption service enabled | 🟡 medium |
| CG-004 | Privileged mode protected by `enable secret`, not `enable password` | 🟠 high |
| CG-005 | AAA enabled with a login authentication method | 🟠 high |
| CG-006 | No default SNMP community strings (SNMPv3 preferred) | 🔴 critical |
| CG-007 | Cleartext HTTP management disabled | 🟠 high |
| CG-008 | Login banner configured | ⚪ low |
| CG-009 | Remote syslog with informational logging | 🟡 medium |
| CG-010 | Authenticated NTP | 🟡 medium |
| CG-011 | VTY access restricted by ACL | 🟠 high |
| CG-012 | Idle session timeout on console and vty | 🟡 medium |
| CG-013 | CDP disabled on external-facing interfaces | 🟡 medium |
| CG-014 | Unused interfaces shut down | ⚪ low |

**Adding a rule** takes a few lines of YAML, using one of four check types (`global_required`,
`global_forbidden`, `children_required`, `python`):

```yaml
- id: CG-015
  title: Domain lookup disabled
  severity: low
  category: hardening
  description: Disable DNS lookups so mistyped commands are not broadcast as hostnames.
  check:
    type: global_required
    all_of: ['^no ip domain[- ]lookup$']
  remediation_hint: [no ip domain lookup]
```

The baseline is validated when it is loaded. Two conventions you may need to adapt:
- **External interfaces (CG-013):** interfaces whose `description` matches `settings.external_interface_pattern`.
- **Unused interfaces (CG-014):** no IP, no description, no switchport or channel-group config, and not `shutdown`.

## Security and safeguards

| Risk | How ConfigGuard handles it |
|---|---|
| **Secrets leaking to the model** | Raw config text stays in memory and is never returned by a tool. All tool output is masked: enable/user/line secrets, type-7 passwords, SNMP communities and v3 keys, NTP/TACACS/RADIUS/ISAKMP/OSPF/BGP/HSRP/VRRP keys, Wi-Fi PSKs and more. The search tool runs on masked text, so the model can't probe for secret values. A test checks that no fixture secret appears in any tool output. |
| **Prompt injection via config text** | Verdicts are decided in code, so injected text can't change them. Free text is truncated and labelled untrusted. Only the Critic can end a run. The test set includes a config (r09) with a live injection payload. |
| **Unsafe remediation** | Destructive or exec-mode commands (`reload`, `write`, `copy`, `erase`, ...) are rejected. Secrets must be placeholders. Lockout risks need a warning. Scripts are written only after human approval, and nothing is ever pushed to a device. |
| **Script or report injection** | Control characters are stripped from agent text, so a newline can't turn a script comment into a command. Report text is HTML-escaped, and CSV cells are protected against formula injection. |
| **Runaway cost** | Each audit stops at the first of: approval, 25 messages, 150k tokens, or 300 s. Replies are capped at 2,048 tokens, and requests time out after 60 s. |
| **Malicious regex patterns** | The `regex` engine runs model-supplied patterns with a 1-second budget for the whole search. |
| **Web UI abuse** | Localhost only, Host and Origin checks, no client-supplied file paths, sanitised uploads, and approvals accepted only while a question is open. |
| **Code execution** | No agent executes code, so no executor is configured. |

## Testing

```bash
uv run pytest                    # 232 offline tests, no API calls (about 6 s)
uv run pytest -m llm -s          # live run on all 10 fixtures (about 4 min, about $0.47 with gpt-4o)
uv run python tests/fixtures/generate_fixtures.py   # regenerate fixtures and expected_results.json
```

- **Independent ground truth.** `expected_results.json` comes from the violations *seeded* by the
  fixture generator, not from ConfigGuard output.
- **Coverage.** The fixtures include a fully compliant config (r01), one with all 14 violations (r02),
  NOT_APPLICABLE cases (r08) and a prompt-injection bait config (r09).
- **What's tested.** Every tool, the rule engine's edge cases, masking (including leak tests), the
  remediation patcher, reports, approvals, checkpoints, the web backend (with a fake agent run)
  and the spend safeguards.

## Project structure

```
AutoGen_Agentic-AI/
├── main.py                       # entry point (same as `configguard`)
├── baselines/cisco_ios_v1.yaml   # the 14 baseline rules
├── docs/
│   ├── ARCHITECTURE.md           # design, Mermaid flow, schema, security model
│   └── SPEC.md                   # original project brief
├── src/configguard/
│   ├── cli.py · runner.py        # CLI; single, batch and resume orchestration
│   ├── team.py                   # RoundRobinGroupChat, termination, spend caps
│   ├── agents/factory.py         # the four AssistantAgents and their tool bindings
│   ├── approval.py               # HumanApprover (UserProxyAgent) gate
│   ├── prompts.py                # agent system messages
│   ├── tools/                    # framework-agnostic tools (no AutoGen imports)
│   │   ├── loader.py · masking.py · parser.py
│   │   ├── baseline.py · rule_checks.py        # deterministic rule engine
│   │   ├── ios_syntax.py · simulate.py         # remediation validation and verification
│   │   └── audit_record.py                     # read-only views for agents
│   ├── web/                      # FastAPI backend + static UI (index.html, app.js, styles.css)
│   ├── reporting.py              # Markdown, CSV, remediation scripts
│   ├── telemetry.py              # JSONL logging, token and cost tracking
│   ├── persistence.py            # pause/resume checkpoints
│   └── config/                   # settings (.env) and model client factory
└── tests/                        # unit, accuracy, web and safeguard tests + fixtures
```

**Tech stack:** Python 3.11 · AutoGen AgentChat / autogen-ext 0.7.5 · ciscoconfparse2 · Pydantic ·
FastAPI + uvicorn + WebSockets · vanilla JS · pytest · uv

## Troubleshooting

<details>
<summary><b>"No API key configured" in the UI, or authentication errors</b></summary>

Set `OPENAI_API_KEY` in `.env` (not `.env.example`) and restart `configguard ui`. For other
providers, set `MODEL_PROVIDER` and that provider's key.
</details>

<details>
<summary><b>The UI won't start: port already in use</b></summary>

Run `uv run configguard ui --port 8765`, or stop the other process using port 8000.
</details>

<details>
<summary><b>An audit ended "NOT approved"</b></summary>

It hit a limit (messages, tokens or time), or the Critic raised issues that weren't resolved. The
audit is checkpointed. Continue with `configguard resume <audit_id>`, or use **Resume** in the
History tab. The reason is printed and recorded in `logs/<audit_id>.jsonl`.
</details>

<details>
<summary><b>My own configs don't appear in the UI</b></summary>

Upload them with the **Upload** button, or set `CONFIGS_DIR` in `.env` to your config folder.
Files must end in `.cfg`, `.txt`, `.conf` or `.ios`.
</details>

<details>
<summary><b>Resume says the config "changed on disk"</b></summary>

This is intentional: a checkpoint only resumes against the exact file it started with. Start a
new audit for the updated config.
</details>

## Known limitations

- **The syntax validator is best-effort.** It knows command keywords, mode order and the argument
  shapes this baseline needs. It is not a full IOS parser, and it accepts any command inside
  `router`, `key chain` or `tacacs server` blocks.
- **Remediation verification is an approximation.** The patcher models IOS merge behaviour well
  enough for these rules, but it isn't an emulator. Validate fixes in a lab before production.
- **"Intent" relies on the Critic.** Code proves that a fix makes the rule pass, not that it does
  so the intended way. In testing the Critic approved almost everything, so **human review is
  required, not optional.**
- **Remediation can be redundant.** For example, it may re-add `aaa new-model` when it already
  exists, or create a placeholder ACL instead of reusing an existing one.
- **Interface classification depends on descriptions** (CG-013), and line numbers assume
  `show running-config` formatting.
- **Batch audits run one at a time.** That avoids rate limits, but takes roughly 15–30 s per device.
- **Ctrl+C pause is untested.** Resume after an early stop is tested live. Saving mid-run on
  Ctrl+C has no automated test yet.

## Roadmap

**v2: Cisco ASA and Palo Alto PAN-OS.** The design already isolates what changes per platform:

1. **Parsers:** ASA via `ciscoconfparse2` (`syntax="asa"`). PAN-OS XML into the same masked
   inventory shape.
2. **Baselines:** one per platform, plus new XML check types (`xpath_required`, rule-table checks
   such as "no any/any allow rules").
3. **Masking:** ASA and PAN-OS secret patterns (`<phash>`, `<key>`, API keys), each with leak tests.
4. **Remediation:** an ASA validator variant, plus PAN-OS `set` commands or XML API patches.
5. **Routing:** detect the platform from the file and pick the parser, baseline and validator.
   The agents and prompts stay the same.

**Also planned:**
- Further token savings: skip the ConfigParser's reflection call, and cap how much history each
  agent re-reads.
- A stronger model, or an independent second-opinion check, for the Critic.
- Verify that access-class ACLs are defined and non-empty.
- Concurrent batch audits with a rate-limit budget.
- Optional lab verification of remediation (pyATS / Batfish).

---

<div align="center">

**ConfigGuard drafts. Humans decide. Devices stay untouched.**

[Architecture](docs/ARCHITECTURE.md) · [Project brief](docs/SPEC.md) · [Report an issue](https://github.com/natrajexplore/AutoGen_Agentic-AI/issues)

</div>
