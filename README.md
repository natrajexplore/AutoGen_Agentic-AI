# ConfigGuard

Multi-agent compliance auditing for Cisco IOS / IOS-XE running configs, built on
[Microsoft AutoGen](https://github.com/microsoft/autogen) AgentChat (v0.4+ API).

ConfigGuard checks each config against a YAML security baseline, cites the exact config line
behind every finding, explains each risk in plain language for auditors, and drafts IOS
remediation for engineers to review. **It never pushes changes to a device.**

- Verdicts come from a deterministic rule engine, not the LLM, so it can't invent findings.
- Passwords, keys and SNMP communities are masked before any text reaches the model.
- Every remediation is syntax-checked and verified to resolve its finding before it is accepted.
- A human approves before remediation scripts are exported or reports are overwritten.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the agent design, Mermaid flow, baseline
schema and security model. The original project brief is in [docs/SPEC.md](docs/SPEC.md).

## Results on the test set

10 synthetic IOS-XE configs with 39 seeded violations (`tests/fixtures/`), gpt-4o:

| Criterion | Result |
|---|---|
| Detects 100% of seeded violations | 140/140 verdicts correct (39/39 violations found) |
| Zero hallucinated violations | 0 false positives; every evidence line verified against the file |
| Remediation is valid IOS | 100% pass syntax/mode validation and resolve the finding when re-checked |
| One audit under 90 seconds | 12–69 s per audit (typically 15–35 s) |

Typical cost: about $0.04–0.09 per device with gpt-4o (12k–31k tokens).

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/) (or pip).

```bash
git clone <this repo> && cd AutoGen_Agentic-AI
uv sync                          # or: python -m venv .venv && pip install -r requirements.txt && pip install -e .
cp .env.example .env             # then set OPENAI_API_KEY
```

To switch models, change `MODEL_PROVIDER` / `MODEL` in `.env` (`openai`, `anthropic`, `ollama`).
Anthropic and Ollama also need `uv add "autogen-ext[anthropic]==0.7.5"` or `"autogen-ext[ollama]==0.7.5"`.
Update `PRICE_INPUT_PER_MTOK` / `PRICE_OUTPUT_PER_MTOK` so cost tracking matches your model.

### AutoGen reference repository (optional, read-only)

The framework is installed from PyPI with pinned versions. The source repo is useful as a
read-only reference for checking APIs:

```bash
git clone --depth 1 https://github.com/microsoft/autogen.git ./reference/autogen
```

`reference/` is gitignored. The most useful paths are
`python/packages/autogen-agentchat/src/autogen_agentchat/` (agents, teams, conditions, ui) and
`python/samples/`. AutoGen is in maintenance mode, with Microsoft Agent Framework as its
successor; see *Portability* in the architecture doc.

## Usage

```bash
uv run configguard audit tests/fixtures/r10-mixed.cfg      # one device, streams the agent conversation
uv run configguard batch tests/fixtures                    # every *.cfg in a folder, one review step
uv run configguard batch ./configs --pattern "*.txt"       # other file names
uv run configguard resume 5f5d60172f2e                     # continue a paused / unapproved audit
uv run configguard --no-remediation-export batch ./configs # reports only, never write scripts
python main.py audit tests/fixtures/r10-mixed.cfg          # same as `configguard`
```

Global options go **before** the subcommand: `--baseline PATH`, `--no-remediation-export`.
`audit` and `resume` accept `--quiet` (no streaming); `batch` accepts `--stream`.

**Pause and resume.** Press Ctrl+C during an audit to save it to `state/<audit_id>.json`. An audit
that ends without approval (for example, hitting the 25-message limit) is saved the same way. Use
`configguard resume <audit_id>` to continue. Resume refuses to continue if the config file has
changed since the audit started.

**Exit codes:** `0` all audits approved · `2` any audit not approved or failed · `130` interrupted (state saved) · `1` usage error.

### Outputs

| Path | Content |
|---|---|
| `reports/<device>.md` | Per-device report: summary for auditors, all findings with line numbers, risk + remediation per FAIL |
| `reports/summary-<timestamp>.csv` | `device, rule_id, severity, status, evidence` for every rule on every device |
| `reports/batch-summary-<timestamp>.md` | Batch table (also printed) |
| `remediation/<device>_<audit_id>_remediation.txt` | Approved remediation script, headed `REVIEW BEFORE APPLYING` |
| `logs/<audit_id>.jsonl` | Every agent message, tool call and result, the human review, tokens and cost |
| `state/<audit_id>.json` | Checkpoint for resume (no config text) |

If a report already exists, ConfigGuard asks before overwriting it. Answer anything other than
`overwrite` and the new report is written next to the old one as `<device>-<audit_id>.md`.
Remediation script names include the audit ID, so they never overwrite each other.

## Sample output

Batch run (abridged):

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
Type 'all', 'none', or numbers/names separated by commas:
> all

| Device | Approved | PASS | FAIL | N/A | Critical/High FAIL | Time | Tokens | Cost |
|---|---|---|---|---|---|---|---|---|
| EDGE-R01 | yes | 14 | 0 | 0 | 0 | 12s | 12,418 | $0.0390 |
| EDGE-R02 | yes | 0 | 14 | 0 | 7 | 31s | 27,067 | $0.0870 |
| BR-R04 | yes | 11 | 3 | 0 | 2 | 18s | 17,584 | $0.0542 |
| **Total (3)** | | | | | | | 57,069 | $0.1802 |
```

Report excerpt (`reports/EDGE-R10.md`):

```markdown
| Severity | Control | What this means |
|---|---|---|
| CRITICAL | CG-006 No default SNMP community strings | The device uses a default SNMP community string, which is a common target for attackers ... |

| Rule | Severity | Status | Line(s) | Evidence |
|---|---|---|---|---|
| CG-006 | critical | **FAIL** | 68 | `snmp-server host 10.1.1.60 version 2c <MASKED:weak-default>` |
```

Remediation script excerpt:

```text
!========================================================================
! REVIEW BEFORE APPLYING
! ConfigGuard draft remediation. NOT applied to any device.
...
! --- CG-006 No default SNMP community strings [critical]
snmp-server group <SNMP_GROUP> v3 priv
snmp-server user <SNMP_USER> <SNMP_GROUP> v3 auth sha <AUTH_SECRET> priv aes 128 <PRIV_SECRET>
no snmp-server host 10.1.1.60 version 2c <CURRENT_COMMUNITY>
```

## Baseline

`baselines/cisco_ios_v1.yaml` has 14 rules (CG-001 to CG-014): SSH-only vty, SSH v2, password
encryption, enable secret, AAA, SNMP default communities, HTTP server, login banner, remote syslog,
authenticated NTP, vty ACL, exec-timeout, CDP on external interfaces, and unused interfaces. To
add a rule, append it to the YAML using one of the four check types (see the architecture doc).
The baseline is validated when it is loaded.

Conventions you may need to adapt:
- **External interfaces (CG-013)** are those whose `description` matches `settings.external_interface_pattern`.
- **Unused interfaces (CG-014)** are those with no IP, no description, no switchport/channel-group config, and not `shutdown`.

## Tests

```bash
uv run pytest                    # 205 offline tests, no API calls (about 4 s)
uv run pytest -m llm -s          # live multi-agent accuracy run on all 10 fixtures (about 5 min, about $0.60 with gpt-4o)
uv run python tests/fixtures/generate_fixtures.py   # regenerate fixtures + expected_results.json
```

`tests/fixtures/expected_results.json` is generated from the violations seeded by the fixture
generator, not from ConfigGuard output, so it is an independent ground truth. The set includes
a fully compliant config (r01), one with all 14 violations (r02), NOT_APPLICABLE cases (r08) and a
prompt-injection bait config (r09).

## Project structure

```
main.py                      entry point (same as `configguard`)
baselines/cisco_ios_v1.yaml  baseline rules
docs/                        ARCHITECTURE.md, SPEC.md
src/configguard/
  cli.py · runner.py         CLI, single / batch / resume orchestration
  team.py                    RoundRobinGroupChat, termination, approval logic
  agents/factory.py          the four AssistantAgents and their tool bindings
  approval.py                HumanApprover (UserProxyAgent) gate
  prompts.py                 system messages
  tools/                     framework-agnostic tools (no AutoGen imports)
    loader · masking · parser · baseline · rule_checks · ios_syntax · simulate · audit_record
  models.py · context.py     data models, per-audit state
  reporting.py               Markdown, CSV, remediation scripts
  telemetry.py               JSONL logging, token + cost tracking
  persistence.py             checkpoints for pause / resume
  config/                    settings (.env), model client factory
tests/                       unit tests per tool, accuracy tests, fixtures
```

## Known limitations

- **The syntax validator is best-effort.** `validate_ios_syntax` knows command keywords, mode
  order and the argument shape of the commands this baseline fixes. It is not a full IOS parser:
  inside `router`, `key chain` or `tacacs server` blocks it accepts any command, and it doesn't
  model nested sub-modes.
- **Remediation verification is an approximation.** `tools/simulate.py` models IOS merge
  behaviour well enough for the baseline rules, but it is not an emulator. Commands that rely on
  platform defaults or on interactions with other features can't be verified this way. Validate
  in a lab before production.
- **"Intent" is checked by the Critic, not by code.** Code confirms that a fix makes the rule pass,
  not that it does so the intended way. That check rests on the hints and the Critic, which in
  testing approved almost everything. Human review is therefore required, not optional.
- **Remediation can be redundant or over-broad.** For example, it may re-add `aaa new-model`
  when it already exists, create a new placeholder ACL instead of reusing an existing one, or
  remove an extra SNMP community through a placeholder.
- **Regex patterns from the model can be slow.** `find_config_lines` caps pattern length, but
  Python's `re` has no timeout, so a pathological pattern could stall a run.
- **Interface classification depends on descriptions.** CG-013 can't detect an external interface
  whose description doesn't follow your naming convention.
- **Line-number assumptions.** Line numbers refer to the file as given, and the parser assumes
  `show running-config` style indentation.
- **Batch audits run one at a time.** That avoids rate limits, but a large fleet takes roughly
  N × 20–30 s.
- **Ctrl+C pause is untested.** Resume is tested live via an early stop on the message limit.
  The Ctrl+C path saves the team state in the middle of a run with AutoGen's `save_state`, which
  has no automated test yet. If a Ctrl+C checkpoint won't resume, restart the audit.

## Next steps and roadmap

**v2: Cisco ASA and Palo Alto PAN-OS.** The design already isolates what changes per platform:
1. **Parsers:** ASA is IOS-like text and can use `ciscoconfparse2` with `syntax="asa"`. PAN-OS
   configs are XML and need a parser that builds the same masked-inventory shape (zones, security
   rules, profiles, management services).
2. **Baselines:** add `platform: cisco_asa | panos` and a baseline file per platform. Add new
   check types for XML: `xpath_required` and `xpath_forbidden`, plus rule-table checks such as
   "no any/any allow rules" and "every allow rule has a security profile group".
3. **Masking:** add ASA and PAN-OS secret patterns (`<phash>`, `<key>`, API keys, pre-shared
   keys) to `tools/masking.py`, with leak tests for each.
4. **Remediation:** ASA commands go through a validator variant. PAN-OS fixes would be `set`
   commands or XML API patches, with their own validator and simulator.
5. **Routing:** detect the platform from the file content and pick the parser, baseline and
   remediation validator per device. The agents and prompts stay the same.

Other improvements:
- Run the regex search in a subprocess with a timeout, or restrict the pattern syntax.
- Use a stronger model for the Critic only, or add independent second-opinion checks.
- Check that an access-class refers to an ACL that is defined and non-empty.
- Run batch audits concurrently, with a rate-limit budget.
- Optionally verify remediation on a lab device (pyATS / Batfish).
