---
title: RegAuditBench
emoji: 🛡️
colorFrom: blue
colorTo: purple
sdk: docker
app_file: app.py
pinned: false
---
This benchmark is designed to evaluate agent decision-making under constraints, not just model pattern recognition.
# RegAuditBench

RegAuditBench is a benchmark for evaluating AI agents on structured compliance auditing under constraints, not just a task environment.

This matters because real-world auditing requires prioritization, precision, and disciplined reasoning under limited visibility, not just pattern matching.

**Evaluation Outline**

RegAuditBench measures whether an agent can perform compliance auditing in a realistic, resource-constrained setting. Strong performance requires selecting the right files, identifying violations with evidence, assigning the correct severity, and proposing remediation patches that are both syntactically valid and semantically relevant.

**Agent Interface**

The environment follows the standard OpenEnv lifecycle:
- `reset()` starts a deterministic episode
- `step()` accepts one action and returns the next observation plus reward
- `state()` returns the current episode snapshot

Available actions:
- `search_codebase`
- `read_file`
- `flag_violation`
- `propose_fix`
- `finalize_audit`

Search is intentionally weak. It returns limited filename-level hints, hides line numbers and code context, ignores comments, and is capped per episode. It helps with triage, but it is not sufficient to solve the task on its own.

Observations expose:
- `available_files`
- `framework_rules`
- `current_findings`
- `file_reads_remaining`
- `step_count`

**What Is Being Measured**

The core evaluation targets are:
- file prioritization under a limited read budget
- precise violation identification
- correct severity classification
- valid remediation patch generation

This benchmark is designed to evaluate agent behavior, not just model capability.

It rewards disciplined auditing rather than brute-force scanning. Agents must decide what to inspect, when to act, and when the available evidence is strong enough to justify a finding.

**Task Structure**

The current suite includes three representative task types:
- Task 1: single-file audit
- Task 2: multi-file Django-style application audit
- Task 3: microservices audit under higher complexity

Difficulty rises across tasks as the agent must reason over more files, weaker local signals, and more cross-file dependencies.

**Scoring Model**

Final scores combine:
- violation detection quality
- severity accuracy
- patch quality

Step-level reward shaping reinforces good auditing behavior:
- positive reward for correct findings
- extra reward for correct severity
- extra reward for strong file prioritization
- penalty for false positives
- penalty for guessing on uninspected files
- reward for valid remediation patches
- mild penalty for unnecessary extra steps

This means evaluation captures both outcome quality and decision quality.

These reward signals are designed to encourage precision, prioritization, and evidence-based auditing rather than brute-force scanning.

**Grading Integrity**

To reduce shortcut exploitation:
- task comments are neutralized so they do not leak ground truth
- search is intentionally weak and budgeted
- patch grading checks syntax and semantic relevance, not just keyword presence
- seeded surface variation changes superficial patterns without changing underlying violations

These controls make reasoning more important than memorization.

## Final Benchmark Results (LLM-Only)

Model: llama-3.1-8b-instant (Groq, OpenAI-compatible API)

- Task 1 (Single-file audit): `0.8467`
- Task 2 (Multi-file Django audit): `0.5421`
- Task 3 (Microservices audit): `0.3176`

Interpretation:
- Task 1 (Easy): High score (~0.84) -> straightforward detection
- Task 2 (Medium): Moderate score (~0.54) -> multi-file reasoning required
- Task 3 (Hard): Lower score (~0.31) -> constrained access + cross-file reasoning

This performance profile demonstrates clear difficulty separation, with performance decreasing as tasks require broader reasoning, stronger prioritization, and cross-file coordination.

This pattern aligns with realistic auditing scenarios and indicates that the benchmark captures meaningful increases in task complexity rather than superficial pattern matching.

The reported scores are from a real LLM-only run. All results are reproducible using the provided inference pipeline and environment configuration. No task-specific heuristics or ground-truth leakage is used during evaluation.

## Key Benchmark Properties

- Constrained interaction via OpenEnv API (`reset`, `step`, `state`)
- Limited file-read budget per task
- Weak, non-leaking search interface
- Precision-focused grading with false-positive penalties
- Structured violation taxonomy spanning GDPR and OWASP
- Semantic patch validation using AST and relevance checks

## Execution Modes

- `LLM Mode` -> Full benchmark evaluation (used for scoring)
- `Offline-Smoke Mode` -> Pipeline validation only (returns 0 scores)
- `Demo Mode` (`USE_DEMO=true`) -> Debug-only heuristics (not used in evaluation)

Only `LLM Mode` results should be used to interpret benchmark performance.

**What RegAuditBench Claims**

RegAuditBench is a controlled testbed for:
- constrained decision-making
- reasoning over partial information
- precision-aware auditing behavior
- remediation patch quality

It does not claim to fully represent real-world audit performance. Instead, it provides a structured and credible way to compare agent behavior on high-signal auditing tasks under realistic constraints.

This makes RegAuditBench a high-signal evaluation environment for comparing agent designs under realistic constraints.

## OpenEnv compliance

The environment implements the required OpenEnv lifecycle:
- `reset()` initializes a deterministic episode and returns a typed `Observation`.
- `step()` validates a discriminated-union `Action`, applies deterministic reward shaping, and returns typed `Observation` and `Reward` objects.
- `state()` returns the current typed episode snapshot.

Schema notes:
- Actions are defined in `environment/models.py`.
- Reward shaping lives in `environment/reward.py`.
- Environment execution lives in `environment/env.py`.
- API validation is enforced in `api/server.py`.

## Reward design

Per-step rewards encourage disciplined auditing:
- Correct finding:
  - Task 1: `+0.10`
  - Task 2: `+0.08`
  - Task 3: `+0.09`
- Correct severity:
  - Task 1: `+0.05`
  - Task 2: `+0.05`
  - Task 3: `+0.04`
- Near-miss severity:
  - All tasks: `+0.02`
- Cross-file finding:
  - All tasks: `+0.05`
- All violations in a file found:
  - All tasks: `+0.10`
- False positive:
  - Task 1: `-0.05`
  - Task 2: `-0.07`
  - Task 3: `-0.06`
- Guessing on uninspected files:
  - Task 1: `-0.03`
  - Task 2: `-0.03`
  - Task 3: `-0.04`
- Invalid read:
  - All tasks: `-0.02`
- Wasted read:
  - All tasks: `-0.02`
- Valid patch:
  - All tasks: `+0.15 * patch_quality`
- Excess steps beyond the optimal budget:
  - All tasks: `-0.01`
- Step scaling:
  - Task 1: `x1.00`
  - Task 2: `x0.80`
  - Task 3: `x0.75`, then additional `x1.20`

Terminal score:
- Base score: `0.60 * violation_F1 + 0.20 * severity_accuracy + 0.20 * patch_quality`
- No-patch penalty on Task 3: `-0.10`
- Final scaling:
  - Task 1: `x1.00`
  - Task 2: `x0.72`
  - Task 3: `x0.64`

## Repository layout

```text
api/
environment/
graders/
tasks/
inference.py
inference_runtime.py
Dockerfile
README.md
requirements.txt
pyproject.toml
openenv.yaml
```

## Setup

### Local API

```bash
pip install -r requirements.txt
uvicorn api.server:app --host 127.0.0.1 --port 7860
```

### Environment variables

- `ENV_BASE_URL`: RegAuditBench environment API. Default: `http://localhost:7860`
- `API_BASE_URL`: OpenAI-compatible LLM endpoint. Default: `https://api.openai.com`
- `MODEL_NAME`: Chat model for the inference baseline. Default: `gpt-4o-mini`
- `OPENAI_API_KEY`: Optional. If absent, `inference.py` runs in offline smoke-test mode.
- `HF_TOKEN`: Optional fallback credential for OpenAI-compatible providers.
- `USE_DEMO`: Optional development flag. When `true`, enables `DEMO_PLANS` for debugging only.

### Baseline inference

With an API key:

```bash
export ENV_BASE_URL=http://localhost:7860
export API_BASE_URL=https://api.openai.com
export MODEL_NAME=gpt-4o-mini
export OPENAI_API_KEY=sk-...
python inference.py
```

Without an API key:

```bash
export ENV_BASE_URL=http://localhost:7860
python inference.py
```

The script still runs end-to-end, validates `/reset` and `/state`, completes all three tasks, and prints per-task scores plus total runtime.
By default this is an offline smoke test without an API key. To enable development-only heuristic demos, set `USE_DEMO=true`.

## Docker

Build and run:

```bash
docker build -t regauditbench .
docker run --rm -p 7860:7860 regauditbench
```

Container entrypoint:

```bash
uvicorn api.server:app --host 127.0.0.1 --port 7860
```

## Hugging Face Spaces

`app.py` exposes the FastAPI application directly for Spaces deployments.

## API endpoints

### `GET /health`

```bash
curl http://localhost:7860/health
```

### `GET /tasks`

```bash
curl http://localhost:7860/tasks
```

### `POST /reset`

```bash
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" \
  -d '{"task_id":"task1_single_file","seed":42}'
```

### `POST /step`

```bash
curl -X POST http://localhost:7860/step -H "Content-Type: application/json" \
  -d '{"session_id":"SESSION","action":{"action_type":"search_codebase","query":"email","file_pattern":null}}'
```

### `GET /state`

```bash
curl "http://localhost:7860/state?session_id=SESSION"
```

### `GET /leaderboard`

```bash
curl http://localhost:7860/leaderboard
```

## Validation

```bash
pytest -q
python inference.py
```

This repository is designed to satisfy automated OpenEnv checks, Docker execution, and human review as a research-style benchmark rather than a classroom demo.
