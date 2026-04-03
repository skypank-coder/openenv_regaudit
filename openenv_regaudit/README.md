# RegAudit — Regulatory Compliance Auditing Environment

## Overview
RegAudit is an OpenEnv-compatible evaluation benchmark where an AI agent acts as a security auditor across realistic Python codebases. It measures multi-step reasoning, precise violation detection, and patch synthesis under strict read budgets. This environment focuses on compliance vulnerabilities (GDPR, OWASP, SOC2) and penalizes noise/false positives, which most existing benchmarks do not.

## Why this task is hard for LLM agents
- Strategic file budget allocation (cannot read all files)
- Cross-file violations requiring multi-hop data-flow reasoning
- False positive penalty rewards precision not just recall
- Severity classification penalizes "everything is critical" behavior
- Patch quality evaluated at AST level not string match

## What a well-trained agent on this environment can do
An agent that achieves >0.7 on Task 3 has demonstrated the ability to triage a 12-file codebase under information constraints, reason across service boundaries to identify tenant isolation failures, and generate syntactically valid Python remediation code — capabilities directly transferable to automated pre-deployment security review in CI/CD pipelines.

## Environment description

| Aspect | Type | Description |
| --- | --- | --- |
| State | `EpisodeState` | Complete episode data, codebase, findings, step counters |
| Action | discriminated union | Read/Search/Flag/Patch/Finalize actions |
| Observation | `Observation` | File metadata, framework rules, findings, remaining budget |
| Reward | per-step + terminal | Graded on correctness, severity, patches, time penalty |

## Action space

| action_type | fields | cost | description |
| --- | --- | --- | --- |
| read_file | path | 1 read budget | reveal source file content |
| search_codebase | query, file_pattern | free | regex search in any file(s) |
| flag_violation | file, line_start, line_end, rule_id, severity, description | free | report a compliance issue |
| propose_fix | finding_id, patch_code | free | submit code patch for a finding |
| finalize_audit | (none) | free | end episode and compute final metrics |

## Observation space

| field | type | description |
| --- | --- | --- |
| action_result | string | result text from last action |
| available_files | list[FileMetadata] | file names, line counts, imports, service tags |
| framework_rules | dict | active rules for task frameworks |
| current_findings | list[Finding] | agent-reported violations so far |
| file_reads_remaining | int | how many reads are left |
| step_count | int | number of actions taken so far |
| done | bool | terminal flag |

## Tasks

### Task 1 — easy: Single-file GDPR audit
- Domain: Flask routes.py
- Violations: 3 (GDPR)
- File budget: 3 reads / 1 file
- Expected score (gpt-4o-mini): 0.72
- Expected score (gpt-4o): 0.85

### Task 2 — medium: Django multi-regulation audit
- Domain: Django REST API (5 files)
- Violations: 8 (GDPR + OWASP)
- File budget: 7 reads / 5 files
- Expected score (gpt-4o-mini): 0.38
- Expected score (gpt-4o): 0.56

### Task 3 — hard: Microservices strategic audit
- Domain: 4 microservices (12 files)
- Violations: 15 (GDPR + OWASP + SOC2), 3 cross-file
- File budget: 7 reads / 12 files
- Expected score (gpt-4o-mini): 0.15
- Expected score (gpt-4o): 0.28
- Human expert: 0.75

## Reward structure

| Signal | per-step value |
| --- | --- |
| correct_violation | +0.10 |
| correct_severity | +0.05 |
| cross_file_violation | +0.05 |
| all_violations_in_file | +0.10 |
| false_positive | -0.05 |
| valid_patch | +0.15 * patch_quality_score |
| time_penalty | -0.01 per step beyond optimal |

Terminal: `0.60 * violation_F1 + 0.20 * severity_accuracy + 0.20 * patch_quality`

## Setup and usage

### Local development
```bash
git clone <repo_url>
cd openenv_regaudit
pip install -r requirements.txt
uvicorn api.server:app --host 0.0.0.0 --port 7860
```

### Docker
```bash
docker build -t regaudit .
docker run -p 7860:7860 regaudit
```

### Run baseline
```bash
export API_BASE_URL=http://localhost:7860
export MODEL_NAME=gpt-4o-mini
export OPENAI_API_KEY=sk-...
python inference.py
```

### Run tests
```bash
pytest tests/ -v
```

## API reference

### GET /health
```bash
curl http://localhost:7860/health
```

### GET /tasks
```bash
curl http://localhost:7860/tasks
```

### POST /reset
```bash
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" \
  -d '{"task_id":"task1_single_file","seed":42}'
```

### POST /step (read_file)
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"YOUR_SESSION_ID", "action": {"action_type": "read_file", "path": "routes.py"}}'
```

### POST /step (search_codebase)
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"YOUR_SESSION_ID", "action": {"action_type": "search_codebase", "query": "email", "file_pattern": "routes.py"}}'
```

### POST /step (flag_violation)
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"session_id": "YOUR_SESSION_ID", "action": {"action_type": "flag_violation", "file": "routes.py", "line_start": 45, "line_end": 47, "rule_id": "GDPR-ART5-1A", "severity": "high", "description": "User email logged to stdout"}}'
```

### POST /step (propose_fix)
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"YOUR_SESSION_ID", "action": {"action_type": "propose_fix", "finding_id": "F001", "patch_code": "# fix with parameterised query"}}'
```

### POST /step (finalize_audit)
```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"session_id":"YOUR_SESSION_ID", "action": {"action_type": "finalize_audit"}}'
```

### GET /state
```bash
curl "http://localhost:7860/state?session_id=<id>"
```

### POST /leaderboard/submit
```bash
curl -X POST http://localhost:7860/leaderboard/submit -H "Content-Type: application/json" \
  -d '{"session_id":"<id>","model_name":"gpt-4o-mini"}'
```

### GET /leaderboard
```bash
curl http://localhost:7860/leaderboard
```

## What a well-trained agent on this environment can do
A well-trained agent can efficiently prioritize file reads and identify compliance issues with precise line evidence, enabling security teams to focus remediation. It also learns to propose real patches that pass AST validation, reducing manual triage.

## Failure modes this environment exposes
- Over-flagging: agents that mark every file as violating score low due to false-positive penalty
- Pattern matching without context: search-only strategies miss cross-file violations
- Severity inflation: agents that mark everything critical get multiplier penalty in SeverityGrader
- Greedy reading: reading the largest files first rather than the highest-import-density files wastes the budget on Task 3

## Human baseline scores
task1_single_file: 0.95
task2_django_app: 0.91
task3_microservices: 0.74

*Note: Task 3 ceiling is deliberately below 1.0 due to the 7-read budget constraint over a 12-file codebase with 15 violations. Optimal file selection covers ~11 violations; remaining 4 are unreachable within budget.*
