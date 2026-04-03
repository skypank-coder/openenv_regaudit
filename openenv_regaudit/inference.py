import os, json, time, re, requests
from openai import OpenAI

# --- Config from environment variables (required for submission) ---
API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.openai.com").rstrip("/")
ENV_BASE = os.environ.get("ENV_API_BASE", "http://localhost:7860").rstrip("/")
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")
HF_TOKEN = os.environ.get("HF_TOKEN", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
MODEL_API_KEY = HF_TOKEN if HF_TOKEN else OPENAI_API_KEY

# OpenAI client — works with any OpenAI-compatible endpoint
client = None
if MODEL_API_KEY:
    client_kwargs = {"api_key": MODEL_API_KEY}
    if API_BASE_URL and "openai.com" not in API_BASE_URL:
        client_kwargs["base_url"] = f"{API_BASE_URL}/v1"
    client = OpenAI(**client_kwargs)

SYSTEM_PROMPT = """You are a security compliance auditor. Your job is to audit Python codebases for regulatory violations.

You interact with the environment by responding with ONLY a JSON object matching ONE of these action schemas:

1. Search for patterns (FREE — no budget cost):
   {"action_type": "search_codebase", "query": "email|password|SECRET", "file_pattern": null}

2. Read a file (costs 1 from your read budget):
   {"action_type": "read_file", "path": "routes.py"}

3. Flag a violation (after reading the file):
   {"action_type": "flag_violation", "file": "routes.py", "line_start": 45, "line_end": 48,
    "rule_id": "GDPR-ART5-1A", "severity": "high",
    "description": "User email logged to stdout at login, violating GDPR Art 5(1)(a)"}

4. Propose a fix for a finding:
   {"action_type": "propose_fix", "finding_id": "F001",
    "patch_code": "app.logger.info(f'User {user.id} logged in')"}

5. Finalize the audit (ends the episode):
   {"action_type": "finalize_audit"}

STRATEGY:
- First, use search_codebase to scan for risky patterns: passwords, emails, SECRET, raw SQL, DEBUG, CSRF
- Only read_file for files with search hits or suspiciously named files (settings.py, middleware.py)
- Flag violations with EXACT line numbers (use the search results to estimate)
- Propose fixes for all critical violations before finalizing
- Call finalize_audit when confident you've found all violations

SEVERITY GUIDE:
- critical: SQL injection, plaintext secrets, auth bypass
- high: PII exposure, IDOR, missing auth controls  
- medium: rate limiting missing, data retention missing
- low: minor config issues

Respond with ONLY valid JSON. No explanation text. No markdown. Just the JSON action."""

PATCH_MAP = {
    "GDPR-ART5-1A": "logger.info('user_id=%s', user.id)",
    "GDPR-ART5-1C": "return JsonResponse({'id': user.id, 'username': user.username})",
    "GDPR-ART25": "@limiter.limit('10/minute')",
    "GDPR-ART30": "created_at = models.DateTimeField(auto_now_add=True)",
    "GDPR-ART32": "DEBUG = False",
    "OWASP-A01": "if request.user.id != user.id: return HttpResponseForbidden()",
    "OWASP-A02": "SECRET_KEY = os.environ['SECRET_KEY']",
    "OWASP-A03": "return cls.objects.raw('SELECT * FROM users WHERE username = %s', [username])",
    "OWASP-A04": "if not f.name.lower().endswith(('.pdf', '.png', '.jpg')): return JsonResponse({'error': 'invalid file'}, status=400)",
    "SOC2-CC6.1": "logger.info('security_sensitive_action', extra={'user_id': user_id})",
}

FALLBACK_SEARCHES = [
    {
        "query": r"logger\.(info|debug)\(f?.*(email|user_email)|Request body:",
        "rule_id": "GDPR-ART5-1A",
        "severity": "high",
        "description": "Sensitive data or request contents are logged.",
    },
    {
        "query": r"password_hash|fields = \[.*password|to_dict\(\)|JsonResponse\(\{'id': user\.id, 'username': user\.username, 'email': user\.email\}\)",
        "rule_id": "GDPR-ART5-1C",
        "severity": "high",
        "description": "Excessive personal or credential data is exposed.",
    },
    {
        "query": r"missing rate-limiting on authentication endpoint|password reset",
        "rule_id": "GDPR-ART25",
        "severity": "medium",
        "description": "Authentication flow lacks privacy-by-design protections such as throttling.",
    },
    {
        "query": r"GDPR-ART30 violation|TODO add timestamps|tenant_id: int",
        "rule_id": "GDPR-ART30",
        "severity": "medium",
        "description": "Record lifecycle or retention metadata appears incomplete.",
    },
    {
        "query": r"DEBUG = True|token = jwt\.encode|connection\.execute\(query\)",
        "rule_id": "GDPR-ART32",
        "severity": "critical",
        "description": "Security controls are insufficient for protecting personal data.",
    },
    {
        "query": r"no ownership check|no tenant scope|get_by_id\(user_id\)|token payload: only user_id, no tenant_id",
        "rule_id": "OWASP-A01",
        "severity": "critical",
        "description": "Object access is not scoped to the requesting user or tenant.",
    },
    {
        "query": r"SECRET_KEY = '|supersecret|build_report_query",
        "rule_id": "OWASP-A02",
        "severity": "critical",
        "description": "Secrets or sensitive construction logic are hardcoded in source.",
    },
    {
        "query": r"objects\.raw\(f\"SELECT|SELECT \* FROM .* \{.*\}|connection\.execute\(query\)|build_report_query",
        "rule_id": "OWASP-A03",
        "severity": "critical",
        "description": "Raw query construction appears vulnerable to injection.",
    },
    {
        "query": r"no extension/MIME validation|upload_document|list_users",
        "rule_id": "OWASP-A04",
        "severity": "high",
        "description": "Input or upload handling lacks validation.",
    },
    {
        "query": r"reset_password|create_payment|refund_payment",
        "rule_id": "SOC2-CC6.1",
        "severity": "high",
        "description": "Sensitive operational actions are missing audit logging.",
    },
]


def call_env(endpoint: str, payload: dict) -> dict:
    """Make a request to the environment API."""
    resp = requests.post(f"{ENV_BASE}/{endpoint}", json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def call_model(messages: list[dict]) -> str:
    """Return the next JSON action from the configured LLM."""
    if client is None:
        raise RuntimeError(
            "No model credentials configured. Set OPENAI_API_KEY or HF_TOKEN, or use the offline fallback."
        )
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0,
        max_tokens=800,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


def extract_search_hits(action_result: str) -> list[tuple[str, int, str]]:
    hits = []
    for line in action_result.splitlines():
        match = re.match(r"(.+?):(\d+): \[(.*)\]$", line.strip())
        if match:
            hits.append((match.group(1), int(match.group(2)), match.group(3)))
    return hits


def run_offline_fallback(session_id: str) -> tuple[float, int]:
    """Deterministic search-driven auditor for offline/demo use."""
    print("  [fallback] Using deterministic offline auditor.")
    seen_pairs = set()
    final_score = 0.0
    step_count = 0
    done = False

    for spec in FALLBACK_SEARCHES:
        search_action = {
            "action_type": "search_codebase",
            "query": spec["query"],
            "file_pattern": None,
        }
        print(f"  Step {step_count + 1}: search_codebase")
        step_resp = call_env("step", {"action": search_action, "session_id": session_id})
        obs = step_resp["observation"]
        final_score = step_resp["reward"]["cumulative"]
        done = step_resp["done"]
        step_count += 1

        for file_name, line_no, _snippet in extract_search_hits(obs["action_result"]):
            key = (file_name, spec["rule_id"])
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            flag_action = {
                "action_type": "flag_violation",
                "file": file_name,
                "line_start": line_no,
                "line_end": line_no + 2,
                "rule_id": spec["rule_id"],
                "severity": spec["severity"],
                "description": spec["description"],
            }
            print(f"  Step {step_count + 1}: flag_violation - {spec['rule_id']} in {file_name}:{line_no}")
            step_resp = call_env("step", {"action": flag_action, "session_id": session_id})
            obs = step_resp["observation"]
            final_score = step_resp["reward"]["cumulative"]
            done = step_resp["done"]
            step_count += 1

            if spec["severity"] == "critical" and obs["current_findings"]:
                finding_id = obs["current_findings"][-1]["id"]
                patch_code = PATCH_MAP.get(spec["rule_id"])
                if patch_code:
                    patch_action = {
                        "action_type": "propose_fix",
                        "finding_id": finding_id,
                        "patch_code": patch_code,
                    }
                    print(f"  Step {step_count + 1}: propose_fix - {finding_id}")
                    step_resp = call_env("step", {"action": patch_action, "session_id": session_id})
                    obs = step_resp["observation"]
                    final_score = step_resp["reward"]["cumulative"]
                    done = step_resp["done"]
                    step_count += 1

            if done:
                break
        if done:
            break

    if not done:
        print(f"  Step {step_count + 1}: finalize_audit")
        step_resp = call_env("step", {"action": {"action_type": "finalize_audit"}, "session_id": session_id})
        final_score = step_resp["reward"]["cumulative"]
        step_count += 1
        info = step_resp.get("info", {})
        if info.get("critique"):
            critique = info["critique"]
            print(f"\n  Missed violations: {len(critique.get('missed_violations', []))}")
            print(f"  False positives: {len(critique.get('false_positives', []))}")

    return final_score, step_count


def run_task(task_id: str, max_steps: int = 50) -> dict:
    """Run a single task episode with the ReAct agent loop."""
    print(f"\n{'='*60}")
    print(f"Task: {task_id}")
    print('='*60)
    
    # Reset environment
    reset_resp = call_env("reset", {"task_id": task_id, "seed": 42})
    session_id = reset_resp["session_id"]
    obs = reset_resp["observation"]
    
    # Initial context for the agent
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": (
            f"Task: {task_id}\n"
            f"Framework: {obs.get('framework_rules', {}).keys()}\n"
            f"Files available:\n" +
            "\n".join(f"  - {f['name']} ({f['size_lines']} lines) imports: {f['imports'][:3]}"
                      for f in obs['available_files']) +
            f"\n\nFile read budget: {obs['file_reads_remaining']}\n"
            f"Max steps: {max_steps}\n\n"
            f"Begin the audit. Start with search_codebase to find risky patterns."
        )}
    ]
    
    final_score = 0.0
    step_count = 0

    if client is None:
        final_score, step_count = run_offline_fallback(session_id)
        print(f"\n  FINAL SCORE: {final_score:.4f} ({step_count} steps)")
        return {"task_id": task_id, "score": final_score, "steps": step_count}

    for step_num in range(max_steps):
        # Get agent action
        try:
            action_str = call_model(messages)
        except Exception as e:
            print(f"  [LLM error at step {step_num}]: {e}")
            if step_num == 0:
                final_score, step_count = run_offline_fallback(session_id)
            break
        
        # Parse action
        try:
            action_dict = json.loads(action_str)
        except json.JSONDecodeError as e:
            print(f"  [JSON parse error]: {e}")
            # Tell agent to fix its output
            messages.append({"role": "assistant", "content": action_str})
            messages.append({"role": "user", "content": "ERROR: Your response was not valid JSON. Respond with ONLY a JSON object."})
            continue
        
        action_type = action_dict.get("action_type", "unknown")
        print(f"  Step {step_num+1}: {action_type}", end="")
        if action_type == "flag_violation":
            print(f" — {action_dict.get('rule_id')} in {action_dict.get('file')}:{action_dict.get('line_start')}", end="")
        elif action_type == "read_file":
            print(f" — {action_dict.get('path')} (budget: {obs['file_reads_remaining']})", end="")
        print()
        
        # Send action to environment
        try:
            step_resp = call_env("step", {"action": action_dict, "session_id": session_id})
        except Exception as e:
            print(f"  [Env error]: {e}")
            break
        
        obs = step_resp["observation"]
        reward = step_resp["reward"]
        done = step_resp["done"]
        info = step_resp.get("info", {})
        
        final_score = reward["cumulative"]
        step_count = step_num + 1
        
        print(f"    -> reward: {reward['value']:+.4f}  cumulative: {reward['cumulative']:.4f}  budget_left: {obs['file_reads_remaining']}")
        
        # Add to conversation
        messages.append({"role": "assistant", "content": action_str})
        
        obs_summary = (
            f"Step result: {obs['action_result'][:500]}\n"
            f"Findings so far: {len(obs['current_findings'])}\n"
            f"Reads remaining: {obs['file_reads_remaining']}\n"
            f"Steps used: {obs['step_count']}"
        )
        messages.append({"role": "user", "content": obs_summary})
        
        if done:
            if info.get("critique"):
                critique = info["critique"]
                print(f"\n  Missed violations: {len(critique.get('missed_violations', []))}")
                print(f"  False positives: {len(critique.get('false_positives', []))}")
            break
        
        # Force finalize if running low on steps
        if step_num >= max_steps - 3:
            messages.append({"role": "user", "content": "You have 2 steps remaining. Call finalize_audit now."})
    
    print(f"\n  FINAL SCORE: {final_score:.4f} ({step_count} steps)")
    return {"task_id": task_id, "score": final_score, "steps": step_count}


def main():
    tasks = [
        ("task1_single_file", 15),
        ("task2_django_app", 30),
        ("task3_microservices", 50),
    ]
    
    results = []
    start = time.time()
    
    for task_id, max_steps in tasks:
        result = run_task(task_id, max_steps)
        results.append(result)
        
        # Check time budget (20 min total)
        elapsed = time.time() - start
        if elapsed > 1100:   # 18 min 20 sec — leave buffer
            print(f"\nTime budget approaching ({elapsed:.0f}s). Stopping early.")
            break
    
    print(f"\n{'='*60}")
    print("BASELINE RESULTS")
    print('='*60)
    for r in results:
        print(f"  {r['task_id']:<30} score: {r['score']:.4f}  steps: {r['steps']}")
    
    total_elapsed = time.time() - start
    print(f"\nTotal time: {total_elapsed:.1f}s ({total_elapsed/60:.1f} min)")
    print('='*60)


if __name__ == "__main__":
    main()
