"""
RegAudit OpenEnv - inference entry point with structured logging.
Imports the working agent from inference_runtime and wraps each task with 
[START]/[STEP]/[END] structured logs required by the hackathon validator.
"""

import os
import sys
import json
import time
from typing import Any, Dict

# Import the working agent from inference_runtime
from inference_runtime import (
    main as runtime_main,
    call_env as original_call_env,
    TASKS,
    MAX_RUNTIME_SECONDS,
    build_client,
    run_llm_task,
    run_offline_task,
    validate_environment,
)

# Global state for current task tracking
_current_task_id = None
_current_step_count = 0


def call_env_with_logging(endpoint: str, payload: dict[str, Any] | None = None, method: str = "post") -> dict[str, Any]:
    """Monkey-patched call_env that emits [STEP] logs for each step."""
    global _current_task_id, _current_step_count
    
    # Call the original function
    result = original_call_env(endpoint, payload, method)
    
    # Emit [STEP] log if this is a step response in a task
    if endpoint == "step" and _current_task_id is not None:
        _current_step_count += 1
        
        # Extract relevant info from the response
        action = payload.get("action", {}) if payload else {}
        action_type = action.get("action_type", "unknown")
        
        # Get reward info if available
        reward = result.get("reward", {})
        reward_value = reward.get("value", 0.0)
        done = result.get("done", False)
        
        print(
            f"[STEP] step={_current_step_count}"
            f" action={action_type}"
            f" reward={reward_value:.4f}"
            f" done={done}",
            flush=True,
        )
    
    return result


def run_task_with_logging(task_id: str, max_steps: int, use_offline: bool = False) -> dict[str, Any]:
    """Run a single task with structured logging wrapper."""
    global _current_task_id, _current_step_count
    
    # Reset task state
    _current_task_id = task_id
    _current_step_count = 0
    
    # Emit [START] log
    print(f"[START] task_id={task_id}", flush=True)
    
    try:
        # Run the actual task using the imported functions
        client = build_client()
        if use_offline:
            result = run_offline_task(task_id, max_steps)
        else:
            result = run_llm_task(client, task_id, max_steps)
        
        # Emit [END] log
        print(f"[END] task_id={task_id} score={result['score']:.4f} steps={result['steps']}", flush=True)
        return result
        
    except Exception as e:
        # Emit error [END] log
        print(f"[END] task_id={task_id} score=0.0000 steps=0 error={str(e)[:50]}", flush=True)
        return {"task_id": task_id, "score": 0.0, "steps": 0, "mode": "error"}
    finally:
        # Reset task state
        _current_task_id = None
        _current_step_count = 0


def main():
    """Main entry point that wraps the runtime logic with structured logging."""
    start = time.time()
    
    # Monkey-patch call_env to add logging
    import inference_runtime
    inference_runtime.call_env = call_env_with_logging
    
    # Environment validation with error handling
    try:
        validate_environment()
    except Exception as e:
        print(f"Environment validation failed: {e}")
        print("Continuing anyway - environment may still be starting up.")
    
    # Determine mode
    api_key = os.environ.get("HF_TOKEN") or os.environ.get("OPENAI_API_KEY")
    use_offline = not bool(api_key)
    
    if use_offline:
        print("[WARN] No API key found - running in offline mode", flush=True)
    else:
        print("[INFO] API key detected - running LLM agent", flush=True)
    
    # Run tasks with logging
    results = []
    for task_id, max_steps in TASKS:
        if time.time() - start >= MAX_RUNTIME_SECONDS:
            print(f"[WARN] Time budget exceeded, skipping {task_id}", flush=True)
            break
        
        try:
            result = run_task_with_logging(task_id, max_steps, use_offline)
        except Exception as e:
            print(f"[WARN] Task {task_id} failed: {e}", flush=True)
            result = {"task_id": task_id, "score": 0.0, "steps": 0, "mode": "error"}
        
        results.append(result)
    
    # Print final results
    elapsed = time.time() - start
    print(f"\nBASELINE RESULTS", flush=True)
    for result in results:
        print(f"  {result['task_id']:<30} score={result['score']:.4f}  steps={result['steps']}  mode={result.get('mode', 'unknown')}", flush=True)
    print(f"Total time: {elapsed:.1f}s", flush=True)


if __name__ == "__main__":
    main()
