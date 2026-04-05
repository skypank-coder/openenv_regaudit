from typing import Dict, List, Tuple

import random
import re

from environment.graders.patch_grader import PatchGrader
from environment.graders.severity_grader import SeverityGrader
from environment.graders.violation_grader import ViolationGrader
from environment.models import (
    Action,
    EpisodeState,
    FileMetadata,
    FinalizeAction,
    Finding,
    FlagViolationAction,
    Observation,
    ProposePatchAction,
    ReadFileAction,
    Reward,
    SearchCodebaseAction,
)
from environment.reward import RewardShaper
from environment.rules import ALL_RULES
from environment.tasks.task1_single_file import get_task as get_task1
from environment.tasks.task2_django_app import get_task as get_task2
from environment.tasks.task3_microservices import get_task as get_task3

TASK_LOADERS = {
    "task1_single_file": get_task1,
    "task2_django_app": get_task2,
    "task3_microservices": get_task3,
}

SEARCH_LIMITS = {"task1_single_file": 3, "task2_django_app": 3, "task3_microservices": 3}
LINE_TOLERANCES = {"task1_single_file": 10, "task2_django_app": 7, "task3_microservices": 5}


class RegAuditEnv:
    def __init__(self):
        self.state: EpisodeState | None = None
        self._violation_grader = ViolationGrader()
        self._severity_grader = SeverityGrader()
        self._patch_grader = PatchGrader()
        self.reward_shaper = RewardShaper(self._violation_grader, self._patch_grader)
        self._finding_counter = 0

    def reset(self, task_id: str, seed: int = 42) -> Observation:
        """Initialize a new episode. Returns the first observation."""
        if task_id not in TASK_LOADERS:
            raise ValueError(f"Unknown task_id: {task_id}. Must be one of {list(TASK_LOADERS.keys())}")

        task_config = TASK_LOADERS[task_id]()

        # Apply seed-based shuffling for variant generation
        rng = random.Random(seed)
        codebase = task_config["codebase"].copy()

        self.state = EpisodeState(
            task_id=task_id,
            codebase=codebase,
            ground_truth=task_config["ground_truth"],
            framework=task_config["framework"],
            findings=[],
            file_reads_remaining=task_config["file_reads_remaining"],
            max_steps=task_config["max_steps"],
            seed=seed,
            inspected_files=set(),
        )
        self._finding_counter = 0
        self.reward_shaper.reset()

        return self._build_observation("Episode started. Begin your audit.", initial=True)

    def step(self, action: Action) -> Tuple[Observation, Reward, bool, Dict]:
        """Process one action. Returns (observation, reward, done, info)."""
        assert self.state is not None, "Call reset() before step()"
        assert not self.state.done, "Episode is done. Call reset()."

        self.state.step_count += 1
        action_result = ""
        violation_match = None
        patch_score = None

        # --- Handle each action type ---

        if isinstance(action, ReadFileAction):
            if self.state.file_reads_remaining <= 0:
                action_result = "ERROR: File read budget exhausted. No reads remaining."
            elif action.path not in self.state.codebase:
                action_result = f"ERROR: File '{action.path}' not found. Available: {list(self.state.codebase.keys())}"
            else:
                content = self.state.codebase[action.path]
                action_result = content
                self.state.file_reads_remaining -= 1
                self.state.inspected_files.add(action.path)
                # Check if this was a "wasted" read (no violations in file)
                gt_files = {g["file"] for g in self.state.ground_truth}
                if action.path not in gt_files:
                    # Check if it's adjacent (imported by a violation file)
                    adjacent = self._is_adjacent_to_violation(action.path)
                    if not adjacent:
                        action_result += "\n\n[AUDIT NOTE: No violations found in this file]"

        elif isinstance(action, SearchCodebaseAction):
            if self.state.search_count >= SEARCH_LIMITS.get(self.state.task_id, 3):
                action_result = "Search budget exhausted. Use read_file to examine files directly."
            else:
                results = self._search_codebase(action.query, action.file_pattern)
                if results:
                    action_result = f"Search results for '{action.query}':\n" + "\n".join(results[:3])
                else:
                    action_result = f"No matches found for '{action.query}'"
                self.state.search_count += 1
            # Search is FREE (no budget cost)

        elif isinstance(action, FlagViolationAction):
            if action.file not in self.state.codebase:
                action_result = f"ERROR: File '{action.file}' does not exist in this codebase."
                violation_match = None
            elif action.rule_id not in ALL_RULES:
                action_result = f"ERROR: Unknown rule_id '{action.rule_id}'. Check framework_rules for valid IDs."
                violation_match = None
            else:
                # Find match in ground truth
                violation_match = self._find_ground_truth_match(action)
                self._finding_counter += 1
                finding_id = f"F{self._finding_counter:03d}"
                new_finding = Finding(
                    id=finding_id,
                    file=action.file,
                    line_start=action.line_start,
                    line_end=action.line_end,
                    rule_id=action.rule_id,
                    severity=action.severity,
                    description=action.description,
                    is_false_positive=(violation_match is None),
                )
                self.state.findings.append(new_finding)
                if violation_match:
                    action_result = f"Finding {finding_id} recorded: potential match for {action.rule_id} in {action.file}."
                else:
                    action_result = f"Finding {finding_id} recorded (flagged for review)."

        elif isinstance(action, ProposePatchAction):
            # Find the finding this patch is for
            finding = next((f for f in self.state.findings if f.id == action.finding_id), None)
            if finding is None:
                action_result = f"ERROR: Finding '{action.finding_id}' not found."
                patch_score = 0.0
            else:
                patch_score, reason = self._patch_grader.validate_single_patch(action.patch_code, finding.rule_id)
                finding.patch_code = action.patch_code
                action_result = f"Patch recorded for {action.finding_id}."

        elif isinstance(action, FinalizeAction):
            return self._finalize()

        # Compute step reward
        reward_delta, breakdown = self.reward_shaper.compute_step_reward(
            action, action_result, self.state, violation_match, patch_score
        )
        self.state.cumulative_reward += reward_delta

        # Check max steps
        if self.state.step_count >= self.state.max_steps:
            self.state.done = True

        obs = self._build_observation(action_result)
        reward = Reward(value=reward_delta, cumulative=self.state.cumulative_reward, breakdown=breakdown)
        return obs, reward, self.state.done, {}

    def get_state(self) -> Dict:
        """Returns current episode state as dict."""
        if self.state is None:
            return {"status": "not_started"}
        return self.state.model_dump()

    def _finalize(self) -> Tuple[Observation, Reward, bool, Dict]:
        """Compute final scores across all graders and end episode."""
        v_score = self._violation_grader.score(self.state)

        # Severity score only on matched pairs
        s_score = self._severity_grader.score(self.state)

        p_score = self._patch_grader.score(self.state)

        # Final combined score: violations 60%, severity 20%, patches 20%
        final_score = 0.60 * v_score + 0.20 * s_score + 0.20 * p_score
        if self.state.task_id == "task3_microservices" and p_score <= 0:
            final_score -= 0.10
        final_score = self.reward_shaper.adjust_final_score(self.state.task_id, final_score)

        # Update cumulative to final score (it's the authoritative terminal reward)
        self.state.cumulative_reward = final_score
        self.state.done = True

        critique = self._build_critique(v_score, s_score, p_score, self._violation_grader.get_matched_pairs(self.state))

        obs = self._build_observation(f"Audit finalized. Final score: {final_score:.4f}")
        reward = Reward(value=final_score, cumulative=final_score, breakdown={
            "violation_f1": v_score, "severity_accuracy": s_score, "patch_quality": p_score
        })
        return obs, reward, True, {"critique": critique, "final_score": final_score}

    def _search_codebase(self, query: str, file_pattern: str | None) -> List[str]:
        """Hint-only search that returns filenames without line numbers or code context."""
        if not query.strip():
            return []

        pattern = re.compile(query, re.IGNORECASE)
        hits: List[str] = []
        seen = set()

        for filename, content in self.state.codebase.items():
            if file_pattern and not re.search(file_pattern, filename):
                continue

            executable_lines = [
                line for line in content.split("\n")
                if not line.lstrip().startswith("#")
            ]
            if any(pattern.search(line) for line in executable_lines):
                if filename not in seen:
                    seen.add(filename)
                    hits.append(f"{filename}: match found")

        return hits[:3]

    def _find_ground_truth_match(self, action: FlagViolationAction) -> Dict | None:
        """Find matching ground truth entry with 10-line tolerance."""
        tolerance = LINE_TOLERANCES.get(self.state.task_id, 10)
        for gt in self.state.ground_truth:
            if (gt["file"] == action.file and
                gt["rule_id"] == action.rule_id and
                abs(gt["line_start"] - action.line_start) <= tolerance):
                return gt
        return None

    def _is_adjacent_to_violation(self, filename: str) -> bool:
        """Check if filename is imported by a file that contains violations."""
        violation_files = {g["file"] for g in self.state.ground_truth}
        base = filename.replace(".py", "").replace("/", ".")
        for vf in violation_files:
            content = self.state.codebase.get(vf, "")
            if base in content or filename.split("/")[-1].replace(".py", "") in content:
                return True
        return False

    def _build_observation(self, action_result: str, initial: bool = False) -> Observation:
        available_files = []
        for fname, content in self.state.codebase.items():
            lines = content.split('\n')
            imports = [l.strip() for l in lines[:30] if l.startswith('import') or l.startswith('from')][:8]
            # Detect service from path
            service = fname.split('/')[0] if '/' in fname else None
            available_files.append(FileMetadata(
                name=fname,
                size_lines=len(lines),
                imports=imports,
                service=service,
            ))

        # Filter rules to only the frameworks active for this task
        active_rules = {
            rid: spec for rid, spec in ALL_RULES.items()
            if any(fw in rid for fw in self.state.framework)
        }

        return Observation(
            action_result=action_result,
            available_files=available_files,
            framework_rules=active_rules,
            current_findings=[f.model_dump() for f in self.state.findings],
            file_reads_remaining=self.state.file_reads_remaining,
            step_count=self.state.step_count,
            done=self.state.done,
        )

    def _build_critique(self, v_score, s_score, p_score, matched_pairs) -> Dict:
        found_ids = {(f.file, f.rule_id) for f in self.state.findings if not f.is_false_positive}
        missed = [g for g in self.state.ground_truth if (g["file"], g["rule_id"]) not in found_ids]
        fps = [f for f in self.state.findings if f.is_false_positive]
        return {
            "violation_score": v_score,
            "severity_score": s_score,
            "patch_score": p_score,
            "missed_violations": [{"file": m["file"], "rule_id": m["rule_id"], "severity": m["severity"]} for m in missed],
            "false_positives": [{"file": f.file, "rule_id": f.rule_id} for f in fps],
            "total_found": len(matched_pairs),
            "total_possible": len(self.state.ground_truth),
        }
