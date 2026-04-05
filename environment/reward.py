from typing import Dict, Tuple

from environment.models import Action, EpisodeState, SEVERITY_LEVELS
from environment.graders.violation_grader import ViolationGrader
from environment.graders.patch_grader import PatchGrader

OPTIMAL_STEPS = {"task1_single_file": 8, "task2_django_app": 18, "task3_microservices": 35}
VIOLATION_REWARDS = {"task1_single_file": 0.10, "task2_django_app": 0.08, "task3_microservices": 0.09}
SEVERITY_MATCH_BONUSES = {"task1_single_file": 0.05, "task2_django_app": 0.05, "task3_microservices": 0.04}
FALSE_POSITIVE_PENALTIES = {"task1_single_file": -0.05, "task2_django_app": -0.07, "task3_microservices": -0.06}
UNINSPECTED_GUESS_PENALTIES = {"task1_single_file": -0.03, "task2_django_app": -0.03, "task3_microservices": -0.04}
TASK_STEP_SCALES = {"task1_single_file": 1.0, "task2_django_app": 0.80, "task3_microservices": 0.75}
TASK_FINAL_SCALES = {"task1_single_file": 1.0, "task2_django_app": 0.72, "task3_microservices": 0.64}


class RewardShaper:
    def __init__(self, violation_grader: ViolationGrader, patch_grader: PatchGrader):
        self.vg = violation_grader
        self.pg = patch_grader
        self._found_violations: set = set()   # (file, rule_id) tuples already rewarded

    def compute_step_reward(
        self,
        action: Action,
        action_result: str,
        state: EpisodeState,
        violation_match: dict | None,     # None if not a flag_violation action, else ground truth match or None
        patch_score: float | None,        # None if not a propose_fix action
    ) -> Tuple[float, Dict[str, float]]:
        """
        Returns (reward_delta, breakdown_dict)
        breakdown_dict keys: "violation_found", "severity_bonus", "patch_reward",
                              "false_positive", "wasted_read", "time_penalty", "all_found_bonus"
        """
        delta = 0.0
        breakdown: Dict[str, float] = {}
        task_id = state.task_id
        violation_reward = VIOLATION_REWARDS.get(task_id, 0.10)
        severity_match_bonus = SEVERITY_MATCH_BONUSES.get(task_id, 0.05)
        false_positive_penalty = FALSE_POSITIVE_PENALTIES.get(task_id, -0.05)
        uninspected_guess_penalty = UNINSPECTED_GUESS_PENALTIES.get(task_id, -0.03)

        if action.action_type == "flag_violation":
            key = (action.file, action.rule_id)
            if violation_match is not None and key not in self._found_violations:
                # Correct violation found
                delta += violation_reward
                breakdown["violation_found"] = violation_reward
                self._found_violations.add(key)

                # Severity bonus
                agent_level = SEVERITY_LEVELS[action.severity.value]
                gt_level = SEVERITY_LEVELS[violation_match["severity"]]
                if agent_level == gt_level:
                    delta += severity_match_bonus
                    breakdown["severity_bonus"] = severity_match_bonus
                elif abs(agent_level - gt_level) == 1:
                    delta += 0.02
                    breakdown["severity_bonus"] = 0.02

                # Cross-file bonus (harder to find)
                if violation_match.get("cross_file"):
                    delta += 0.05
                    breakdown["cross_file_bonus"] = 0.05

                # All violations in a file found in one read bonus
                # Check if all GT violations for this file are now found
                gt_for_file = [g for g in state.ground_truth if g["file"] == action.file]
                found_for_file = [k for k in self._found_violations if k[0] == action.file]
                if len(found_for_file) == len(gt_for_file) and len(gt_for_file) >= 2:
                    delta += 0.10
                    breakdown["all_found_bonus"] = 0.10
            elif key in self._found_violations:
                # Duplicate finding — ignore, no penalty (agent might not know)
                breakdown["duplicate"] = 0.0
            else:
                # False positive
                delta += false_positive_penalty
                breakdown["false_positive"] = false_positive_penalty

            if action.file not in state.inspected_files:
                delta += uninspected_guess_penalty
                breakdown["uninspected_guess_penalty"] = uninspected_guess_penalty

        elif action.action_type == "read_file":
            # Penalize reads of files with no violations that aren't import-adjacent to violation files
            if action_result.startswith("ERROR"):
                delta -= 0.02
                breakdown["invalid_read"] = -0.02
            elif "AUDIT NOTE: No violations" in action_result:
                delta -= 0.02
                breakdown["wasted_read"] = -0.02
            # violation-adjacent check done in env.py, passed here via action_result annotation

        elif action.action_type == "propose_fix":
            if patch_score is not None:
                delta += 0.15 * patch_score
                breakdown["patch_reward"] = 0.15 * patch_score

        # Time penalty after optimal steps
        optimal = OPTIMAL_STEPS.get(state.task_id, 20)
        if state.step_count > optimal + 5:
            delta -= 0.01
            breakdown["time_penalty"] = -0.01

        delta *= TASK_STEP_SCALES.get(task_id, 1.0)
        if state.task_id == "task3_microservices":
            delta *= 1.2

        return round(delta, 4), breakdown

    def adjust_final_score(self, task_id: str, score: float) -> float:
        return round(max(0.0, score * TASK_FINAL_SCALES.get(task_id, 1.0)), 4)

    def reset(self):
        self._found_violations = set()
