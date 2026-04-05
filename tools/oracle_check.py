#!/usr/bin/env python3
"""
Oracle validator: computes max achievable scores with optimal file selection.
"""

import sys
from itertools import combinations
from typing import Dict, List

# Add the project root to path
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from environment.tasks.task1_single_file import get_task as get_task1
from environment.tasks.task2_django_app import get_task as get_task2
from environment.tasks.task3_microservices import get_task as get_task3
from environment.graders.violation_grader import ViolationGrader
from environment.graders.severity_grader import SeverityGrader
from environment.graders.patch_grader import PatchGrader
from environment.models import EpisodeState, Finding, Severity


def get_perfect_patch(rule_id: str) -> str:
    """Return a perfect patch code for the rule."""
    patches = {
        "GDPR-ART5-1A": "app.logger.info('User %s logged in', str(user.id))",
        "GDPR-ART5-1C": "return jsonify({'user': user.to_dict()})",
        "GDPR-ART30": "# added created_at and updated_at fields",
        "GDPR-ART32": "# removed debug=True in production",
        "OWASP-A01": "# added user ownership check",
        "OWASP-A02": "# use environment variable for SECRET_KEY",
        "OWASP-A03": "User.objects.filter(username=username)",
        "OWASP-A04": "# added input validation",
        "SOC2-CC6.1": "# added authorization check",
    }
    return patches.get(rule_id, "x = 1")  # default for unknown


def compute_max_score(task_dict: Dict) -> float:
    """Compute max achievable score with optimal file reads."""
    ground_truth = task_dict['ground_truth']
    file_budget = task_dict['file_reads_remaining']
    total_violations = len(ground_truth)

    # Group violations by file
    violations_by_file = {}
    for gt in ground_truth:
        file = gt['file']
        if file not in violations_by_file:
            violations_by_file[file] = []
        violations_by_file[file].append(gt)

    files = list(violations_by_file.keys())
    num_files = len(files)

    # Find optimal file combination (up to budget) that covers most violations
    max_covered = 0
    optimal_files = []

    if num_files <= file_budget:
        # Can read all files
        max_covered = total_violations
        optimal_files = files
    else:
        # Try combinations
        for r in range(1, file_budget + 1):
            for combo in combinations(files, r):
                covered = sum(len(violations_by_file[f]) for f in combo)
                if covered > max_covered:
                    max_covered = covered
                    optimal_files = list(combo)

    covered_violations = max_covered

    # Simulate perfect agent: finds all violations in optimal files
    findings = []
    finding_id = 0
    for file in optimal_files:
        for gt in violations_by_file[file]:
            finding_id += 1
            # Add perfect patch
            patch_code = get_perfect_patch(gt['rule_id'])
            findings.append(Finding(
                id=f"F{finding_id:03d}",
                file=gt['file'],
                line_start=gt['line_start'],
                line_end=gt['line_end'],
                rule_id=gt['rule_id'],
                severity=Severity(gt['severity']),
                description=f"Perfect: {gt['rule_id']}",
                is_false_positive=False,
                patch_code=patch_code
            ))

    # Create mock state
    state = EpisodeState(
        task_id=task_dict['task_id'],
        codebase=task_dict['codebase'],
        ground_truth=ground_truth,
        framework=task_dict['framework'],
        findings=findings,
        file_reads_remaining=file_budget,
        max_steps=task_dict['max_steps'],
        search_count=0
    )

    # Compute scores
    v_grader = ViolationGrader()
    s_grader = SeverityGrader()
    p_grader = PatchGrader()

    v_score = v_grader.score(state)
    s_score = s_grader.score(state)
    p_score = p_grader.score(state)

    final_score = round(0.60 * v_score + 0.20 * s_score + 0.20 * p_score, 4)

    return final_score, covered_violations, total_violations, optimal_files


def main():
    tasks = [
        ("Task 1", get_task1()),
        ("Task 2", get_task2()),
        ("Task 3", get_task3()),
    ]

    all_passed = True

    for name, task in tasks:
        score, covered, total, files = compute_max_score(task)
        print(f"{name}: optimal {len(files)}-file combo covers {covered}/{total} violations (max score: {score:.2f})")
        if score < 0.45:
            print(f"ERROR: {name} max score {score:.2f} < 0.45 - task is impossible!")
            all_passed = False

    if not all_passed:
        sys.exit(1)

    print("All tasks have achievable scores >= 0.45")


if __name__ == "__main__":
    main()