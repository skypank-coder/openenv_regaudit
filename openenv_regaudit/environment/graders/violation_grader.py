from typing import List, Tuple

from environment.models import EpisodeState
from .base_grader import BaseGrader


class ViolationGrader(BaseGrader):
    def is_match(self, pred: dict, gt: dict, task_id: str) -> bool:
        if pred["file"] != gt["file"]:
            return False
        if pred["rule_id"] != gt["rule_id"]:
            return False

        if task_id == "task1_single_file":
            return (
                abs(pred["line_start"] - gt["line_start"]) <= 8 and
                abs(pred["line_end"] - gt["line_end"]) <= 8
            )

        if task_id == "task2_django_app":
            return abs(pred["line_start"] - gt["line_start"]) <= 5

        if task_id == "task3_microservices":
            return not (
                pred["line_end"] < gt["line_start"] or
                pred["line_start"] > gt["line_end"]
            )

        return abs(pred["line_start"] - gt["line_start"]) <= 5

    def _task3_credit(self, pred: dict, gt: dict) -> float:
        if pred["file"] != gt["file"] or pred["rule_id"] != gt["rule_id"]:
            return 0.0

        if not (
            pred["line_end"] < gt["line_start"] or
            pred["line_start"] > gt["line_end"]
        ):
            return 1.0

        if (
            abs(pred["line_start"] - gt["line_start"]) <= 5 or
            abs(pred["line_end"] - gt["line_end"]) <= 5
        ):
            return 0.75

        return 0.55

    def get_matched_pairs(self, state: EpisodeState) -> List[Tuple]:
        matched_pairs = []
        gt_items = [dict(gt) for gt in state.ground_truth] if hasattr(state, 'ground_truth') else []
        used_indices = set()
        task_id = getattr(state, "task_id", "")

        for finding in getattr(state, 'findings', []):
            best_idx = None
            pred = {
                "file": finding.file,
                "rule_id": finding.rule_id,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
            }
            for idx, gt in enumerate(gt_items):
                if idx in used_indices:
                    continue
                if self.is_match(pred, gt, task_id):
                    best_idx = idx
                    break
            if best_idx is not None:
                used_indices.add(best_idx)
                matched_pairs.append((finding, gt_items[best_idx]))

        return matched_pairs

    def score(self, state: EpisodeState) -> float:
        findings = getattr(state, 'findings', [])
        gt_items = [dict(gt) for gt in getattr(state, 'ground_truth', [])]
        matched_pairs = self.get_matched_pairs(state)
        task_id = getattr(state, "task_id", "")

        exact_credit = 0.0
        false_positives = 0.0
        weighted_tp = 0.0
        used_gt_ids = {id(gt) for _, gt in matched_pairs}

        for finding in findings:
            exact_match = None
            for matched_finding, gt in matched_pairs:
                if matched_finding is finding:
                    exact_match = gt
                    break

            if exact_match is not None:
                exact_credit += 1.0
                gt = exact_match
                weight = 2.0 if gt.get('severity') == 'critical' else 1.0
                if gt.get('cross_file'):
                    weight *= 1.5
                weighted_tp += weight
            else:
                pred = {
                    "file": finding.file,
                    "rule_id": finding.rule_id,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                }
                partial_credit = 0.0
                partial_gt = None

                if task_id == "task3_microservices":
                    best_credit = 0.0
                    for gt in gt_items:
                        if id(gt) in used_gt_ids:
                            continue
                        credit = self._task3_credit(pred, gt)
                        if credit > best_credit:
                            best_credit = credit
                            partial_gt = gt
                    partial_credit = best_credit

                if partial_credit > 0 and partial_gt is not None:
                    used_gt_ids.add(id(partial_gt))
                    exact_credit += partial_credit
                    weight = 2.0 if partial_gt.get('severity') == 'critical' else 1.0
                    if partial_gt.get('cross_file'):
                        weight *= 1.5
                    weighted_tp += partial_credit * weight
                else:
                    false_positives += 1.0

        precision = exact_credit / (exact_credit + false_positives) if (exact_credit + false_positives) > 0 else 0.0
        recall = exact_credit / len(gt_items) if len(gt_items) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        weighted_total = 0.0
        for gt in gt_items:
            weight = 2.0 if gt.get('severity') == 'critical' else 1.0
            if gt.get('cross_file'):
                weight *= 1.5
            weighted_total += weight

        weighted_recall = weighted_tp / weighted_total if weighted_total > 0 else 0.0

        final_score = 0.6 * f1 + 0.4 * weighted_recall
        return self._normalize(final_score)
