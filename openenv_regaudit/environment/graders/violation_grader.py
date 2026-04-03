from typing import List, Tuple

from ..models import EpisodeState
from .base_grader import BaseGrader


class ViolationGrader(BaseGrader):
    def get_matched_pairs(self, state: EpisodeState) -> List[Tuple]:
        matched_pairs = []
        gt_items = [dict(gt) for gt in state.ground_truth] if hasattr(state, 'ground_truth') else []
        used_indices = set()

        for finding in getattr(state, 'findings', []):
            best_idx = None
            for idx, gt in enumerate(gt_items):
                if idx in used_indices:
                    continue
                if finding.file == gt.get('file') and finding.rule_id == gt.get('rule_id'):
                    if abs(finding.line_start - gt.get('line_start', 0)) <= 10:
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

        true_positives = len(matched_pairs)
        false_positives = 0
        for finding in findings:
            matched = False
            for matched_finding, _ in matched_pairs:
                if matched_finding is finding:
                    matched = True
                    break
            if not matched:
                false_positives += 1

        false_negatives = len(gt_items) - true_positives

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
        recall = true_positives / len(gt_items) if len(gt_items) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        weighted_tp = 0.0
        for _, gt in matched_pairs:
            weight = 2.0 if gt.get('severity') == 'critical' else 1.0
            if gt.get('cross_file'):
                weight *= 1.5
            weighted_tp += weight

        weighted_total = 0.0
        for gt in gt_items:
            weight = 2.0 if gt.get('severity') == 'critical' else 1.0
            if gt.get('cross_file'):
                weight *= 1.5
            weighted_total += weight

        weighted_recall = weighted_tp / weighted_total if weighted_total > 0 else 0.0

        final_score = 0.6 * f1 + 0.4 * weighted_recall
        return self._normalize(final_score)
