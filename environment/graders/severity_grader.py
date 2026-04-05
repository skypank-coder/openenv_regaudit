from typing import List, Tuple

from environment.models import SEVERITY_LEVELS, EpisodeState
from .base_grader import BaseGrader
from .violation_grader import ViolationGrader


class SeverityGrader(BaseGrader):
    def score(self, state: EpisodeState) -> float:
        violation_grader = ViolationGrader()
        matched_pairs = violation_grader.get_matched_pairs(state)

        if not matched_pairs:
            return 0.0

        total_score = 0.0
        for finding, gt in matched_pairs:
            fsev = finding.severity
            gtsev = gt.get('severity')
            if fsev == gtsev:
                total_score += 1.0
            else:
                diff = abs(SEVERITY_LEVELS.get(fsev, 0) - SEVERITY_LEVELS.get(gtsev, 0))
                if diff == 1:
                    total_score += 0.5

        base_score = total_score / len(matched_pairs)

        total_findings = len(getattr(state, 'findings', []))
        critical_count = sum(1 for f in getattr(state, 'findings', []) if f.severity == 'critical')

        if total_findings > 0 and (critical_count / total_findings) > 0.7:
            base_score *= 0.8

        return self._normalize(base_score)
