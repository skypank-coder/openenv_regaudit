import ast
import re
from typing import Tuple

from environment.models import EpisodeState
from .base_grader import BaseGrader

PATCH_PATTERNS = {
    "GDPR-ART5-1A": [
        (r"filter\(|exclude\(|sanitize\(", 0.3),
        (r"logging\.(info|debug|warning)(?!.*email)(?!.*phone)", 0.3),
        (r"str\(user\.id\)|user_id", 0.4),
    ],
    "OWASP-A03": [
        (r"parameterized|%s|:param|\?", 0.5),
        (r"filter\(|objects\.filter", 0.5),
    ],
    "GDPR-ART25": [
        (r"@limiter|rate_limit|RateLimit|throttle", 0.7),
        (r"limit\(", 0.3),
    ],
    "GDPR-ART32": [
        (r"os\.environ|environ\.get|getenv", 0.6),
        (r"SECRET_KEY\s*=\s*os\.", 0.4),
    ],
    "OWASP-A01": [
        (r"request\.user\.id|current_user\.id", 0.5),
        (r"== user_id|== pk|permission|authorize", 0.5),
    ],
    "OWASP-A04": [
        (r"allowed_extensions|ALLOWED_EXTENSIONS|\.endswith\(", 0.4),
        (r"mimetypes|magic\.|content_type", 0.3),
        (r"secure_filename|werkzeug", 0.3),
    ],
}

DANGEROUS_PATTERNS = ["os.system", "eval(", "exec(", "subprocess", "__import__"]


class PatchGrader(BaseGrader):
    def validate_single_patch(self, patch_code: str, rule_id: str) -> Tuple[float, str]:
        try:
            ast.parse(patch_code)
            ast_valid = True
        except SyntaxError as exc:
            return 0.0, f"Invalid syntax: {exc}"

        if any(pattern in patch_code for pattern in DANGEROUS_PATTERNS):
            return 0.0, "Dangerous pattern detected"

        patterns = PATCH_PATTERNS.get(rule_id)
        if not patterns:
            return 0.3, "No specific patterns for rule, partial credit"

        score = 0.0
        for patt, weight in patterns:
            if re.search(patt, patch_code):
                score += weight

        return min(score, 1.0), "scored"

    def score(self, state: EpisodeState) -> float:
        findings = getattr(state, 'findings', [])
        patch_scores = []

        for finding in findings:
            patch_code = getattr(finding, 'patch_code', None)
            if not patch_code:
                continue

            patch_score, _ = self.validate_single_patch(patch_code, finding.rule_id)
            patch_scores.append(patch_score)

        if not patch_scores:
            return 0.0

        avg_score = sum(patch_scores) / len(patch_scores)
        return self._normalize(avg_score)
