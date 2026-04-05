from environment.graders.violation_grader import ViolationGrader
from environment.graders.severity_grader import SeverityGrader
from environment.graders.patch_grader import PatchGrader
from environment.models import EpisodeState, Finding, Severity
import pytest


def make_state(findings, ground_truth):
    """Helper: create a minimal EpisodeState for grader testing."""
    return EpisodeState(
        task_id="task1_single_file",
        codebase={"routes.py": ""},
        ground_truth=ground_truth,
        framework=["GDPR"],
        findings=findings,
        file_reads_remaining=3,
        max_steps=15,
    )


def make_finding(file, rule_id, severity, line_start=45):
    return Finding(id="F001", file=file, rule_id=rule_id, severity=Severity(severity),
                   description="test", line_start=line_start, line_end=line_start+2)


GT_ITEM = {"file": "routes.py", "rule_id": "GDPR-ART5-1A", "severity": "high",
           "line_start": 45, "line_end": 47}


class TestViolationGrader:
    def test_perfect_match_scores_high(self):
        finding = make_finding("routes.py", "GDPR-ART5-1A", "high", 45)
        state = make_state([finding], [GT_ITEM])
        score = ViolationGrader().score(state)
        assert score > 0.8

    def test_zero_findings_scores_zero(self):
        state = make_state([], [GT_ITEM])
        assert ViolationGrader().score(state) == 0.0

    def test_false_positive_only_scores_zero(self):
        finding = make_finding("routes.py", "OWASP-A03", "critical", 45)
        state = make_state([finding], [GT_ITEM])
        score = ViolationGrader().score(state)
        assert score == 0.0  # precision=0, recall=0

    def test_10_line_tolerance_accepted(self):
        finding = make_finding("routes.py", "GDPR-ART5-1A", "high", 54)  # 9 lines off
        state = make_state([finding], [GT_ITEM])
        score = ViolationGrader().score(state)
        assert score > 0.5

    def test_11_line_miss_not_matched(self):
        finding = make_finding("routes.py", "GDPR-ART5-1A", "high", 56)  # 11 lines off
        state = make_state([finding], [GT_ITEM])
        score = ViolationGrader().score(state)
        assert score == 0.0

    def test_same_gt_matched_once_only(self):
        """Two findings for same violation — only one should count as TP."""
        f1 = make_finding("routes.py", "GDPR-ART5-1A", "high", 45)
        f2 = make_finding("routes.py", "GDPR-ART5-1A", "high", 45)
        f2.id = "F002"
        state = make_state([f1, f2], [GT_ITEM])
        pairs = ViolationGrader().get_matched_pairs(state)
        assert len(pairs) == 1   # not 2

    def test_critical_gets_double_weight(self):
        """Critical GT item should produce higher weighted_recall than medium."""
        gt_critical = {**GT_ITEM, "severity": "critical"}
        gt_medium = {**GT_ITEM, "severity": "medium", "rule_id": "GDPR-ART25"}
        finding_c = make_finding("routes.py", "GDPR-ART5-1A", "critical", 45)
        finding_m = make_finding("routes.py", "GDPR-ART25", "medium", 45)
        state_both = make_state([finding_c, finding_m], [gt_critical, gt_medium])
        state_medium_only = make_state([finding_m], [gt_critical, gt_medium])
        score_both = ViolationGrader().score(state_both)
        score_medium = ViolationGrader().score(state_medium_only)
        assert score_both > score_medium

    def test_determinism(self):
        """Same inputs always produce same score."""
        finding = make_finding("routes.py", "GDPR-ART5-1A", "high", 45)
        state = make_state([finding], [GT_ITEM])
        scores = [ViolationGrader().score(state) for _ in range(5)]
        assert len(set(scores)) == 1


class TestSeverityGrader:
    def test_exact_severity_scores_one(self):
        finding = make_finding("routes.py", "GDPR-ART5-1A", "high", 45)
        state = make_state([finding], [GT_ITEM])
        score = SeverityGrader().score(state)
        assert score == pytest.approx(1.0)

    def test_adjacent_severity_scores_half(self):
        finding = make_finding("routes.py", "GDPR-ART5-1A", "critical", 45)  # one level off
        state = make_state([finding], [GT_ITEM])
        score = SeverityGrader().score(state)
        assert score == pytest.approx(0.4)  # 0.5 * 0.8 penalty for critical inflation

    def test_critical_inflation_penalty(self):
        """Agent marking everything critical gets 0.8x multiplier."""
        findings = [make_finding("routes.py", f"GDPR-ART5-1A", "critical", 45+i) for i in range(5)]
        for i, f in enumerate(findings): f.id = f"F{i:03d}"
        gt_items = [{"file": "routes.py", "rule_id": "GDPR-ART5-1A", "severity": "medium",
                     "line_start": 45, "line_end": 47}]
        state = make_state(findings[:1], gt_items)
        score = SeverityGrader().score(state)
        # All critical, GT is medium — penalty should apply
        # Score would be 0.5 (adjacent), with penalty if >70% critical: check it's <=0.5
        assert score <= 0.5


class TestPatchGrader:
    def test_ast_invalid_patch_scores_zero(self):
        pg = PatchGrader()
        score, reason = pg.validate_single_patch("def foo(: broken python", "GDPR-ART5-1A")
        assert score == 0.0
        assert "syntax" in reason.lower() or "invalid" in reason.lower()

    def test_dangerous_pattern_scores_zero(self):
        pg = PatchGrader()
        score, reason = pg.validate_single_patch("import os; os.system('rm -rf /')", "GDPR-ART5-1A")
        assert score == 0.0

    def test_good_gdpr_patch_scores_high(self):
        pg = PatchGrader()
        patch = "app.logger.info('User %s logged in', str(user.id))"
        score, _ = pg.validate_single_patch(patch, "GDPR-ART5-1A")
        assert score >= 0.4

    def test_good_sql_injection_fix_scores_high(self):
        pg = PatchGrader()
        patch = "User.objects.filter(username=username)"
        score, _ = pg.validate_single_patch(patch, "OWASP-A03")
        assert score >= 0.5

    def test_unknown_rule_gives_partial_credit(self):
        pg = PatchGrader()
        score, _ = pg.validate_single_patch("x = 1", "SOC2-CC7.2")
        assert score == pytest.approx(0.3)

    def test_empty_state_scores_zero(self):
        state = make_state([], [GT_ITEM])
        assert PatchGrader().score(state) == 0.0
