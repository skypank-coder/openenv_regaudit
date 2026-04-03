from environment.env import RegAuditEnv
from environment.models import (ReadFileAction, SearchCodebaseAction, FlagViolationAction,
                                 ProposePatchAction, FinalizeAction, Severity)
import pytest


@pytest.fixture
def env():
    return RegAuditEnv()


class TestReset:
    def test_reset_task1_returns_observation(self, env):
        obs = env.reset("task1_single_file")
        assert obs.done is False
        assert obs.file_reads_remaining == 3
        assert obs.step_count == 0
        assert len(obs.available_files) == 1
        assert obs.available_files[0].name == "routes.py"
        assert len(obs.framework_rules) > 0

    def test_reset_task2_has_five_files(self, env):
        obs = env.reset("task2_django_app")
        assert len(obs.available_files) == 5
        assert obs.file_reads_remaining == 7

    def test_reset_task3_has_twelve_files(self, env):
        obs = env.reset("task3_microservices")
        assert len(obs.available_files) == 12
        assert obs.file_reads_remaining == 7

    def test_reset_clears_previous_state(self, env):
        env.reset("task1_single_file")
        env.step(ReadFileAction(action_type="read_file", path="routes.py"))
        obs = env.reset("task1_single_file")
        assert obs.file_reads_remaining == 3
        assert len(obs.current_findings) == 0

    def test_invalid_task_id_raises(self, env):
        with pytest.raises(ValueError, match="Unknown task_id"):
            env.reset("nonexistent_task")


class TestReadFile:
    def test_read_file_returns_content(self, env):
        env.reset("task1_single_file")
        obs, reward, done, info = env.step(ReadFileAction(action_type="read_file", path="routes.py"))
        assert "routes.py" in obs.action_result or "def " in obs.action_result
        assert obs.file_reads_remaining == 2
        assert done is False

    def test_read_file_decrements_budget(self, env):
        env.reset("task1_single_file")
        for _ in range(3):
            env.step(ReadFileAction(action_type="read_file", path="routes.py"))
        obs, _, _, _ = env.step(ReadFileAction(action_type="read_file", path="routes.py"))
        assert "ERROR" in obs.action_result
        assert "budget" in obs.action_result.lower()

    def test_read_nonexistent_file_returns_error(self, env):
        env.reset("task1_single_file")
        obs, reward, done, info = env.step(ReadFileAction(action_type="read_file", path="does_not_exist.py"))
        assert "ERROR" in obs.action_result
        # Invalid reads do not decrement budget; error branch never hits budget decrement
        assert obs.file_reads_remaining == 3


class TestSearch:
    def test_search_finds_pattern(self, env):
        env.reset("task1_single_file")
        obs, _, _, _ = env.step(SearchCodebaseAction(action_type="search_codebase", query="email"))
        assert "routes.py" in obs.action_result

    def test_search_does_not_cost_budget(self, env):
        env.reset("task1_single_file")
        for _ in range(10):
            obs, _, _, _ = env.step(SearchCodebaseAction(action_type="search_codebase", query="def "))
        assert obs.file_reads_remaining == 3


class TestFlagViolation:
    def test_correct_violation_gives_positive_reward(self, env):
        env.reset("task1_single_file")
        env.step(ReadFileAction(action_type="read_file", path="routes.py"))
        gt = env.state.ground_truth[0]
        obs, reward, done, info = env.step(FlagViolationAction(
            action_type="flag_violation",
            file=gt["file"],
            line_start=gt["line_start"], line_end=gt["line_end"],
            rule_id=gt["rule_id"],
            severity=Severity.HIGH,
            description="Email logged to stdout"
        ))
        assert reward.value > 0

    def test_false_positive_gives_negative_reward(self, env):
        env.reset("task1_single_file")
        obs, reward, done, info = env.step(FlagViolationAction(
            action_type="flag_violation",
            file="routes.py",
            line_start=1, line_end=5,
            rule_id="OWASP-A03",
            severity=Severity.CRITICAL,
            description="Fake SQL injection"
        ))
        assert reward.value < 0

    def test_unknown_rule_id_returns_error(self, env):
        env.reset("task1_single_file")
        obs, _, _, _ = env.step(FlagViolationAction(
            action_type="flag_violation",
            file="routes.py", line_start=1, line_end=2,
            rule_id="FAKE-RULE-999",
            severity=Severity.HIGH,
            description="test"
        ))
        assert "ERROR" in obs.action_result


class TestFinalize:
    def test_finalize_ends_episode(self, env):
        env.reset("task1_single_file")
        obs, reward, done, info = env.step(FinalizeAction(action_type="finalize_audit"))
        assert done is True
        assert "final_score" in info
        assert 0.0 <= info["final_score"] <= 1.0

    def test_finalize_returns_critique(self, env):
        env.reset("task1_single_file")
        _, _, _, info = env.step(FinalizeAction(action_type="finalize_audit"))
        assert "critique" in info
        critique = info["critique"]
        assert "missed_violations" in critique
        assert "false_positives" in critique

    def test_perfect_task1_scores_high(self, env):
        env.reset("task1_single_file")
        gt = env.state.ground_truth
        for v in gt:
            env.step(FlagViolationAction(
                action_type="flag_violation",
                file=v["file"], line_start=v["line_start"], line_end=v["line_end"],
                rule_id=v["rule_id"], severity=Severity(v["severity"]),
                description=f"Test: {v['rule_id']}"
            ))
        _, reward, _, info = env.step(FinalizeAction(action_type="finalize_audit"))
        assert info["final_score"] >= 0.55, f"Perfect agent scored {info['final_score']}"


class TestEpisodeBoundaries:
    def test_max_steps_terminates_episode(self, env):
        env.reset("task1_single_file")
        done = False
        for _ in range(20):
            _, _, done, _ = env.step(SearchCodebaseAction(action_type="search_codebase", query="x"))
            if done:
                break
        assert done is True

    def test_step_after_done_raises(self, env):
        env.reset("task1_single_file")
        env.step(FinalizeAction(action_type="finalize_audit"))
        with pytest.raises(AssertionError):
            env.step(SearchCodebaseAction(action_type="search_codebase", query="test"))
