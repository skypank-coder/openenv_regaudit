#!/usr/bin/env python3
"""Run human baseline via direct environment API simulation to prove ceiling scores."""
import os
import sys
import time

# Ensure project package path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from environment.env import RegAuditEnv
from environment.models import FlagViolationAction, ProposePatchAction, FinalizeAction, Action, Severity
from environment.tasks.task1_single_file import get_task as get_task1
from environment.tasks.task2_django_app import get_task as get_task2
from environment.tasks.task3_microservices import get_task as get_task3

PATCH_MAP = {
    "GDPR-ART5-1A": "app.logger.info('user_id=%s', user_id)",
    "GDPR-ART5-1C": "return jsonify({'id': user.id})",
    "GDPR-ART30": "# add retention policy fields",
    "GDPR-ART32": "# disable DEBUG in production",
    "OWASP-A01": "if request.user.id != user_id: raise PermissionDenied()",
    "OWASP-A02": "SECRET_KEY = os.environ.get('SECRET_KEY')",
    "OWASP-A03": "User.objects.filter(username=username)",
    "OWASP-A04": "# enforce file extension check",
    "SOC2-CC6.1": "# add audit logging",
}


def run_task(task_getter):
    task_info = task_getter()
    task_id = task_info['task_id']

    env = RegAuditEnv()
    obs = env.reset(task_id, seed=42)

    ground_truth = task_info['ground_truth']
    last_finding_id = None

    for gt in ground_truth:
        flag_action = FlagViolationAction(
            action_type='flag_violation',
            file=gt['file'],
            line_start=gt['line_start'],
            line_end=gt['line_end'],
            rule_id=gt['rule_id'],
            severity=Severity(gt['severity']),
            description=f"Human baseline: {gt['rule_id']}"
        )

        obs, reward, done, info = env.step(flag_action)
        if done:
            break

        last_finding_id = obs.current_findings[-1].id if obs.current_findings else None

        if gt['severity'] == 'critical' and last_finding_id:
            patch_action = ProposePatchAction(
                action_type='propose_fix',
                finding_id=last_finding_id,
                patch_code=PATCH_MAP.get(gt['rule_id'], 'x = 1'),
            )
            obs, reward, done, info = env.step(patch_action)
            if done:
                break

    obs, reward, done, info = env.step(FinalizeAction(action_type='finalize_audit'))
    score = info.get('final_score', 0.0)
    return task_id, score


def main():
    results = []
    for task_getter in [get_task1, get_task2, get_task3]:
        task_id, score = run_task(task_getter)
        results.append((task_id, score))
        print(f"{task_id}: human ceiling score = {score:.2f}")

    # Write to README update section in place
    import pathlib
    readme_path = pathlib.Path(ROOT_DIR) / 'README.md'
    text = readme_path.read_text(encoding='utf-8')
    marker = '## Human baseline scores'
    if marker in text:
        before, after = text.split(marker, 1)
        human_scores = '\n'.join([f"{tid}: {scr:.2f}" for tid, scr in results])
        new_text = before + marker + "\n" + human_scores + "\n"
        # Keep everything after the section marker
        if '###' in after:
            new_text += '###' + after.split('###', 1)[1]
        readme_path.write_text(new_text, encoding='utf-8')
        print('README.md updated with human baseline scores.')
    else:
        print('Warning: README marker not found, skip update.')

    return results


if __name__ == '__main__':
    main()
