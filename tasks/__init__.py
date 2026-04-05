"""Compatibility package exposing task fixtures at the repository root."""

from environment.tasks.task1_single_file import get_task as get_task1
from environment.tasks.task2_django_app import get_task as get_task2
from environment.tasks.task3_microservices import get_task as get_task3

__all__ = ["get_task1", "get_task2", "get_task3"]
