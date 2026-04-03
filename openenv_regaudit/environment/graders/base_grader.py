from abc import ABC, abstractmethod

from environment.models import EpisodeState


class BaseGrader(ABC):
    @abstractmethod
    def score(self, state: EpisodeState) -> float:
        """Returns float 0.0–1.0"""
        pass

    def _normalize(self, value: float) -> float:
        return max(0.0, min(1.0, value))
