from abc import ABC, abstractmethod
from typing import List
from mini_sast.domain.models import Vulnerability

class Reporter(ABC):
    @abstractmethod
    def report(self, vulnerabilities: List[Vulnerability], output_path: str = None) -> None:
        pass