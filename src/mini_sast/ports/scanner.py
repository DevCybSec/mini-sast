from abc import ABC, abstractmethod
from typing import List
from mini_sast.domain.models import Vulnerability

class ScannerEngine(ABC):
    """
    Interface (Port) que cualquier motor de análisis debe implementar.
    """
    
    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        Analiza un solo archivo y retorna vulnerabilidades.
        """
        pass