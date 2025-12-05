from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass(frozen=True)
class Location:
    file_path: str
    line_number: int
    column_number: int = 0
    snippet: Optional[str] = None

@dataclass(frozen=True)
class Vulnerability:
    id: str
    name: str
    description: str
    severity: Severity
    location: Location
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "file": self.location.file_path,
            "line": self.location.line_number,
            "snippet": self.location.snippet
        }