import re
from typing import List, Pattern
from dataclasses import dataclass

from mini_sast.domain.models import Vulnerability, Severity, Location
from mini_sast.ports.scanner import ScannerEngine

@dataclass
class Rule:
    id: str
    name: str
    pattern: Pattern[str]
    severity: Severity
    description: str
    remediation: str

class RegexEngine(ScannerEngine):
    def __init__(self) -> None:
        # En un sistema real, estas reglas vendrían de un archivo YAML o JSON externo
        self.rules: List[Rule] = [
            Rule(
                id="SAST001",
                name="AWS Access Key Hardcoded",
                # Regex simplificado para detectar AKIA... (ID de AWS)
                pattern=re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
                severity=Severity.HIGH,
                description="Se detectó una AWS Access Key hardcodeada.",
                remediation="Usa variables de entorno o AWS Secrets Manager."
            ),
            Rule(
                id="SAST002",
                name="Generic Hardcoded Password",
                # Busca 'password = "..."' o variantes comunes
                pattern=re.compile(r"(password|passwd|pwd|secret)\s*[:=]\s*['\"][^\s]+['\"]", re.IGNORECASE),
                severity=Severity.MEDIUM,
                description="Posible contraseña en texto plano.",
                remediation="No guardes credenciales en el código fuente."
            )
        ]

    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        
        # Iteramos sobre cada línea para reportar el número de línea correcto
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            line_num = i + 1
            
            for rule in self.rules:
                # Buscamos coincidencias en la línea actual
                match = rule.pattern.search(line)
                if match:
                    vuln = Vulnerability(
                        id=rule.id,
                        name=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        location=Location(
                            file_path=file_path,
                            line_number=line_num,
                            column_number=match.start(),
                            snippet=line.strip()
                        ),
                        remediation=rule.remediation
                    )
                    vulnerabilities.append(vuln)
                    
        return vulnerabilities