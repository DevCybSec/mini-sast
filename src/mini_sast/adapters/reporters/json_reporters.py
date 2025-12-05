import json
from typing import List
from pathlib import Path
from mini_sast.ports.reporter import Reporter
from mini_sast.domain.models import Vulnerability

class JsonReporter(Reporter):
    def report(self, vulnerabilities: List[Vulnerability], output_path: str = "sast-report.json") -> None:
        # Convertimos los objetos de dominio a diccionarios
        report_data = {
            "scan_summary": {
                "total_issues": len(vulnerabilities),
                "high_severity": sum(1 for v in vulnerabilities if v.severity.value == "HIGH")
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities]
        }
        
        # Escribimos al disco
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
            
        print(f"📄 JSON Report generated at: {Path(output_path).absolute()}")