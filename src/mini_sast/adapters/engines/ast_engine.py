import ast
from typing import List, Any
from mini_sast.domain.models import Vulnerability, Severity, Location
from mini_sast.ports.scanner import ScannerEngine

class SecurityVisitor(ast.NodeVisitor):
    """
    El 'Visitante' que recorre el árbol.
    Sobreescribimos métodos como 'visit_Call' para interceptar acciones específicas.
    """
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content_lines = content.splitlines()
        self.vulnerabilities: List[Vulnerability] = []

    def _get_snippet(self, lineno: int) -> str:
        """Helper para extraer la línea de código exacta del texto original."""
        try:
            return self.content_lines[lineno - 1].strip()
        except IndexError:
            return ""

    def visit_Call(self, node: ast.Call) -> None:
        """
        Se ejecuta automáticamente cada vez que el parser encuentra una llamada a función.
        Ej: eval(), print(), subprocess.Popen()
        """
        # Verificamos si la función llamada tiene un nombre simple (ej. 'eval')
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            
            # REGLA 1: Detección de 'eval' o 'exec'
            if func_name in ['eval', 'exec']:
                self.vulnerabilities.append(Vulnerability(
                    id="SAST003",
                    name=f"Dangerous Function Call ({func_name})",
                    description=f"Uso de '{func_name}' permite ejecución arbitraria de código.",
                    severity=Severity.HIGH,
                    location=Location(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        snippet=self._get_snippet(node.lineno)
                    ),
                    remediation="Evita ejecutar código dinámico. Usa 'ast.literal_eval' si necesitas parsear estructuras seguras."
                ))

        # Continúa recorriendo los hijos de este nodo (por si hay llamadas anidadas)
        self.generic_visit(node)

class AstEngine(ScannerEngine):
    """
    Implementación del puerto ScannerEngine usando el módulo AST de Python.
    """
    def scan_file(self, file_path: str, content: str) -> List[Vulnerability]:
        # Solo podemos analizar archivos .py
        if not file_path.endswith(".py"):
            return []

        try:
            # 1. Parsear el texto a un Árbol (AST)
            tree = ast.parse(content, filename=file_path)
            
            # 2. Instanciar nuestro visitante
            visitor = SecurityVisitor(file_path, content)
            
            # 3. Caminar el árbol
            visitor.visit(tree)
            
            return visitor.vulnerabilities
            
        except SyntaxError:
            # Si el archivo tiene errores de sintaxis, no podemos analizar su AST.
            # En un sistema real, podríamos loguear un warning.
            return []