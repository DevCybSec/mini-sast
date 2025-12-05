import typer
from pathlib import Path
from typing import List
from rich.console import Console
from rich.table import Table
from rich.progress import track

from mini_sast.adapters.engines.regex_engine import RegexEngine
from mini_sast.adapters.engines.ast_engine import AstEngine
from mini_sast.domain.models import Vulnerability, Severity

# Inicializamos la app y la consola
app = typer.Typer(name="mini-sast", help="Simple Static Application Security Testing Tool")
console = Console()

def print_console_report(vulnerabilities: List[Vulnerability]) -> None:
    """Renderiza una tabla bonita con los hallazgos."""
    if not vulnerabilities:
        console.print("[bold green]✅ No issues found. Your code looks clean![/bold green]")
        return

    table = Table(title=f"Security Scan Report ({len(vulnerabilities)} issues found)")

    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta")
    table.add_column("Location", style="white")
    table.add_column("Message", style="red")

    for vuln in vulnerabilities:
        # Coloreamos la severidad
        severity_style = "red" if vuln.severity == Severity.HIGH else "yellow"
        
        loc_str = f"{vuln.location.file_path}:{vuln.location.line_number}"
        
        table.add_row(
            vuln.id,
            f"[{severity_style}]{vuln.severity.value}[/{severity_style}]",
            loc_str,
            vuln.name
        )

    console.print(table)

@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, help="Directory or file to scan"),
    ignore_dirs: List[str] = typer.Option(
        [".git", "node_modules", "__pycache__", ".venv", "venv"], 
        help="Directories to ignore"
    )
):
    """
    Scans a directory for security vulnerabilities using Regex patterns.
    """
    engines = [RegexEngine(), AstEngine()]
    walker = FileSystemWalker(ignore_dirs)
    all_vulns: List[Vulnerability] = []
    
    console.print(f"[bold blue]🔍 Enumerating files in {path}...[/bold blue]")
    files = list(walker.get_files(path))

    for file_path in track(files, description="Scanning..."):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for engine in engines:
                vulns = engine.scan_file(str(file_path), content)
                all_vulns.extend(vulns)
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not scan {file_path}: {e}[/yellow]")

    print_console_report(all_vulns)

    # Generar reporte JSON si se especifica
    if output:
        json_reporter = JsonReporter()
        json_reporter.report(all_vulns, output_path=output)

    # Exit code para CI/CD (fallar si hay vulnerabilidades HIGH)
    if any(v.severity == Severity.HIGH for v in all_vulns):
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()