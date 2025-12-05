import pytest
from mini_sast.adapters.engines.regex_engine import RegexEngine
from mini_sast.domain.models import Severity

# Fixture: Instancia el motor una vez para usarlo en varios tests
@pytest.fixture
def engine():
    return RegexEngine()

def test_no_vulnerabilities_in_clean_code(engine):
    """Debe retornar una lista vacía si el código es seguro."""
    content = """
    def hello_world():
        print("Hello world")
        user_password = get_password_from_env() # Esto es seguro
    """
    results = engine.scan_file("safe_app.py", content)
    assert len(results) == 0

def test_detect_hardcoded_aws_key(engine):
    """Debe detectar una AWS Access Key simulada."""
    # AKIA... seguido de 16 caracteres es el patrón que definimos
    content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"' 
    
    results = engine.scan_file("config.py", content)
    
    assert len(results) == 1
    vuln = results[0]
    assert vuln.id == "SAST001"
    assert vuln.severity == Severity.HIGH
    assert vuln.location.line_number == 1
    assert "AWS Access Key" in vuln.name

def test_detect_hardcoded_password(engine):
    """Debe detectar asignaciones de variables tipo 'password'."""
    content = """
    def connect():
        user = "admin"
        password = "superSecretPassword123" # Vulnerable
    """
    
    results = engine.scan_file("db.py", content)
    
    assert len(results) == 1
    assert results[0].id == "SAST002"
    assert results[0].location.line_number == 4

def test_detect_multiple_issues(engine):
    """Debe encontrar múltiples vulnerabilidades en el mismo archivo."""
    content = """
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    password = "12345password"
    """
    results = engine.scan_file("bad.py", content)
    assert len(results) == 2