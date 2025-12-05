# 🛡️ Mini-SAST Scanner

![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-hexagonal-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-blue)

A robust, modular, and type-safe **Static Application Security Testing (SAST)** tool designed to detect security vulnerabilities in code.

Unlike simple regex scripts, Mini-SAST leverages **Abstract Syntax Trees (AST)** to understand code structure, reducing false positives and enabling context-aware detection. Built with **Hexagonal Architecture** to ensure maintainability and testability.

## 🚀 Key Features

* **Multi-Engine Analysis**:
    * 🕵️ **Regex Engine**: Fast detection of secrets (AWS Keys, tokens) and simple patterns.
    * 🧠 **AST Engine**: Deep analysis of Python code structure to detect dangerous function calls (e.g., `eval()`, `exec()`) and insecure logic.
* **Hexagonal Architecture**: Complete decoupling between the Core Domain, Interfaces (Ports), and Infrastructure (Adapters).
* **CI/CD Integration**: Native support for GitHub Actions and JSON reporting for pipeline blocking.
* **Developer Friendly**: Beautiful CLI output using `Rich` and strict type checking with `Mypy`.

## 🏗️ Architecture

This project follows the **Ports and Adapters (Hexagonal)** pattern to isolate the business logic from external concerns.

```text
src/mini_sast/
├── domain/       # 🧠 The Core: Vulnerability Models & Rules (Pure Python)
├── ports/        # 🔌 The Contracts: Scanner & Reporter Interfaces (ABC)
└── adapters/     # 🛠️ The Implementation:
    ├── cli/      #     -> Typer/Rich (User Interface)
    ├── fs/       #     -> File System Walker (IO)
    ├── engines/  #     -> Regex & AST Logic (Analysis)
    └── reporters/#     -> JSON & Console Output
````

## 📦 Usage

### Option A: As a GitHub Action (Recommended)

Add this to your `.github/workflows/security.yml` to scan your repo on every push:

```yaml
steps:
  - uses: actions/checkout@v3
  
  - name: Run Mini-SAST
    uses: DevCybSec/mini-sast@v1
    with:
      path: '.'
      output: 'sast-report.json'
      
  - name: Upload Report
    if: always()
    uses: actions/upload-artifact@v3
    with:
      name: security-report
      path: sast-report.json
```

### Option B: Local CLI

1.  **Install with Poetry**:

    ```bash
    git clone [https://github.com/DevCybSec/mini-sast.git](https://github.com/DevCybSec/mini-sast.git)
    cd mini-sast
    poetry install
    ```

2.  **Run the scanner**:

    ```bash
    # Scan the current directory
    poetry run mini-sast .

    # Scan specific folder and output JSON
    poetry run mini-sast ./src --output report.json
    ```

## 🛡️ Supported Rules

| ID      | Severity | Description | Engine |
|:--------|:---------|:------------|:-------|
| SAST001 | HIGH     | AWS Access Key Hardcoded | Regex |
| SAST002 | MEDIUM   | Generic Hardcoded Password | Regex |
| SAST003 | HIGH     | Dangerous Function Call (`eval`, `exec`) | AST |

## 🧪 Development & Testing

We enforce code quality with strict type checking and unit tests.

```bash
# Run Unit Tests
poetry run pytest

# Run Type Checking (Strict Mode)
poetry run mypy .
```

## 👤 Author

**Edgar Macias** - *Software Security Engineer*

