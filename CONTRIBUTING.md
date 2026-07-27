# Contributing Guidelines

Thank you for your interest in contributing to **PhishGuard AI**! 

To maintain production standards, please review the following guidelines:

## Development Workflow

1. **Fork the Repository**: Clone your fork locally.
2. **Setup Environment**:
   ```bash
   py -m venv .venv
   source .venv/Scripts/activate # On Windows
   pip install -r requirements.txt
   ```
3. **Branching**: Use descriptive branch names like `feature/improving-heuristics` or `bugfix/issue-12`.
4. **Code Quality**: Follow PEP8 standards and document all classes and services.
5. **Testing**: Run test validations before opening a pull request:
   ```bash
   pytest tests/
   ```
6. **Submit PR**: Open a pull request against the `main` branch. Provide a detailed description of changes.

## Security Vulnerability Reporting
For reporting security issues, please refer directly to our [SECURITY.md](file:///c:/Users/SANDILYA/OneDrive/Desktop/AI%20Phishing%20Detector/SECURITY.md) guidelines.
