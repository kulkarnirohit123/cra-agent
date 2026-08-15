# Contributing to CRA-AGENT

Thank you for your interest in contributing to CRA-AGENT! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Types of Contributions

1. **Bug Reports**: Report bugs using GitHub Issues
2. **Feature Requests**: Suggest new features using GitHub Issues
3. **Code Contributions**: Submit pull requests for bug fixes or new features
4. **Documentation**: Improve documentation, tutorials, or examples
5. **Testing**: Add tests or improve test coverage

### Before You Start

1. Check existing issues to see if your contribution is already being worked on
2. For major changes, open an issue first to discuss the proposed changes
3. Fork the repository and create a feature branch

## Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/CRA-AGENT.git
cd CRA-AGENT

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Copy environment template
cp .env.example .env
# Edit .env with your configuration

# 5. Run tests
pytest

# 6. Run the dashboard
streamlit run src/dashboard/app.py
```

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines
- Use type hints for all function signatures
- Write docstrings for all public functions and classes
- Maximum line length: 100 characters
- Use `ruff` for linting and formatting

### Code Quality Tools

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type checking
mypy src/

# Run tests with coverage
pytest --cov=src --cov-report=html
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add support for trivy container scanning
fix(triage): correct severity classification for CVE-2024-1234
docs(readme): update installation instructions
```

## Pull Request Process

### Before Submitting

1. Ensure your code passes all tests: `pytest`
2. Ensure your code is properly formatted: `ruff format .`
3. Ensure your code passes linting: `ruff check .`
4. Update documentation if necessary
5. Add tests for new functionality

### Submitting a Pull Request

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "feat: add your feature"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Open a Pull Request on GitHub

### Pull Request Template

When opening a PR, please include:

- Description of changes
- Related issue number (if applicable)
- Screenshots (for UI changes)
- Testing performed

### Review Process

1. At least one maintainer will review your PR
2. Address any feedback or requested changes
3. Once approved, a maintainer will merge your PR

## Reporting Issues

### Bug Reports

When reporting a bug, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**: Python version, OS, package versions
6. **Logs/Screenshots**: Any relevant logs or screenshots

### Feature Requests

When requesting a feature, please include:

1. **Problem Statement**: What problem does this feature solve?
2. **Proposed Solution**: How should the feature work?
3. **Alternatives Considered**: Any alternative solutions you've considered
4. **Additional Context**: Any other relevant information

## Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Please email security concerns directly to: security@cra-agent.dev

## Questions?

- Open a [Discussion](https://github.com/kulkarnirohit123/cra-agent/discussions) on GitHub
- Check existing documentation in the `docs/` folder

## License

By contributing to CRA-AGENT, you agree that your contributions will be licensed under the Apache License 2.0.