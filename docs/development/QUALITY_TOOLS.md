# Code Quality Tools Documentation

This document provides comprehensive information about the code quality tools configured for the AuthOS project.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Tools Configuration](#tools-configuration)
- [Running Quality Checks](#running-quality-checks)
- [IDE Integration](#ide-integration)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## Overview

AuthOS uses multiple code quality tools to ensure consistent, secure, and maintainable code:

| Tool | Purpose | Level/Version |
|------|---------|---------------|
| PHP CS Fixer | Code style and formatting | PSR-12 + Laravel |
| Laravel Pint | Laravel-specific code style | Laravel conventions |
| PHPStan | Static analysis | Level 5 |
| Larastan | Laravel-specific static analysis | v3.7 |
| Psalm | Alternative static analysis | Latest |
| PHPMD | Code complexity and mess detection | 2.15 |
| PHP Insights | Code quality metrics | Latest |
| PHPUnit | Testing framework | 11.5 |
| Composer Audit | Security vulnerability scanning | Built-in |

## Quick Start

### Run All Quality Checks

```bash
herd composer quality
```

This runs:
- PHP CS Fixer (check mode)
- PHPStan analysis
- PHPMD analysis
- Psalm analysis

### Fix Code Style Issues

```bash
herd composer quality:fix
```

This runs:
- PHP CS Fixer (fix mode)
- Laravel Pint

### Run Tests with Coverage

```bash
herd composer test:coverage
```

## Tools Configuration

### PHP CS Fixer

**Configuration**: `.php-cs-fixer.php`

Features:
- PSR-12 compliance
- PHP 8.4 migration rules
- Laravel conventions
- Automatic import ordering
- Strict type checking

**Usage**:
```bash
# Check code style
herd composer cs:check

# Fix code style
herd composer cs:fix

# Fix specific file
herd php vendor/bin/php-cs-fixer fix app/Models/User.php
```

**Cache**: `.php-cs-fixer.cache` (gitignored)

### Laravel Pint

**Configuration**: Uses default Laravel conventions

**Usage**:
```bash
# Fix all files
herd composer pint

# Check without fixing
herd composer pint:test

# Fix specific directory
herd php vendor/bin/pint app/Models
```

### PHPStan / Larastan

**Configuration**: `phpstan.neon`

**Level**: 5 (0-10 scale, 10 being strictest)

Features:
- Laravel-aware analysis
- Model property checking
- Octane compatibility checking
- Custom ignore patterns for common Laravel patterns

**Usage**:
```bash
# Run analysis
herd composer analyse

# Generate baseline (ignore existing issues)
herd composer analyse:baseline

# Analyze specific path
herd php vendor/bin/phpstan analyse app/Services --level=6
```

**Memory**: Configured for 1GB, increase if needed:
```bash
herd php vendor/bin/phpstan analyse --memory-limit=2G
```

### Psalm

**Configuration**: `psalm.xml` (auto-generated)

**Usage**:
```bash
# Run analysis
herd composer psalm

# Generate baseline
herd composer psalm:baseline

# Show more info
herd php vendor/bin/psalm --show-info=true
```

### PHPMD (PHP Mess Detector)

**Configuration**: `phpmd.xml`

Checks for:
- Code complexity (cyclomatic, NPath)
- Excessive method/class length
- Unused code
- Naming conventions
- Design issues

**Usage**:
```bash
# Run analysis
herd composer phpmd

# Analyze specific path
herd php vendor/bin/phpmd app/Models text phpmd.xml

# Output to HTML
herd php vendor/bin/phpmd app html phpmd.xml > phpmd-report.html
```

### PHP Insights

**Configuration**: Auto-generated on first run

Provides metrics for:
- Code quality
- Complexity
- Architecture
- Style

**Usage**:
```bash
# Run with default thresholds (80%)
herd composer insights

# Run with verbose output
herd composer insights:verbose

# Configure thresholds
herd php artisan insights --min-quality=85 --min-complexity=85
```

### PHPUnit Coverage

**Configuration**: `phpunit.xml`

Generates:
- Clover XML (`coverage/clover.xml`)
- HTML report (`coverage/html/`)
- Console summary

**Usage**:
```bash
# Run all tests with coverage
herd composer test:coverage

# Run specific suite with coverage
XDEBUG_MODE=coverage herd php vendor/bin/phpunit --testsuite=Unit --coverage-html=coverage/html

# View HTML report
open coverage/html/index.html
```

**Requirements**: Xdebug or PCOV extension

### Security Scanning

**Usage**:
```bash
# Check for security vulnerabilities
herd composer security:check

# Or directly
herd composer audit
```

## Running Quality Checks

### Pre-Commit Hook

A Git pre-commit hook is configured to run quality checks automatically.

**Location**: `.git/hooks/pre-commit`

**What it checks**:
- PHP CS Fixer (dry-run)
- PHPStan analysis

**Skip hook** (not recommended):
```bash
git commit --no-verify
```

### Individual Tool Commands

```bash
# Code Style
herd composer cs:check          # Check code style
herd composer cs:fix            # Fix code style
herd composer pint              # Laravel Pint fix
herd composer pint:test         # Laravel Pint check

# Static Analysis
herd composer analyse           # PHPStan
herd composer psalm             # Psalm
herd composer phpmd             # PHPMD

# Code Quality
herd composer insights          # PHP Insights

# Testing
herd composer test              # All tests
herd composer test:unit         # Unit tests only
herd composer test:feature      # Feature tests only
herd composer test:coverage     # With coverage

# Security
herd composer security:check    # Security audit

# Combined
herd composer quality           # All checks
herd composer quality:fix       # Fix what can be fixed
```

### Recommended Workflow

1. **Before Starting Work**:
   ```bash
   git pull origin main
   herd composer install
   ```

2. **During Development**:
   ```bash
   # Check frequently
   herd composer cs:check
   herd composer analyse
   ```

3. **Before Committing**:
   ```bash
   # Fix issues
   herd composer quality:fix
   
   # Run all checks
   herd composer quality
   
   # Run tests
   ./run-tests.sh
   ```

4. **Before Creating PR**:
   ```bash
   # Full quality check
   herd composer quality
   
   # Full test suite with coverage
   herd composer test:coverage
   
   # Security check
   herd composer security:check
   ```

## IDE Integration

### PHPStorm

#### PHP CS Fixer

1. Go to `Settings > Tools > External Tools`
2. Add new tool:
   - Name: `PHP CS Fixer`
   - Program: `$ProjectFileDir$/vendor/bin/php-cs-fixer`
   - Arguments: `fix $FilePathRelativeToProjectRoot$ --config=$ProjectFileDir$/.php-cs-fixer.php`
   - Working directory: `$ProjectFileDir$`

#### PHPStan

1. Go to `Settings > PHP > Quality Tools > PHPStan`
2. Configuration file: Select `phpstan.neon`
3. Enable inspection: `Settings > Editor > Inspections > PHPStan`

#### EditorConfig

PHPStorm automatically reads `.editorconfig`

### VS Code

#### Extensions

Install these extensions:
- PHP Intelephense
- PHP CS Fixer
- PHPStan
- EditorConfig for VS Code

#### Settings

Add to `.vscode/settings.json`:
```json
{
  "php-cs-fixer.executablePath": "${workspaceFolder}/vendor/bin/php-cs-fixer",
  "php-cs-fixer.config": "${workspaceFolder}/.php-cs-fixer.php",
  "editor.formatOnSave": true,
  "phpstan.enabled": true,
  "phpstan.path": "${workspaceFolder}/vendor/bin/phpstan"
}
```

## CI/CD Integration

### GitHub Actions

Example workflow (`.github/workflows/quality.yml`):

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: 8.4
          extensions: mbstring, pdo, pdo_pgsql
          coverage: xdebug
      
      - name: Install Dependencies
        run: composer install --no-interaction --prefer-dist
      
      - name: Run PHP CS Fixer
        run: composer cs:check
      
      - name: Run PHPStan
        run: composer analyse
      
      - name: Run Tests with Coverage
        run: composer test:coverage
      
      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage/clover.xml
```

### GitLab CI

Example `.gitlab-ci.yml`:

```yaml
quality:
  stage: test
  image: php:8.4-cli
  script:
    - composer install
    - composer quality
    - composer test:coverage
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/clover.xml
```

## Troubleshooting

### Common Issues

#### Memory Limit Errors

**Problem**: PHPStan runs out of memory

**Solution**:
```bash
# Increase memory limit
herd php -d memory_limit=2G vendor/bin/phpstan analyse
```

#### PHP CS Fixer Cache Issues

**Problem**: PHP CS Fixer not detecting changes

**Solution**:
```bash
# Clear cache
rm .php-cs-fixer.cache
herd composer cs:fix
```

#### Pre-commit Hook Not Running

**Problem**: Git hook not executing

**Solution**:
```bash
# Make executable
chmod +x .git/hooks/pre-commit

# Check hook exists
ls -l .git/hooks/pre-commit
```

#### PHPStan False Positives

**Problem**: PHPStan reports errors for valid Laravel code

**Solution**: Add to `phpstan.neon`:
```yaml
parameters:
    ignoreErrors:
        - '#Your error message pattern#'
```

Or generate baseline:
```bash
herd composer analyse:baseline
```

#### Coverage Not Generating

**Problem**: No coverage report generated

**Solution**:
```bash
# Check Xdebug is installed
herd php -v | grep Xdebug

# Install if missing
pecl install xdebug

# Enable for coverage
XDEBUG_MODE=coverage herd composer test:coverage
```

### Performance Tips

1. **Use Parallel Processing** (PHPStan):
   Already configured in `phpstan.neon`

2. **Exclude Directories**:
   Update `phpstan.neon` to exclude unnecessary paths

3. **Run Specific Tools**:
   Instead of `composer quality`, run individual tools as needed

4. **Use Baselines**:
   Generate baselines for existing issues:
   ```bash
   herd composer analyse:baseline
   herd composer psalm:baseline
   ```

### Getting Help

- Check tool documentation:
  - [PHP CS Fixer](https://github.com/PHP-CS-Fixer/PHP-CS-Fixer)
  - [PHPStan](https://phpstan.org/user-guide/getting-started)
  - [Larastan](https://github.com/larastan/larastan)
  - [PHPMD](https://phpmd.org/)
  - [PHP Insights](https://phpinsights.com/)

- Project issues: Create an issue on GitHub
- Ask in team chat/discussions

## Maintenance

### Updating Tools

```bash
# Update all dev dependencies
herd composer update --dev

# Update specific tool
herd composer update friendsofphp/php-cs-fixer

# After updates, regenerate baselines
herd composer analyse:baseline
herd composer psalm:baseline
```

### Baseline Management

Baselines should be reviewed periodically:

```bash
# Review PHPStan baseline
cat phpstan-baseline.neon

# Regenerate if issues are fixed
herd composer analyse:baseline
```

### Adding New Rules

1. Update configuration file (e.g., `.php-cs-fixer.php`)
2. Run in check mode: `herd composer cs:check`
3. Fix automatically: `herd composer cs:fix`
4. Commit changes with updated config

---

**Last Updated**: 2025-10-06  
**Maintained By**: AuthOS Team
