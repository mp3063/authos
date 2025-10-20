# Contributing to AuthOS

Thank you for considering contributing to AuthOS! This document outlines the process and guidelines for contributing to this Laravel 12 authentication service.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Quality Standards](#code-quality-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Branch Naming Conventions](#branch-naming-conventions)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Collaborate in good faith
- Respect project maintainers' decisions

## Getting Started

### Prerequisites

- PHP 8.4.13 or higher
- Composer 2.x
- Node.js & npm
- PostgreSQL or MySQL
- Laravel Herd (recommended) or Valet

### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone git@github.com:your-username/authos.git
   cd authos
   ```

3. Install dependencies:
   ```bash
   composer install
   npm install
   ```

4. Set up environment:
   ```bash
   cp .env.example .env
   herd php artisan key:generate
   herd php artisan migrate --seed
   herd php artisan passport:install
   ```

5. Install pre-commit hooks (recommended):
   ```bash
   cp .git/hooks/pre-commit.sample .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes

Follow our [Code Standards](.claude/CODE_STANDARDS.md) while developing.

### 3. Run Quality Checks

Before committing, ensure your code passes all quality checks:

```bash
# Check code style
herd composer cs:check

# Fix code style automatically
herd composer cs:fix

# Run static analysis
herd composer analyse

# Run PHP Mess Detector
herd composer phpmd

# Run all quality checks
herd composer quality
```

### 4. Run Tests

Ensure all tests pass:

```bash
# Run all tests
./run-tests.sh

# Run specific test suite
./run-tests.sh tests/Unit/
./run-tests.sh tests/Feature/

# Run with coverage
herd composer test:coverage
```

### 5. Commit Your Changes

Follow our [commit message guidelines](#commit-message-guidelines).

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Code Quality Standards

We use multiple tools to maintain code quality:

### PHP CS Fixer

- PSR-12 compliant
- Laravel conventions
- Automatic formatting

```bash
# Check issues
herd composer cs:check

# Fix issues
herd composer cs:fix
```

### PHPStan (Level 5)

- Static analysis
- Type checking
- Laravel-aware

```bash
# Run analysis
herd composer analyse

# Generate baseline
herd composer analyse:baseline
```

### Laravel Pint

Alternative to PHP CS Fixer:

```bash
# Fix code style
herd composer pint

# Check without fixing
herd composer pint:test
```

### PHPMD (PHP Mess Detector)

- Code complexity
- Unused code
- Design issues

```bash
herd composer phpmd
```

### PHP Insights

- Code quality metrics
- Architecture analysis

```bash
herd composer insights
```

### Psalm

- Additional static analysis
- Type safety

```bash
herd composer psalm
```

## Testing Requirements

### Test Coverage

- Minimum 80% code coverage
- All new features must include tests
- Bug fixes should include regression tests

### Test Types

1. **Unit Tests** (`tests/Unit/`)
   - Test individual classes/methods
   - Mock dependencies
   - Fast execution

2. **Feature Tests** (`tests/Feature/`)
   - Test HTTP endpoints
   - Test integrations
   - Database interactions

3. **Integration Tests** (`tests/Integration/`)
   - Test multiple components
   - External services
   - Complex workflows

### Writing Tests

```php
use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;

class ExampleTest extends TestCase
{
    use RefreshDatabase;

    public function test_example(): void
    {
        // Arrange
        $user = User::factory()->create();

        // Act
        $response = $this->actingAs($user)->get('/api/v1/profile');

        // Assert
        $response->assertStatus(200);
        $response->assertJsonStructure(['data' => ['id', 'email']]);
    }
}
```

## Pull Request Process

### Before Submitting

- [ ] Code passes all quality checks (`composer quality`)
- [ ] All tests pass (`./run-tests.sh`)
- [ ] New features have tests
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (if applicable)
- [ ] No merge conflicts with main

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Related Issues
Fixes #(issue)

## Testing
How to test these changes

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex code
- [ ] Documentation updated
- [ ] No new warnings
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Quality checks pass
```

### Review Process

1. Automated checks must pass (CI/CD)
2. At least one maintainer approval required
3. All review comments addressed
4. No unresolved conversations
5. Branch is up to date with main

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `build`: Build system changes

### Examples

```
feat(auth): add MFA support with TOTP

Implement multi-factor authentication using TOTP (Time-based One-Time Password).
Users can now enable MFA from their profile settings.

Closes #123
```

```
fix(oauth): resolve token expiration issue

Fixed an issue where refresh tokens were not being properly rotated,
causing authentication failures after token expiration.

Fixes #456
```

```
docs(readme): update installation instructions

Added Laravel Herd setup instructions and clarified PHP version requirements.
```

### Scope Examples

- `auth`: Authentication features
- `oauth`: OAuth implementation
- `api`: API endpoints
- `admin`: Filament admin panel
- `models`: Eloquent models
- `tests`: Test-related changes
- `ci`: CI/CD pipeline
- `deps`: Dependencies

## Branch Naming Conventions

Use descriptive branch names following this pattern:

```
<type>/<short-description>
```

### Types

- `feature/` - New features
- `fix/` - Bug fixes
- `hotfix/` - Critical production fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation updates
- `test/` - Test additions/updates
- `chore/` - Maintenance tasks

### Examples

```
feature/social-login-providers
fix/oauth-token-refresh
hotfix/critical-security-patch
refactor/user-repository-pattern
docs/api-documentation
test/integration-test-coverage
chore/update-dependencies
```

### Branch Naming Rules

- Use lowercase
- Use hyphens to separate words
- Be descriptive but concise
- Include issue number if applicable: `fix/123-token-expiration`

## Security Vulnerabilities

If you discover a security vulnerability, please email [security@yourapp.com] instead of creating a public issue.

## Questions?

- Check existing issues and discussions
- Read the [documentation](README.md)
- Ask in GitHub Discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to AuthOS!
