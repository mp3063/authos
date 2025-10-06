# CI/CD Pipeline Guide

## Table of Contents

1. [Overview](#overview)
2. [GitHub Actions Workflows](#github-actions-workflows)
3. [Quality Gates](#quality-gates)
4. [Deployment Process](#deployment-process)
5. [Configuration](#configuration)
6. [Local Development](#local-development)
7. [Troubleshooting](#troubleshooting)

## Overview

AuthOS uses a comprehensive CI/CD pipeline built on GitHub Actions to ensure code quality, security, and reliable deployments.

### Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Code Push / Pull Request                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
          ▼            ▼            ▼
    ┌─────────┐  ┌─────────┐  ┌──────────┐
    │  Code   │  │  Unit   │  │Integration│
    │ Quality │  │  Tests  │  │  Tests   │
    └────┬────┘  └────┬────┘  └────┬─────┘
         │            │            │
         └────────────┼────────────┘
                      │
              ┌───────┴────────┐
              │  Quality Gate  │
              └───────┬────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
    ┌─────────┐  ┌─────────┐  ┌──────────┐
    │Security │  │ Perf.   │  │  Build   │
    │ Scans   │  │ Tests   │  │ Artifact │
    └────┬────┘  └────┬────┘  └────┬─────┘
         │            │            │
         └────────────┼────────────┘
                      │
              ┌───────┴────────┐
              │ Deploy Staging │
              └───────┬────────┘
                      │
              ┌───────┴────────┐
              │Deploy Production│
              │ (Manual Approval)│
              └────────────────┘
```

## GitHub Actions Workflows

### 1. Main CI Pipeline (`ci.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`

**Jobs:**

#### Code Quality Checks
- **Laravel Pint** - Code style validation
- **PHP CS Fixer** - PSR-12 compliance
- **PHPStan (Level 5)** - Static analysis
- **Psalm** - Additional static analysis
- **Composer Audit** - Dependency security

#### Unit Tests
- **Matrix:**
  - PHP: 8.3, 8.4
  - PostgreSQL: 15, 16
  - OS: Ubuntu 22.04, 24.04
- **Coverage:** Xdebug enabled
- **Upload:** Codecov integration

#### Integration Tests
- **Matrix:**
  - PHP: 8.3, 8.4
  - PostgreSQL: 16
- **Includes:** Feature tests, API tests
- **Coverage:** Combined with unit tests

#### Quality Gate
- All tests must pass
- No PHPStan errors
- No high/critical security vulnerabilities
- Minimum 80% code coverage (enforced by Codecov)

**Status:** Required check for PR merges

---

### 2. Security Scanning (`security.yml`)

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Daily at 2 AM UTC (scheduled)

**Scans:**

#### Dependency Check
- Composer security audit
- NPM audit
- Fails on high/critical vulnerabilities

#### Secret Scanning
- **TruffleHog OSS** - Scans for hardcoded secrets
- Checks commits and diffs

#### SAST (Static Application Security Testing)
- **Psalm Taint Analysis** - Detects SQL injection, XSS
- Custom security rules

#### OWASP Dependency Check
- CVE database scanning
- Fails on CVSS score ≥ 7

#### License Compliance
- Validates dependency licenses
- Blocks GPL, AGPL licenses
- Allows MIT, Apache, BSD

#### Code Quality Security
- **PHPMD** - Mess detection
- **PHP Insights** - Quality metrics (80% minimum)

**Notifications:**
- Slack webhook on failure
- GitHub issue created for critical failures

---

### 3. Performance Testing (`performance.yml`)

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Weekly on Sunday at 3 AM UTC
- Manual workflow dispatch

**Tests:**

#### Performance Benchmarks
- OAuth token generation (< 100ms)
- User authentication (< 50ms)
- API endpoint response (< 200ms)
- Database queries (< 10ms)
- Cache operations (< 5ms)

#### Load Testing (Manual/Scheduled Only)
- **Tool:** k6
- **Stages:**
  - Ramp up to 50 users (2 min)
  - Sustain 50 users (5 min)
  - Ramp up to 100 users (2 min)
  - Sustain 100 users (5 min)
  - Ramp down (2 min)
- **Thresholds:**
  - p95 response time < 500ms
  - Error rate < 5%

#### Memory Profiling
- Xdebug memory profiling
- Detects memory leaks
- Reports peak usage

**PR Integration:**
- Compares with baseline
- Comments performance changes
- Fails on >5% regression

---

### 4. Nightly Comprehensive Tests (`nightly.yml`)

**Triggers:**
- Daily at 2 AM UTC
- Manual workflow dispatch

**Test Suites:**

#### Full Test Suite
- All 1,166+ test methods
- Full code coverage report
- Matrix: PHP 8.3/8.4 × PostgreSQL 15/16

#### Browser Tests (Laravel Dusk)
- E2E user flows
- Admin panel functionality
- OAuth authorization flow
- Critical user journeys

#### Integration Compatibility
- **Groups:**
  - OAuth
  - Social Auth
  - SSO (OIDC/SAML)
  - LDAP
  - Webhooks
  - Bulk Operations

#### Database Migration Tests
- Fresh migrations
- Rollback testing
- Refresh testing
- Schema verification

**On Failure:**
- Creates GitHub issue
- Sends Slack notification
- Priority: High

---

### 5. Staging Deployment (`deploy-staging.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Manual workflow dispatch

**Process:**

#### Pre-Deployment
1. Check if deployment needed (skip if `[skip deploy]` in commit)
2. Run smoke tests
3. Validate dependencies

#### Build
1. Install Composer dependencies (production)
2. Install NPM dependencies
3. Build frontend assets
4. Create deployment artifact (tar.gz)
5. Generate checksum

#### Deploy
1. Download artifact
2. Upload to staging server via rsync
3. Extract to new release directory
4. Link shared directories (storage)
5. Copy environment file

#### Database & Configuration
1. Run migrations
2. Cache configurations
3. Generate Passport keys (if needed)
4. Warm application caches

#### Switch Release
1. Put app in maintenance mode
2. Switch symlink atomically
3. Restart queue workers
4. Bring app back online

#### Health Check
1. Test `/api/v1/health` endpoint
2. Retry up to 30 times (5 min)
3. Rollback on failure

#### Post-Deployment
1. Run API smoke tests
2. Verify migrations
3. Cleanup old releases (keep last 5)

**Environment:** `staging`
**URL:** https://staging.authos.example.com

---

### 6. Production Deployment (`deploy-production.yml`)

**Triggers:**
- **Manual only** via workflow dispatch

**Required Input:**
- Version tag (e.g., `v1.0.0`)
- Skip tests flag (optional, not recommended)

**Process:**

#### Validation
1. Validate version format (semver)
2. Check if tag exists
3. Create deployment tracking issue

#### Pre-Deployment Tests (unless skipped)
1. Checkout tagged version
2. Run critical test suite
3. Security audit
4. Fail if any critical tests fail

#### Build Production Artifact
1. Install optimized dependencies
2. Build minified assets
3. Remove development files
4. Create production artifact
5. Generate SHA256 checksum
6. Store artifact (90 days retention)

#### Database Backup
1. SSH to production server
2. Create database backup
3. Store in backups directory

#### Deploy
1. Verify artifact checksum
2. Upload to production server
3. Extract to new release
4. Link shared directories
5. Run migrations (manual confirmation)

#### Switch Release
1. Maintenance mode ON
2. Switch symlink atomically
3. Clear all caches
4. Cache configurations
5. Generate Passport keys (if needed)
6. Restart queue workers
7. Maintenance mode OFF

#### Health Check
1. Wait 10 seconds for stabilization
2. Test health endpoint
3. Retry up to 60 times (10 min)
4. **Automatic rollback on failure**

#### Post-Deployment Verification
1. Smoke tests
2. OAuth flow verification
3. Database schema check

#### Cleanup
1. Keep last 10 releases
2. Remove older releases

**Environment:** `production`
**URL:** https://authos.example.com

**Rollback:**
- Automatic on health check failure
- Manual via `scripts/deployment/rollback.sh`

---

### 7. SDK Release (`sdk-release.yml`)

**Triggers:**
- Push tags matching `v*.*.*`
- Manual workflow dispatch

**Process:**
1. Generate OpenAPI specification
2. Build TypeScript SDK
3. Run SDK tests
4. Publish to npm registry
5. Create GitHub release
6. Generate release notes

---

## Quality Gates

### Pull Request Requirements

All PRs must pass the following checks:

1. **Code Quality**
   - ✅ Laravel Pint passes
   - ✅ PHP CS Fixer passes
   - ✅ PHPStan Level 5 passes
   - ✅ Psalm passes

2. **Tests**
   - ✅ All unit tests pass
   - ✅ All integration tests pass
   - ✅ Code coverage ≥ 80%

3. **Security**
   - ✅ No high/critical vulnerabilities
   - ✅ No secrets detected
   - ✅ License compliance

4. **Performance**
   - ✅ No regression > 5%
   - ✅ All benchmarks within thresholds

### Merge Requirements

- All status checks passing
- At least 1 approval (recommended)
- No merge conflicts
- Branch up to date with target

---

## Deployment Process

### Staging Deployment

**Automatic on push to `main` or `develop`:**

```bash
# Triggered automatically on push
git push origin main
```

**Manual deployment:**

```bash
# Via GitHub UI
# Actions → Deploy to Staging → Run workflow

# Via GitHub CLI
gh workflow run deploy-staging.yml
```

**Local deployment script:**

```bash
# Using deployment script
./scripts/deployment/deploy.sh staging
```

---

### Production Deployment

**Required Steps:**

1. **Create Release Tag**
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

2. **Trigger Deployment**
   ```bash
   # Via GitHub UI
   # Actions → Deploy to Production → Run workflow
   # Input: version = v1.0.0

   # Via GitHub CLI
   gh workflow run deploy-production.yml -f version=v1.0.0
   ```

3. **Monitor Deployment**
   - Watch GitHub Actions progress
   - Check deployment tracking issue
   - Monitor health checks

4. **Post-Deployment**
   - Verify production health
   - Check monitoring dashboards
   - Review logs for errors

**Rollback if Needed:**

```bash
# Automatic rollback on health check failure

# Manual rollback
./scripts/deployment/rollback.sh production 1

# Rollback 2 releases
./scripts/deployment/rollback.sh production 2

# List available releases
./scripts/deployment/rollback.sh production list
```

---

## Configuration

### Required GitHub Secrets

#### Staging Environment

```
STAGING_SSH_PRIVATE_KEY      # SSH key for staging server
STAGING_SERVER_HOST          # staging.authos.example.com
STAGING_SERVER_USER          # deploy
STAGING_DEPLOY_PATH          # /var/www/authos
```

#### Production Environment

```
PRODUCTION_SSH_PRIVATE_KEY   # SSH key for production server
PRODUCTION_SERVER_HOST       # authos.example.com
PRODUCTION_SERVER_USER       # deploy
PRODUCTION_DEPLOY_PATH       # /var/www/authos
```

#### Services

```
CODECOV_TOKEN                # Codecov.io integration
SLACK_WEBHOOK                # Slack notifications
NOTIFICATION_EMAIL           # Email for critical alerts
```

### Environment Variables in Workflows

**Set in repository settings:**

1. Navigate to Settings → Secrets and variables → Actions
2. Add repository secrets listed above
3. Add environment-specific secrets under Environments

**Environment Configuration:**

Create environment configs:

```bash
# Copy example configs
cp scripts/deployment/config/staging.env.example scripts/deployment/config/staging.env
cp scripts/deployment/config/production.env.example scripts/deployment/config/production.env

# Edit with actual values
nano scripts/deployment/config/staging.env
nano scripts/deployment/config/production.env
```

---

## Local Development

### Running Quality Checks Locally

```bash
# Code style check
composer pint:test

# Fix code style
composer pint

# PHP CS Fixer check
composer cs:check

# Fix with PHP CS Fixer
composer cs:fix

# Static analysis
composer analyse

# PHPMD
composer phpmd

# PHP Insights
composer insights

# Psalm
composer psalm

# All quality checks
composer quality

# Fix all auto-fixable issues
composer quality:fix
```

### Running Tests Locally

```bash
# All tests
composer test

# Unit tests only
composer test:unit

# Feature tests only
composer test:feature

# With coverage
composer test:coverage

# Specific test
./vendor/bin/phpunit --filter testMethodName
```

### Performance Benchmarks

```bash
# Run benchmarks
php artisan performance:benchmark

# With JSON output
php artisan performance:benchmark --format=json
```

### Local Deployment Testing

```bash
# Test staging deployment
SKIP_TESTS=false ./scripts/deployment/deploy.sh staging

# Test rollback
./scripts/deployment/rollback.sh staging 1
```

---

## Troubleshooting

### Common Issues

#### 1. PHPStan Errors

**Issue:** PHPStan fails on CI but passes locally

**Solution:**
```bash
# Clear PHPStan cache
rm -rf storage/phpstan

# Run with same PHP version as CI
php8.4 vendor/bin/phpstan analyse --memory-limit=2G
```

#### 2. Failed Deployment

**Issue:** Deployment fails during health check

**Solution:**
```bash
# Check server logs
ssh deploy@server "tail -f /var/www/authos/current/storage/logs/laravel.log"

# Manual rollback
./scripts/deployment/rollback.sh production 1

# Debug deployment
ssh deploy@server
cd /var/www/authos/current
php artisan down
php artisan cache:clear
php artisan config:cache
php artisan up
```

#### 3. Tests Timeout

**Issue:** Tests hang and timeout on CI

**Solution:**
- Use `./run-tests.sh` wrapper locally
- Check for infinite loops
- Review database connections
- Check Redis connectivity

#### 4. Code Coverage Below Threshold

**Issue:** Codecov reports < 80% coverage

**Solution:**
```bash
# Generate coverage report locally
composer test:coverage

# View HTML report
open coverage/html/index.html

# Add missing tests for uncovered code
```

#### 5. Security Scan Failures

**Issue:** Dependency has known vulnerability

**Solution:**
```bash
# Update dependency
composer update package/name

# If no update available, evaluate risk
composer audit

# Add to allowed exceptions (only if low risk)
# Document in security policy
```

#### 6. Performance Regression

**Issue:** PR shows >5% performance regression

**Solution:**
```bash
# Run benchmarks locally
php artisan performance:benchmark

# Profile specific endpoint
php artisan performance:profile /api/v1/endpoint

# Check database queries
php artisan telescope:list

# Optimize as needed
```

### Getting Help

**Documentation:**
- GitHub Actions: https://docs.github.com/actions
- Laravel Testing: https://laravel.com/docs/testing
- PHPStan: https://phpstan.org/

**Support Channels:**
- Create GitHub issue
- Contact DevOps team
- Check deployment logs

---

## Best Practices

### For Developers

1. **Run tests locally before pushing**
   ```bash
   composer test
   ```

2. **Check code quality before PR**
   ```bash
   composer quality
   ```

3. **Keep PRs focused and small**
   - Easier to review
   - Faster CI execution
   - Lower risk

4. **Write tests for new features**
   - Maintain >80% coverage
   - Include unit + integration tests

5. **Use semantic commit messages**
   ```
   feat: Add new OAuth provider
   fix: Resolve memory leak in cache
   refactor: Optimize database queries
   docs: Update API documentation
   ```

### For Deployments

1. **Always deploy to staging first**
   - Test thoroughly
   - Verify migrations
   - Check performance

2. **Create tagged releases for production**
   ```bash
   git tag -a v1.0.0 -m "Release 1.0.0"
   ```

3. **Monitor after deployment**
   - Check health endpoints
   - Review error logs
   - Monitor metrics

4. **Have rollback plan ready**
   - Know rollback procedure
   - Test rollback in staging
   - Document rollback steps

5. **Communicate deployments**
   - Notify stakeholders
   - Update status page
   - Document changes

---

## Metrics and Monitoring

### CI/CD Metrics

Track these metrics for continuous improvement:

- **Build Success Rate:** Target >95%
- **Average Build Time:** Target <15 min
- **Deployment Frequency:** Track trend
- **Mean Time to Recovery:** Target <30 min
- **Change Failure Rate:** Target <5%

### Quality Metrics

- **Code Coverage:** Maintain >80%
- **PHPStan Level:** Maintain Level 5+
- **Security Vulnerabilities:** Zero high/critical
- **Performance Benchmarks:** Within thresholds

### Deployment Metrics

- **Deployment Success Rate:** Target >98%
- **Rollback Rate:** Target <2%
- **Deployment Duration:** Track and optimize
- **Health Check Response:** Target <200ms

---

## Continuous Improvement

### Regular Reviews

**Monthly:**
- Review failed deployments
- Analyze performance trends
- Update quality thresholds
- Optimize build times

**Quarterly:**
- Update dependencies
- Review security policies
- Evaluate new tools
- Update documentation

**Annually:**
- Major version upgrades
- Infrastructure improvements
- Process refinements
- Team training

---

## Appendix

### Workflow File Reference

| Workflow | File | Purpose |
|----------|------|---------|
| Main CI | `ci.yml` | Code quality + tests |
| Security | `security.yml` | Security scanning |
| Performance | `performance.yml` | Performance tests |
| Nightly | `nightly.yml` | Comprehensive tests |
| Staging Deploy | `deploy-staging.yml` | Staging deployment |
| Production Deploy | `deploy-production.yml` | Production deployment |
| SDK Release | `sdk-release.yml` | SDK publishing |

### Script Reference

| Script | Purpose |
|--------|---------|
| `deploy.sh` | Deploy to environment |
| `rollback.sh` | Rollback deployment |
| `run-tests.sh` | Test execution wrapper |

### Configuration Files

| File | Purpose |
|------|---------|
| `phpstan.neon` | PHPStan configuration |
| `.php-cs-fixer.php` | Code style rules |
| `pint.json` | Laravel Pint config |
| `.env.example` | Environment template |

---

**Last Updated:** 2025-10-06
**Version:** 1.0.0
**Maintained By:** DevOps Team
