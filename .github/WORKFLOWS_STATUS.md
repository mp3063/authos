# GitHub Actions Workflows Status

This document tracks which workflows are active and which are disabled pending infrastructure setup.

## ✅ Active Workflows

These workflows run automatically and are fully functional:

### 1. **Main CI Pipeline** (`ci.yml`)
- **Status**: ✅ ACTIVE
- **Triggers**: Every push, pull request
- **Purpose**: Code quality checks, tests, coverage
- **Requirements**: None - runs on GitHub-hosted runners
- **Test Matrix**: 8 configurations (PHP 8.3/8.4 × PostgreSQL 15/16 × Ubuntu 22.04/24.04)

### 2. **Security Scanning** (`security.yml`)
- **Status**: ✅ ACTIVE
- **Triggers**: Daily at 2 AM UTC, manual
- **Purpose**: Dependency audit, secret detection, OWASP checks, SAST
- **Requirements**: None - runs on GitHub-hosted runners

### 3. **Performance Testing** (`performance.yml`)
- **Status**: ✅ ACTIVE
- **Triggers**: Pull requests, weekly on Sundays
- **Purpose**: Performance benchmarks, regression detection
- **Requirements**: None - runs on GitHub-hosted runners

### 4. **Nightly Tests** (`nightly.yml`)
- **Status**: ✅ ACTIVE
- **Triggers**: Daily at 2 AM UTC
- **Purpose**: Full test suite, E2E tests, migrations
- **Requirements**: None - runs on GitHub-hosted runners
- **On Failure**: Creates GitHub issue, sends Slack notification

### 5. **SDK Release** (`sdk-release.yml`)
- **Status**: ✅ ACTIVE
- **Triggers**: Git tags (v* pattern)
- **Purpose**: Publish TypeScript SDK to NPM
- **Requirements**: NPM_TOKEN secret (configure when ready to publish)

---

## ⚠️ Disabled Workflows (Pending Infrastructure)

These workflows are **disabled** until you have actual servers configured. They will NOT run automatically.

### 6. **Deploy to Staging** (`deploy-staging.yml`)
- **Status**: ⚠️ DISABLED (manual trigger only)
- **Original Triggers**: Push to `develop` or `main` (COMMENTED OUT)
- **Manual Trigger**: Available via GitHub Actions UI
- **Purpose**: Deploy to staging server
- **Why Disabled**: No staging server configured yet

**Required to Enable:**
1. **Staging Server** (e.g., DigitalOcean, AWS, Hetzner)
   - Domain: `staging.authos.yourdomain.com`
   - SSH access configured
   - PostgreSQL database
   - Redis cache
   - SSL certificate

2. **GitHub Secrets** (Settings → Secrets → Actions):
   - `STAGING_SERVER_HOST` - Server hostname/IP
   - `STAGING_SERVER_USER` - SSH username
   - `STAGING_DEPLOY_PATH` - Deployment directory path
   - `STAGING_SSH_PRIVATE_KEY` - SSH private key for deployment

3. **Optional Secrets**:
   - `SLACK_WEBHOOK` - For deployment notifications

**To Enable:**
1. Configure all secrets in GitHub
2. Uncomment the `push:` trigger in `deploy-staging.yml`
3. Update `staging.authos.example.com` to your actual domain

---

### 7. **Deploy to Production** (`deploy-production.yml`)
- **Status**: ⚠️ DISABLED (infrastructure not ready)
- **Triggers**: Manual only (always requires version tag)
- **Purpose**: Deploy to production server
- **Why Disabled**: No production server configured yet

**Required to Enable:**
1. **Production Server** (separate from staging)
   - Domain: `authos.yourdomain.com`
   - SSH access configured
   - PostgreSQL database with backup system
   - Redis cache
   - SSL certificate
   - Monitoring configured

2. **GitHub Secrets**:
   - `PRODUCTION_SERVER_HOST` - Server hostname/IP
   - `PRODUCTION_SERVER_USER` - SSH username
   - `PRODUCTION_DEPLOY_PATH` - Deployment directory path
   - `PRODUCTION_SSH_PRIVATE_KEY` - SSH private key for deployment

3. **Optional Secrets**:
   - `SLACK_WEBHOOK` - For deployment notifications
   - `NOTIFICATION_EMAIL` - For critical alerts

**To Enable:**
1. Configure all secrets in GitHub
2. Test deployment to staging first
3. Update `authos.example.com` to your actual domain
4. Ensure database backups are configured
5. Run manually via GitHub Actions UI

---

## 📊 Workflow Summary

| Workflow | Status | Auto-Run | Manual Run | Infrastructure Needed |
|----------|--------|----------|------------|----------------------|
| CI Pipeline | ✅ Active | Yes | Yes | None |
| Security Scanning | ✅ Active | Daily | Yes | None |
| Performance Testing | ✅ Active | Weekly | Yes | None |
| Nightly Tests | ✅ Active | Daily | Yes | None |
| SDK Release | ✅ Active | On tag | Yes | NPM token |
| Deploy Staging | ⚠️ Disabled | **NO** | Yes | Staging server |
| Deploy Production | ⚠️ Disabled | **NO** | Yes | Production server |

---

## 🚀 Deployment Workflow

When you're ready to deploy, the typical workflow is:

```
1. Develop feature → push to feature branch
2. CI runs automatically (tests, security, quality)
3. Create PR → CI validates changes
4. Merge to develop → (staging deployment disabled for now)
5. Test in staging → Verify functionality
6. Create release tag (v1.0.0) → Production deployment (manual, disabled for now)
```

---

## 🔧 Setting Up Servers (Future)

### Recommended Hosting Providers

**For Development/Staging:**
- DigitalOcean Droplets ($6-12/month)
- Hetzner Cloud (€4-8/month)
- Vultr ($6-12/month)

**For Production:**
- AWS (auto-scaling)
- DigitalOcean Managed Kubernetes
- Laravel Forge + DigitalOcean/AWS/Linode

### Minimum Server Requirements

**Staging Server:**
- 2 vCPU
- 4 GB RAM
- 40 GB SSD
- Ubuntu 22.04/24.04
- PHP 8.4, PostgreSQL 15+, Redis 7+
- Nginx/Apache

**Production Server:**
- 4 vCPU
- 8 GB RAM
- 80 GB SSD
- Ubuntu 24.04 LTS
- PHP 8.4, PostgreSQL 16, Redis 7+
- Nginx with HTTP/2
- SSL certificate (Let's Encrypt)

---

## 📝 Next Steps

When you're ready to deploy:

1. **Set up staging server** first
2. **Configure GitHub Secrets**
3. **Enable staging workflow** (uncomment push trigger)
4. **Test deployment manually** (workflow_dispatch)
5. **Verify staging environment**
6. **Repeat for production** (always manual)

---

## 📚 Documentation

- **Deployment Guide**: See `docs/operations/ci-cd-guide.md`
- **CI/CD Report**: See `docs/operations/CI-CD-IMPLEMENTATION-REPORT.md`
- **Runbooks**: See `docs/operations/RUNBOOKS.md`

---

**Last Updated**: Phase 8 Complete - October 2025
**Maintained By**: AuthOS Development Team

**Questions?** Refer to the deployment documentation in `docs/operations/` or `.github/DEPLOYMENT.md`
