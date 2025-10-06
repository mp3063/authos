# Deployment Quick Reference

## Staging Deployment

### Automatic (Recommended)
```bash
git push origin main
# Deployment triggers automatically
```

### Manual
```bash
# Via GitHub CLI
gh workflow run deploy-staging.yml

# Via deployment script
./scripts/deployment/deploy.sh staging
```

### Monitor
- Watch: https://github.com/YOUR_ORG/authos/actions
- Check: https://staging.authos.example.com/api/v1/health

---

## Production Deployment

### Step 1: Create Release Tag
```bash
# Semantic versioning: vMAJOR.MINOR.PATCH
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

### Step 2: Trigger Deployment
```bash
# Via GitHub UI
# Go to: Actions → Deploy to Production → Run workflow
# Input version: v1.0.0

# Via GitHub CLI
gh workflow run deploy-production.yml -f version=v1.0.0
```

### Step 3: Monitor
1. **GitHub Actions:** Watch deployment progress
2. **Health Check:** https://authos.example.com/api/v1/health
3. **Logs:** Check server logs for errors
4. **Metrics:** Review monitoring dashboard

---

## Rollback

### Automatic Rollback
- Triggers automatically if health check fails
- Switches to previous release
- Logs rollback reason

### Manual Rollback

#### Quick Rollback (Previous Release)
```bash
./scripts/deployment/rollback.sh production 1
```

#### Rollback to Specific Release
```bash
# List available releases
./scripts/deployment/rollback.sh production list

# Rollback to 2nd previous release
./scripts/deployment/rollback.sh production 2
```

#### Emergency Rollback (SSH)
```bash
ssh deploy@production.server
cd /var/www/authos

# Check current release
ls -la current

# List releases (newest first)
ls -lt releases/

# Switch to previous release
PREV_RELEASE=$(ls -t releases | sed -n 2p)
ln -nfs releases/$PREV_RELEASE current_tmp
mv -Tf current_tmp current

# Clear caches and restart
cd current
php artisan cache:clear
php artisan config:cache
php artisan queue:restart
php artisan up
```

---

## Pre-Deployment Checklist

### Before Staging
- [ ] All tests passing locally
- [ ] Code review approved
- [ ] Database migrations tested
- [ ] Breaking changes documented
- [ ] Feature flags configured

### Before Production
- [ ] Tested in staging environment
- [ ] Migration plan reviewed
- [ ] Rollback plan documented
- [ ] Stakeholders notified
- [ ] Backup verified
- [ ] Monitoring alerts configured
- [ ] Documentation updated

---

## Common Commands

### Check Deployment Status
```bash
# Via GitHub CLI
gh run list --workflow=deploy-production.yml --limit=5

# View specific run
gh run view RUN_ID
```

### Server Health Check
```bash
# Staging
curl https://staging.authos.example.com/api/v1/health

# Production
curl https://authos.example.com/api/v1/health
```

### View Server Logs
```bash
# SSH to server
ssh deploy@server

# View Laravel logs
tail -f /var/www/authos/current/storage/logs/laravel.log

# View queue worker logs
journalctl -u queue-worker -f
```

### Database Migrations
```bash
# Check migration status
ssh deploy@server
cd /var/www/authos/current
php artisan migrate:status

# Rollback last migration
php artisan migrate:rollback --step=1
```

---

## Troubleshooting

### Deployment Fails

1. **Check GitHub Actions logs**
   ```bash
   gh run view --log
   ```

2. **Check server connectivity**
   ```bash
   ssh deploy@server "echo 'Connection OK'"
   ```

3. **Verify disk space**
   ```bash
   ssh deploy@server "df -h"
   ```

4. **Check permissions**
   ```bash
   ssh deploy@server "ls -la /var/www/authos/"
   ```

### Health Check Fails

1. **Check application logs**
   ```bash
   ssh deploy@server "tail -100 /var/www/authos/current/storage/logs/laravel.log"
   ```

2. **Check web server**
   ```bash
   ssh deploy@server "systemctl status nginx"
   ```

3. **Check PHP-FPM**
   ```bash
   ssh deploy@server "systemctl status php8.4-fpm"
   ```

4. **Test database connection**
   ```bash
   ssh deploy@server "cd /var/www/authos/current && php artisan tinker"
   # In tinker: DB::connection()->getPdo();
   ```

### Rollback Fails

1. **Check available releases**
   ```bash
   ssh deploy@server "ls -lt /var/www/authos/releases/"
   ```

2. **Manually switch symlink**
   ```bash
   ssh deploy@server
   cd /var/www/authos
   ln -nfs releases/PREVIOUS_RELEASE current
   ```

3. **Clear all caches**
   ```bash
   php artisan optimize:clear
   ```

---

## Emergency Contacts

### During Business Hours
- **DevOps Team:** devops@example.com
- **Slack Channel:** #deployments

### After Hours / Urgent
- **On-Call Engineer:** PagerDuty
- **Emergency Hotline:** +1-XXX-XXX-XXXX

---

## Environment URLs

| Environment | URL | Purpose |
|-------------|-----|---------|
| Local | http://authos.test | Development |
| Staging | https://staging.authos.example.com | Testing |
| Production | https://authos.example.com | Live |

---

## Required Secrets

### GitHub Repository Secrets

#### Staging
- `STAGING_SSH_PRIVATE_KEY`
- `STAGING_SERVER_HOST`
- `STAGING_SERVER_USER`
- `STAGING_DEPLOY_PATH`

#### Production
- `PRODUCTION_SSH_PRIVATE_KEY`
- `PRODUCTION_SERVER_HOST`
- `PRODUCTION_SERVER_USER`
- `PRODUCTION_DEPLOY_PATH`

#### Services
- `CODECOV_TOKEN`
- `SLACK_WEBHOOK`
- `NOTIFICATION_EMAIL`

### How to Add Secrets

1. Go to repository Settings
2. Navigate to Secrets and variables → Actions
3. Click "New repository secret"
4. Add name and value
5. Click "Add secret"

---

## Best Practices

### DO
✅ Deploy to staging first
✅ Tag releases with semantic versioning
✅ Monitor deployments actively
✅ Test rollback procedures
✅ Communicate with team
✅ Document changes

### DON'T
❌ Deploy on Friday afternoon
❌ Skip pre-deployment tests
❌ Deploy without backup
❌ Deploy during peak hours
❌ Deploy multiple changes at once
❌ Ignore health check warnings

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-10-06 | Initial deployment pipeline |

---

**For detailed documentation, see:** [docs/ci-cd-guide.md](../docs/ci-cd-guide.md)
