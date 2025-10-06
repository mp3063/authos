# AuthOS Incident Response Runbooks

## Table of Contents
1. [High Error Rate](#high-error-rate)
2. [Database Connection Failures](#database-connection-failures)
3. [OAuth System Failure](#oauth-system-failure)
4. [High API Response Times](#high-api-response-times)
5. [Brute Force Attack](#brute-force-attack)
6. [Webhook Delivery Failures](#webhook-delivery-failures)
7. [Cache System Failure](#cache-system-failure)
8. [Disk Space Critical](#disk-space-critical)
9. [Failed Queue Jobs](#failed-queue-jobs)
10. [SSL Certificate Expiry](#ssl-certificate-expiry)

---

## High Error Rate

### Alert Trigger
- Error rate > 10 errors per minute
- Multiple critical errors in short period

### Severity
**High** - Service degradation likely

### Impact
- Poor user experience
- Potential service unavailability
- Data integrity concerns

### Diagnostic Steps

1. **Check Error Statistics**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/errors
   ```

2. **Review Recent Errors**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/errors/recent?limit=20
   ```

3. **Check Error Logs**
   ```bash
   tail -n 100 storage/logs/monitoring.log
   ```

4. **Check System Health**
   ```bash
   curl https://authos.test/api/health/detailed
   ```

### Resolution Steps

1. **Identify Error Pattern**
   - Check if errors are from specific endpoint
   - Check if errors are from specific user/organization
   - Check if errors started after deployment

2. **Quick Fixes**
   - Restart application: `herd restart`
   - Clear cache: `herd php artisan cache:clear`
   - Restart queue workers: `herd php artisan queue:restart`

3. **Database Issues**
   ```bash
   # Check database connections
   herd php artisan db:show

   # Check for long-running queries
   herd php artisan db:monitor
   ```

4. **Memory Issues**
   ```bash
   # Check PHP memory limit
   herd php -i | grep memory_limit

   # Increase if needed (temporarily)
   herd php -d memory_limit=512M artisan optimize:clear
   ```

5. **Rollback if Recent Deployment**
   ```bash
   git revert HEAD
   composer install
   herd php artisan migrate:rollback
   herd restart
   ```

### Prevention
- Implement comprehensive error handling
- Add input validation
- Monitor deployment impacts
- Use feature flags for risky changes

### Escalation
If unresolved after 30 minutes, escalate to:
- **Level 2**: Senior Backend Engineer
- **Level 3**: Engineering Manager

---

## Database Connection Failures

### Alert Trigger
- Database health check returns "unhealthy"
- Connection timeout errors
- Max connections exceeded

### Severity
**Critical** - Service outage

### Impact
- Complete service unavailability
- No authentication possible
- Data loss potential

### Diagnostic Steps

1. **Check Database Health**
   ```bash
   curl https://authos.test/api/health/database
   ```

2. **Test Direct Connection**
   ```bash
   herd php artisan tinker
   >>> DB::connection()->getPdo();
   ```

3. **Check Database Server**
   ```bash
   # For PostgreSQL
   pg_isready -h localhost -p 5432

   # Check connections
   psql -U authos -c "SELECT count(*) FROM pg_stat_activity;"
   ```

4. **Check Connection Pool**
   ```bash
   # Review database config
   cat config/database.php | grep -A 10 "pgsql"
   ```

### Resolution Steps

1. **Restart Database Service**
   ```bash
   # PostgreSQL
   sudo systemctl restart postgresql

   # Or with Docker
   docker restart authos-postgres
   ```

2. **Kill Long-Running Queries**
   ```sql
   -- Find long-running queries
   SELECT pid, now() - query_start as duration, query
   FROM pg_stat_activity
   WHERE state = 'active'
   ORDER BY duration DESC;

   -- Terminate specific query
   SELECT pg_terminate_backend(PID);
   ```

3. **Increase Max Connections** (if needed)
   ```sql
   -- PostgreSQL
   ALTER SYSTEM SET max_connections = 200;
   SELECT pg_reload_conf();
   ```

4. **Clear Connection Pool**
   ```bash
   herd php artisan db:wipe-cache
   herd restart
   ```

5. **Check Disk Space**
   ```bash
   df -h
   # Database requires disk space for WAL files
   ```

### Prevention
- Monitor connection pool usage
- Set up connection pooling (PgBouncer)
- Configure proper connection limits
- Implement query timeouts

### Escalation
**Immediate escalation to Database Administrator**

---

## OAuth System Failure

### Alert Trigger
- OAuth health check returns "unhealthy"
- Missing OAuth keys
- Token generation failures

### Severity
**Critical** - Authentication unavailable

### Impact
- No new logins possible
- API authentication failures
- Third-party integration failures

### Diagnostic Steps

1. **Check OAuth Health**
   ```bash
   curl https://authos.test/api/health/oauth
   ```

2. **Verify OAuth Keys**
   ```bash
   ls -la storage/oauth-*.key
   # Should show oauth-private.key and oauth-public.key
   ```

3. **Check OAuth Clients**
   ```bash
   herd php artisan passport:client
   ```

4. **Test Token Generation**
   ```bash
   herd php artisan tinker
   >>> $user = User::first();
   >>> $token = $user->createToken('test')->accessToken;
   ```

### Resolution Steps

1. **Regenerate OAuth Keys** (if missing)
   ```bash
   herd php artisan passport:keys --force
   chmod 600 storage/oauth-*.key
   herd restart
   ```

2. **Reinstall Passport** (if corrupted)
   ```bash
   herd php artisan passport:install --force
   ```

3. **Check File Permissions**
   ```bash
   chmod 600 storage/oauth-*.key
   chown www-data:www-data storage/oauth-*.key
   ```

4. **Clear OAuth Cache**
   ```bash
   herd php artisan cache:forget passport:*
   herd restart
   ```

5. **Verify Database Tables**
   ```bash
   herd php artisan tinker
   >>> DB::table('oauth_clients')->count();
   >>> DB::table('oauth_personal_access_clients')->count();
   ```

### Prevention
- Backup OAuth keys regularly
- Include keys in deployment checklist
- Monitor OAuth metrics
- Set up key rotation schedule

### Escalation
If unresolved after 15 minutes:
- **Level 2**: Security Engineer
- **Level 3**: CTO

---

## High API Response Times

### Alert Trigger
- Avg response time > 100ms (95th percentile)
- Max response time > 500ms
- Multiple slow query warnings

### Severity
**Medium** - Performance degradation

### Impact
- Poor user experience
- Potential timeouts
- Increased server load

### Diagnostic Steps

1. **Check Performance Metrics**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/metrics/performance
   ```

2. **Identify Slow Endpoints**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/metrics/api
   ```

3. **Check Database Query Performance**
   ```bash
   tail -f storage/logs/performance.log | grep "slow query"
   ```

4. **Check System Resources**
   ```bash
   top -bn1 | grep php
   free -h
   df -h
   ```

### Resolution Steps

1. **Clear Application Cache**
   ```bash
   herd php artisan cache:clear
   herd php artisan config:clear
   herd php artisan route:clear
   herd php artisan view:clear
   ```

2. **Optimize Database**
   ```bash
   # Analyze slow queries
   herd php artisan db:monitor --slow

   # Check for missing indexes
   herd php artisan db:show --counts
   ```

3. **Enable Query Caching**
   ```bash
   # Check cache hit rate
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/metrics/performance

   # Warm up cache
   herd php artisan cache:warm
   ```

4. **Optimize Code**
   ```bash
   # Enable OPcache
   herd php -i | grep opcache

   # Clear autoload cache
   composer dump-autoload --optimize
   ```

5. **Scale Resources** (if needed)
   ```bash
   # Increase PHP workers
   # Increase database connections
   # Add read replicas
   ```

### Prevention
- Implement query result caching
- Add database indexes
- Use eager loading for relationships
- Monitor slow query log daily

### Escalation
If response times don't improve after 1 hour:
- **Level 2**: Performance Engineer
- **Level 3**: Infrastructure Team

---

## Brute Force Attack

### Alert Trigger
- >10 failed login attempts from same IP within 1 hour
- >10 failed attempts for same email within 1 hour
- Multiple suspicious IPs detected

### Severity
**High** - Security incident

### Impact
- Potential account compromise
- Service degradation from attack traffic
- Reputation damage

### Diagnostic Steps

1. **Check Security Metrics**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/metrics/authentication
   ```

2. **Review Suspicious IPs**
   ```bash
   tail -n 500 storage/logs/security.log | grep "failed_authentication"
   ```

3. **Analyze Attack Pattern**
   ```bash
   # Count attempts per IP
   grep "failed_authentication" storage/logs/security.log | \
     jq -r '.context.ip' | sort | uniq -c | sort -rn | head -20
   ```

4. **Check Targeted Accounts**
   ```bash
   grep "failed_authentication" storage/logs/security.log | \
     jq -r '.context.email' | sort | uniq -c | sort -rn | head -20
   ```

### Resolution Steps

1. **Block Attacking IPs** (immediately)
   ```bash
   # Add to firewall
   sudo ufw deny from 192.168.1.100

   # Or add to nginx
   echo "deny 192.168.1.100;" >> /etc/nginx/snippets/block-ips.conf
   sudo nginx -t && sudo systemctl reload nginx
   ```

2. **Rate Limit Authentication**
   ```bash
   # Verify rate limiting is active
   grep "throttle:auth" routes/api.php

   # Temporarily increase throttling
   # Edit config/throttle.php or .env
   RATE_LIMIT_AUTH=5  # Reduce from 10 to 5
   ```

3. **Notify Targeted Users**
   ```bash
   herd php artisan tinker
   >>> $users = User::whereIn('email', ['targeted@example.com'])->get();
   >>> foreach ($users as $user) {
   ...   Mail::to($user)->send(new SecurityAlertMail());
   ... }
   ```

4. **Enable Account Lockouts** (if not enabled)
   ```php
   // In AuthController or middleware
   // Lock account after 5 failed attempts for 30 minutes
   ```

5. **Monitor Ongoing Attack**
   ```bash
   # Watch live attacks
   tail -f storage/logs/security.log | grep "failed_authentication"
   ```

### Prevention
- Implement CAPTCHA after 3 failed attempts
- Use rate limiting at multiple layers
- Implement IP-based geofencing
- Enable MFA for all accounts
- Use Web Application Firewall (WAF)

### Escalation
**Immediate escalation to Security Team**
- Document attack details
- Preserve logs
- Coordinate with infrastructure team

---

## Webhook Delivery Failures

### Alert Trigger
- Webhook success rate < 95%
- >50 failed deliveries per day for a webhook
- Multiple webhook timeouts

### Severity
**Medium** - Integration issues

### Impact
- Third-party integration failures
- Delayed notifications
- Data sync issues

### Diagnostic Steps

1. **Check Webhook Metrics**
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/monitoring/metrics/webhooks
   ```

2. **Review Webhook Logs**
   ```bash
   tail -n 200 storage/logs/webhooks.log | grep "failed"
   ```

3. **Test Webhook Endpoint**
   ```bash
   # Test specific webhook
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/webhooks/{id}/test
   ```

4. **Check Network Connectivity**
   ```bash
   # Test webhook URL
   curl -I https://webhook-endpoint.example.com/webhook
   ```

### Resolution Steps

1. **Retry Failed Deliveries**
   ```bash
   # Retry specific delivery
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/webhook-deliveries/{id}/retry
   ```

2. **Verify Webhook Configuration**
   ```bash
   herd php artisan tinker
   >>> $webhook = Webhook::find(1);
   >>> $webhook->url;
   >>> $webhook->enabled;
   >>> $webhook->secret;
   ```

3. **Check Webhook Endpoint**
   - Verify URL is accessible
   - Check SSL certificate validity
   - Test with manual request
   - Verify signature validation

4. **Adjust Retry Logic**
   ```bash
   # Check retry configuration
   grep "WEBHOOK_" .env

   # Adjust if needed
   WEBHOOK_MAX_RETRIES=3
   WEBHOOK_RETRY_DELAY=60
   ```

5. **Disable Problematic Webhook** (temporarily)
   ```bash
   curl -X POST -H "Authorization: Bearer $TOKEN" \
     https://authos.test/api/v1/webhooks/{id}/disable
   ```

### Prevention
- Implement exponential backoff
- Monitor webhook endpoint health
- Set appropriate timeouts
- Log detailed failure reasons
- Coordinate with webhook consumers

### Escalation
If webhook is business-critical:
- **Level 2**: Integration Engineer
- **Contact**: Webhook endpoint owner

---

## Cache System Failure

### Alert Trigger
- Cache health check returns "unhealthy"
- Cache hit rate < 50%
- Cache connection errors

### Severity
**Medium** - Performance degradation

### Impact
- Increased database load
- Slower response times
- Potential service degradation

### Diagnostic Steps

1. **Check Cache Health**
   ```bash
   curl https://authos.test/api/health/cache
   ```

2. **Test Cache Operations**
   ```bash
   herd php artisan tinker
   >>> Cache::put('test', 'value', 60);
   >>> Cache::get('test');
   >>> Cache::forget('test');
   ```

3. **Check Cache Driver**
   ```bash
   grep CACHE_STORE .env
   cat config/cache.php | grep -A 10 "default"
   ```

### Resolution Steps

1. **Clear Cache**
   ```bash
   herd php artisan cache:clear
   herd php artisan config:clear
   ```

2. **Restart Cache Service** (if using Redis)
   ```bash
   sudo systemctl restart redis
   # Or
   docker restart authos-redis
   ```

3. **Switch to Fallback Driver** (temporarily)
   ```bash
   # Edit .env
   CACHE_STORE=file  # or array

   herd php artisan config:clear
   herd restart
   ```

4. **Check Cache Storage**
   ```bash
   # For file cache
   du -sh storage/framework/cache

   # For Redis
   redis-cli INFO memory
   ```

5. **Verify Cache Configuration**
   ```bash
   herd php artisan tinker
   >>> config('cache.default');
   >>> config('cache.stores.database');
   ```

### Prevention
- Monitor cache hit rate
- Set up cache driver redundancy
- Implement cache warming
- Regular cache maintenance

### Escalation
If cache is critical and unresolved:
- **Level 2**: Infrastructure Engineer

---

## Disk Space Critical

### Alert Trigger
- Disk usage > 90%
- Storage health check shows critical
- Write operations failing

### Severity
**Critical** - Service outage imminent

### Impact
- Application crashes
- Log write failures
- Database corruption risk
- Session loss

### Diagnostic Steps

1. **Check Disk Usage**
   ```bash
   df -h
   du -sh /path/to/authos/*
   ```

2. **Identify Large Files**
   ```bash
   du -ah /path/to/authos | sort -rh | head -20
   ```

3. **Check Log Sizes**
   ```bash
   du -sh storage/logs/*
   ```

4. **Check Database Size**
   ```bash
   # PostgreSQL
   psql -U authos -c "\l+"
   psql -U authos -c "SELECT pg_size_pretty(pg_database_size('authos'));"
   ```

### Resolution Steps

1. **Clear Old Logs** (immediately)
   ```bash
   # Keep only last 7 days
   find storage/logs -name "*.log" -mtime +7 -delete

   # Rotate logs
   herd php artisan log:clear --days=7
   ```

2. **Clear Cache Files**
   ```bash
   herd php artisan cache:clear
   rm -rf storage/framework/cache/data/*
   rm -rf storage/framework/sessions/*
   rm -rf storage/framework/views/*
   ```

3. **Clean Failed Jobs**
   ```bash
   herd php artisan queue:flush
   herd php artisan queue:prune-failed --hours=24
   ```

4. **Archive Old Data**
   ```bash
   # Export old authentication logs
   herd php artisan db:archive --table=authentication_logs --days=90
   ```

5. **Increase Disk Space** (if available)
   ```bash
   # AWS EBS
   aws ec2 modify-volume --volume-id vol-xxx --size 100

   # Then resize filesystem
   sudo resize2fs /dev/xvda1
   ```

### Prevention
- Set up automated log rotation
- Implement data archival policy
- Monitor disk usage daily
- Set up disk space alerts at 80%

### Escalation
**Immediate escalation to Infrastructure Team**

---

## Failed Queue Jobs

### Alert Trigger
- >100 failed jobs in queue
- Queue health check degraded
- Critical jobs failing repeatedly

### Severity
**Medium** - Background processing affected

### Impact
- Delayed email notifications
- Delayed webhook deliveries
- Delayed data processing
- Potential data loss

### Diagnostic Steps

1. **Check Queue Health**
   ```bash
   curl https://authos.test/api/health/queue
   ```

2. **Count Failed Jobs**
   ```bash
   herd php artisan queue:failed
   ```

3. **Inspect Failed Job**
   ```bash
   herd php artisan queue:failed-show 1
   ```

4. **Check Queue Workers**
   ```bash
   ps aux | grep "queue:work"
   ```

### Resolution Steps

1. **Restart Queue Workers**
   ```bash
   herd php artisan queue:restart

   # Or restart supervisor
   sudo supervisorctl restart authos-workers:*
   ```

2. **Retry Failed Jobs**
   ```bash
   # Retry specific job
   herd php artisan queue:retry 1

   # Retry all failed jobs
   herd php artisan queue:retry all
   ```

3. **Clear Failed Jobs** (if non-recoverable)
   ```bash
   # Clear all failed jobs
   herd php artisan queue:flush

   # Clear jobs older than 24 hours
   herd php artisan queue:prune-failed --hours=24
   ```

4. **Investigate Root Cause**
   ```bash
   # Check job logs
   tail -f storage/logs/laravel.log | grep "Failed"

   # Test job manually
   herd php artisan tinker
   >>> dispatch(new TestJob());
   ```

5. **Increase Worker Processes** (if overwhelmed)
   ```bash
   # Edit supervisor config
   sudo nano /etc/supervisor/conf.d/authos-workers.conf
   # Increase numprocs

   sudo supervisorctl reread
   sudo supervisorctl update
   ```

### Prevention
- Monitor queue length
- Set up job timeout handling
- Implement job retry logic
- Use dedicated queue workers

### Escalation
If jobs continue failing:
- **Level 2**: Backend Engineer

---

## SSL Certificate Expiry

### Alert Trigger
- Certificate expires in < 7 days
- Certificate validation errors
- HTTPS connection failures

### Severity
**High** - Service outage imminent

### Impact
- Website inaccessible
- API calls blocked
- Browser security warnings
- Loss of user trust

### Diagnostic Steps

1. **Check Certificate Expiry**
   ```bash
   echo | openssl s_client -connect authos.test:443 2>/dev/null | \
     openssl x509 -noout -dates
   ```

2. **Verify Certificate Chain**
   ```bash
   echo | openssl s_client -connect authos.test:443 -showcerts
   ```

3. **Check Certificate Files**
   ```bash
   ls -la /etc/ssl/certs/authos.*
   openssl x509 -in /etc/ssl/certs/authos.crt -text -noout
   ```

### Resolution Steps

1. **Renew Let's Encrypt Certificate**
   ```bash
   # Using Certbot
   sudo certbot renew

   # Or force renewal
   sudo certbot renew --force-renewal

   # Reload web server
   sudo systemctl reload nginx
   ```

2. **Verify Renewal**
   ```bash
   sudo certbot certificates
   ```

3. **Update Certificate Files** (if manual)
   ```bash
   sudo cp new-certificate.crt /etc/ssl/certs/authos.crt
   sudo cp new-private-key.key /etc/ssl/private/authos.key
   sudo chmod 600 /etc/ssl/private/authos.key
   sudo systemctl reload nginx
   ```

4. **Test HTTPS**
   ```bash
   curl -I https://authos.test
   ```

### Prevention
- Set up automatic certificate renewal
- Monitor certificate expiry (30 days notice)
- Test renewal process monthly
- Use monitoring service (SSL Labs)

### Escalation
If certificate issues persist:
- **Level 2**: Infrastructure/DevOps Engineer
- **Level 3**: Security Team

---

## General Troubleshooting Tips

### Quick Health Check
```bash
curl https://authos.test/api/health/detailed | jq
```

### View Live Logs
```bash
# All logs
tail -f storage/logs/*.log

# Specific channel
tail -f storage/logs/api.log

# With filtering
tail -f storage/logs/api.log | grep "error"
```

### Clear All Caches
```bash
herd php artisan optimize:clear
herd restart
```

### Database Console
```bash
herd php artisan tinker
>>> DB::connection()->getPdo();
>>> User::count();
>>> Cache::get('test');
```

### Check System Status
```bash
herd php artisan monitor:health --output-format=table
```

---

## Contact Information

### On-Call Rotation
- **Primary**: ops-primary@example.com
- **Secondary**: ops-secondary@example.com
- **Escalation**: engineering-manager@example.com

### External Support
- **Database**: dba@example.com
- **Infrastructure**: infra@example.com
- **Security**: security@example.com

### Emergency Contacts
- **CTO**: cto@example.com
- **24/7 Hotline**: +1-XXX-XXX-XXXX
