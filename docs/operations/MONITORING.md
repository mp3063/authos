# AuthOS Monitoring & Observability Guide

> **Note**: This monitoring documentation describes the intended production setup. AuthOS is currently in development. These configurations should be validated before production deployment.

## Table of Contents
1. [Overview](#overview)
2. [Health Check Endpoints](#health-check-endpoints)
3. [Metrics Collection](#metrics-collection)
4. [Error Tracking](#error-tracking)
5. [Log Aggregation](#log-aggregation)
6. [Monitoring Dashboards](#monitoring-dashboards)
7. [Alerting](#alerting)
8. [Production Monitoring Tools](#production-monitoring-tools)

## Overview

AuthOS implements comprehensive monitoring and observability with a 99.9% uptime target (production goal) and sub-100ms API response times. The monitoring system includes:

- **Health Checks**: Kubernetes-style readiness and liveness probes
- **Metrics Collection**: Business KPIs and performance metrics
- **Error Tracking**: Categorized error monitoring with alerting
- **Log Aggregation**: Structured JSON logging across multiple channels
- **Dashboards**: Real-time Filament admin widgets
- **Distributed Tracing**: Request correlation IDs

## Health Check Endpoints

### Basic Health Check (Liveness Probe)
```bash
GET /api/health
```

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-10-06T12:00:00+00:00"
}
```

**Use Case**: Kubernetes liveness probe, load balancer health checks

---

### Detailed Health Check
```bash
GET /api/health/detailed
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-06T12:00:00+00:00",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time_ms": 5.23,
      "query_time_ms": 2.15,
      "driver": "pgsql",
      "database": "authos",
      "tables": 30,
      "message": "Database connection successful"
    },
    "cache": {
      "status": "healthy",
      "response_time_ms": 1.42,
      "driver": "database",
      "message": "Cache system operational"
    },
    "oauth": {
      "status": "healthy",
      "response_time_ms": 3.18,
      "clients": 5,
      "message": "OAuth system operational"
    },
    "storage": {
      "status": "healthy",
      "response_time_ms": 2.87,
      "writable": true,
      "message": "Storage system operational"
    },
    "queue": {
      "status": "healthy",
      "response_time_ms": 4.12,
      "driver": "database",
      "failed_jobs": 0,
      "pending_jobs": 3,
      "message": "Queue system operational"
    }
  },
  "version": "1.0.0",
  "environment": "production"
}
```

**Status Codes:**
- `200`: System healthy or degraded
- `503`: System unhealthy or critical

**Status Values:**
- `healthy`: All systems operational
- `degraded`: Some systems experiencing issues but operational
- `unhealthy`: Critical systems failing
- `critical`: System requires immediate attention

---

### Readiness Probe
```bash
GET /api/health/readiness
```

**Response:**
```json
{
  "ready": true,
  "timestamp": "2025-10-06T12:00:00+00:00",
  "checks": {
    "database": "healthy",
    "cache": "healthy"
  }
}
```

**Use Case**: Kubernetes readiness probe - determines if pod can receive traffic

**Status Codes:**
- `200`: Ready to receive traffic
- `503`: Not ready (warming up or experiencing issues)

---

### Liveness Probe
```bash
GET /api/health/liveness
```

**Response:**
```json
{
  "alive": true,
  "timestamp": "2025-10-06T12:00:00+00:00"
}
```

**Use Case**: Kubernetes liveness probe - determines if pod should be restarted

---

### Component-Specific Health Check
```bash
GET /api/health/{component}
```

**Supported Components:**
- `database`
- `cache`
- `oauth`
- `storage`
- `queue`
- `ldap`
- `email`

**Example:**
```bash
GET /api/health/database
```

**Response:**
```json
{
  "component": "database",
  "result": {
    "status": "healthy",
    "response_time_ms": 5.23,
    "query_time_ms": 2.15,
    "driver": "pgsql",
    "database": "authos",
    "tables": 30,
    "message": "Database connection successful"
  },
  "timestamp": "2025-10-06T12:00:00+00:00"
}
```

---

## Metrics Collection

### All System Metrics
```bash
GET /api/v1/monitoring/metrics
Authorization: Bearer {token}
```

**Response includes:**
- Authentication metrics
- OAuth metrics
- API metrics
- Webhook metrics
- User metrics
- Organization metrics
- MFA metrics
- Performance metrics

---

### Authentication Metrics
```bash
GET /api/v1/monitoring/metrics/authentication
```

**Response:**
```json
{
  "today": {
    "total_attempts": 1523,
    "successful": 1487,
    "failed": 36,
    "success_rate": 97.64,
    "mfa_used": 892
  },
  "methods_breakdown": {
    "password": 1200,
    "oauth": 250,
    "social": 73
  },
  "suspicious_ips": [
    {
      "ip_address": "192.168.1.100",
      "attempts": 15
    }
  ],
  "trend_7_days": [...]
}
```

**Key Metrics:**
- Success rate (target: > 95%)
- MFA usage
- Failed login patterns
- Suspicious IP addresses

---

### OAuth Metrics
```bash
GET /api/v1/monitoring/metrics/oauth
```

**Response:**
```json
{
  "active_tokens": 5234,
  "tokens_created_today": 342,
  "tokens_revoked_today": 12,
  "active_refresh_tokens": 2341,
  "pending_auth_codes": 5,
  "tokens_by_client": [...],
  "trend_7_days": [...]
}
```

**Key Metrics:**
- Token generation rate
- Token revocation rate
- Active tokens per client

---

### API Metrics
```bash
GET /api/v1/monitoring/metrics/api
```

**Response:**
```json
{
  "total_requests": 45234,
  "total_errors": 234,
  "error_rate": 0.52,
  "avg_response_time_ms": 45.23,
  "max_response_time_ms": 523.45,
  "min_response_time_ms": 5.12,
  "status_codes": {
    "200": 43000,
    "400": 150,
    "401": 50,
    "500": 34
  },
  "top_endpoints": {
    "GET /api/v1/users": 5234,
    "POST /api/v1/auth/login": 3421
  }
}
```

**Performance Targets:**
- Avg response time: < 100ms (95th percentile)
- Error rate: < 1%
- Max response time: < 500ms

---

### Webhook Metrics
```bash
GET /api/v1/monitoring/metrics/webhooks
```

**Response:**
```json
{
  "total_webhooks": 45,
  "active_webhooks": 42,
  "deliveries_today": 1234,
  "successful_deliveries": 1198,
  "failed_deliveries": 36,
  "success_rate": 97.08,
  "avg_response_time_ms": 234.56,
  "problematic_webhooks": 2,
  "event_breakdown": {
    "user.created": 500,
    "user.updated": 300,
    "user.deleted": 50
  }
}
```

**Key Metrics:**
- Delivery success rate (target: > 95%)
- Average response time
- Failed delivery patterns

---

### Performance Metrics
```bash
GET /api/v1/monitoring/metrics/performance
```

**Response:**
```json
{
  "avg_response_time_ms": 45.23,
  "max_response_time_ms": 523.45,
  "min_response_time_ms": 5.12,
  "avg_memory_usage_bytes": 52428800,
  "slow_queries_count": 5,
  "cache": {
    "hits": 15234,
    "misses": 2341,
    "hit_rate": 86.67
  }
}
```

**Performance Targets:**
- Cache hit rate: > 80%
- Slow queries: < 10 per day
- Memory usage: < 512MB per request

---

## Error Tracking

### Error Statistics
```bash
GET /api/v1/monitoring/errors?date=2025-10-06
```

**Response:**
```json
{
  "critical": 2,
  "error": 15,
  "warning": 45,
  "info": 120,
  "total": 182,
  "by_type": {
    "QueryException": 5,
    "ValidationException": 30,
    "AuthenticationException": 10
  },
  "by_hour": [0, 2, 5, 8, 12, 15, 18, 20, 18, 15, 12, 8, 5, 3, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
```

---

### Error Trends
```bash
GET /api/v1/monitoring/errors/trends?days=7
```

**Response:**
```json
{
  "trends": [
    {
      "date": "2025-10-01",
      "critical": 1,
      "error": 12,
      "warning": 34,
      "total": 47
    },
    ...
  ],
  "days": 7
}
```

---

### Recent Errors
```bash
GET /api/v1/monitoring/errors/recent?limit=50
```

**Response:**
```json
{
  "errors": [
    {
      "id": "err_a1b2c3d4e5f6_1696598400",
      "severity": "error",
      "message": "Database connection timeout",
      "exception": "Illuminate\\Database\\QueryException",
      "file": "/app/Models/User.php",
      "line": 123,
      "timestamp": "2025-10-06T12:00:00+00:00"
    },
    ...
  ],
  "count": 50
}
```

---

## Log Aggregation

### Log Channels

AuthOS uses separate log channels for different concerns:

1. **API Logs** (`storage/logs/api.log`)
   - All API requests/responses
   - Request IDs for tracing
   - Performance metrics
   - Retention: 30 days

2. **Security Logs** (`storage/logs/security.log`)
   - Authentication attempts
   - Authorization failures
   - Suspicious activity
   - Retention: 90 days

3. **OAuth Logs** (`storage/logs/oauth.log`)
   - Token generation/revocation
   - OAuth flow events
   - Client activity
   - Retention: 60 days

4. **Performance Logs** (`storage/logs/performance.log`)
   - Slow queries
   - High memory usage
   - Long-running requests
   - Retention: 7 days

5. **Monitoring Logs** (`storage/logs/monitoring.log`)
   - Health check events
   - System alerts
   - Metric collection errors
   - Retention: 30 days

6. **Webhook Logs** (`storage/logs/webhooks.log`)
   - Webhook deliveries
   - Delivery failures
   - Retry attempts
   - Retention: 30 days

7. **Audit Logs** (`storage/logs/audit.log`)
   - User actions (JSON format)
   - Administrative changes
   - Compliance events
   - Retention: 90 days

### Log Format

**API Logs:**
```json
{
  "timestamp": "2025-10-06T12:00:00+00:00",
  "level": "info",
  "message": "API Request Completed",
  "context": {
    "request_id": "req_abc123_1a2b",
    "method": "GET",
    "url": "https://authos.test/api/v1/users",
    "status_code": 200,
    "execution_time_ms": 45.23,
    "memory_usage_bytes": 5242880,
    "user_id": 1,
    "user_email": "admin@example.com"
  }
}
```

**Security Logs:**
```json
{
  "timestamp": "2025-10-06T12:00:00+00:00",
  "level": "warning",
  "message": "Failed authentication attempt",
  "context": {
    "type": "failed_authentication",
    "email": "user@example.com",
    "ip": "192.168.1.100",
    "reason": "invalid_credentials",
    "user_agent": "Mozilla/5.0..."
  }
}
```

### Request Correlation

Every API request receives a unique request ID in the format: `req_{uniqid}_{random}`

**Headers:**
- Request: Automatically generated
- Response: `X-Request-ID: req_abc123_1a2b`

Use this ID to trace a request across all log files.

---

## Monitoring Dashboards

### Filament Admin Widgets

AuthOS includes 5 monitoring widgets in the Filament admin panel:

1. **System Health Widget**
   - Real-time health status
   - Component checks
   - Response times

2. **Real-Time Metrics Widget**
   - API request counts
   - Response times
   - Success rates
   - Auto-refreshes every 30 seconds

3. **OAuth Flow Monitor Widget**
   - Token generation trends
   - 7-day chart
   - Auto-refreshes every 60 seconds

4. **Security Monitoring Widget**
   - Failed logins
   - Critical errors
   - Suspicious IPs
   - Auto-refreshes every 30 seconds

5. **Error Trends Widget**
   - 7-day error trends
   - Critical/Error/Warning breakdown
   - Auto-refreshes every 60 seconds

### Accessing Dashboards

Navigate to: `https://authos.test/admin`

Widgets appear on the main dashboard for users with monitoring permissions.

---

## Alerting

### Alert Rules

#### Critical Errors
**Trigger**: Any critical error occurs
**Action**: Log to monitoring channel, send email/Slack (production)
**Cooldown**: None

#### Error Rate
**Trigger**: > 10 errors per minute
**Action**: Log alert
**Cooldown**: 1 hour

#### Brute Force Attack
**Trigger**: > 10 failed login attempts from same IP or email per hour
**Action**: Log security alert
**Cooldown**: 1 hour

#### Webhook Failures
**Trigger**: > 50 failed deliveries per day for a webhook
**Action**: Log monitoring alert
**Cooldown**: 24 hours

### Alert Channels

Configure in `.env`:

```bash
# Email Alerts
MONITORING_ALERT_EMAIL=ops@example.com

# Slack Alerts (production)
MONITORING_SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# Thresholds
MONITORING_ERROR_RATE_THRESHOLD=10
MONITORING_BRUTE_FORCE_THRESHOLD=10
MONITORING_WEBHOOK_FAILURE_THRESHOLD=50
```

### Testing Alerts

```bash
# Run health monitoring with alerts
herd php artisan monitor:health --send-alerts
```

---

## Production Monitoring Tools

For production deployments, integrate with these recommended tools:

### 1. Prometheus + Grafana

**Setup:**
```bash
# Install Prometheus exporter
composer require promphp/prometheus_client_php

# Configure metrics endpoint
# GET /api/v1/monitoring/prometheus
```

**Grafana Dashboards:**
- System health overview
- API performance metrics
- OAuth token generation
- Error rates and trends

### 2. New Relic APM

**Installation:**
```bash
# Install New Relic PHP agent
wget -O - https://download.newrelic.com/548C16BF.gpg | apt-key add -
echo "deb http://apt.newrelic.com/debian/ newrelic non-free" > /etc/apt/sources.list.d/newrelic.list
apt-get update
apt-get install newrelic-php5

# Configure
newrelic-install install
```

**Features:**
- Automatic transaction tracing
- Database query monitoring
- External service calls
- Error tracking

### 3. Datadog

**Installation:**
```bash
# Install Datadog PHP tracer
composer require datadog/dd-trace

# Configure in .env
DD_AGENT_HOST=datadog-agent
DD_SERVICE=authos
DD_ENV=production
```

**Monitors:**
- API latency (p95 > 100ms)
- Error rate (> 1%)
- Database query time (> 100ms)
- Memory usage (> 80%)

### 4. Sentry (Error Tracking)

**Installation:**
```bash
composer require sentry/sentry-laravel

# Publish config
herd php artisan vendor:publish --provider="Sentry\Laravel\ServiceProvider"

# Configure in .env
SENTRY_LARAVEL_DSN=https://...@sentry.io/...
```

**Features:**
- Real-time error tracking
- Stack traces
- User context
- Release tracking

### 5. ELK Stack (Logging)

**Components:**
- Elasticsearch: Log storage
- Logstash: Log processing
- Kibana: Visualization

**Log Shipping:**
```bash
# Install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.x.x-amd64.deb
dpkg -i filebeat-7.x.x-amd64.deb

# Configure filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /path/to/authos/storage/logs/*.log
    fields:
      service: authos
      environment: production
```

### 6. Uptime Monitoring

**Recommended Services:**
- Pingdom
- UptimeRobot
- StatusCake

**Endpoints to Monitor:**
- `GET /api/health` (1-minute interval)
- `GET /api/health/readiness` (1-minute interval)
- Critical API endpoints (5-minute interval)

---

## Monitoring Checklist

### Daily
- [ ] Check Filament dashboard for anomalies
- [ ] Review critical errors
- [ ] Monitor authentication success rate
- [ ] Check webhook delivery success rate

### Weekly
- [ ] Review error trends
- [ ] Analyze slow queries
- [ ] Check disk space usage
- [ ] Review suspicious IP list

### Monthly
- [ ] Analyze performance metrics
- [ ] Review cache hit rates
- [ ] Optimize slow endpoints
- [ ] Update alert thresholds

---

## Troubleshooting

### High Error Rate

1. Check recent errors: `GET /api/v1/monitoring/errors/recent`
2. Review error logs: `tail -f storage/logs/monitoring.log`
3. Check system health: `GET /api/health/detailed`
4. Investigate top error types

### Slow Response Times

1. Check performance metrics: `GET /api/v1/monitoring/metrics/performance`
2. Review slow queries: `cat storage/logs/performance.log | grep "slow query"`
3. Check cache hit rate
4. Analyze top endpoints by request count

### Failed Webhooks

1. Check webhook metrics: `GET /api/v1/monitoring/metrics/webhooks`
2. Review webhook logs: `tail -f storage/logs/webhooks.log`
3. Test webhook delivery: `POST /api/v1/webhooks/{id}/test`
4. Verify webhook endpoint availability

---

## Support

For monitoring issues or questions:
- Email: ops@authos.example.com
- Slack: #monitoring-alerts
- Documentation: https://docs.authos.example.com/monitoring
