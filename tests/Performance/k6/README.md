# K6 Load Testing Scripts

This directory contains K6 load testing scripts for the AuthOS application. K6 is a modern load testing tool built for developers.

## Installation

### macOS
```bash
brew install k6
```

### Linux
```bash
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

### Windows
```powershell
choco install k6
```

Or download from: https://k6.io/docs/getting-started/installation/

## Available Tests

### 1. Authentication Load Test (`authentication-load.js`)
Tests authentication endpoints under increasing load.

**Target:** 100 concurrent users
**Duration:** ~6 minutes
**Tests:**
- Login endpoint performance
- Token generation
- Profile retrieval with authentication

**Run:**
```bash
k6 run authentication-load.js
```

**With custom base URL:**
```bash
k6 run -e BASE_URL=https://your-domain.com authentication-load.js
```

### 2. API Stress Test (`api-stress-test.js`)
Stress tests the API with up to 1000 concurrent users.

**Target:** 1000 concurrent users
**Duration:** ~11 minutes
**Tests:**
- User management endpoints
- Application management
- Profile endpoints
- Mixed read operations

**Run:**
```bash
k6 run api-stress-test.js
```

**With access token (skip authentication):**
```bash
k6 run -e BASE_URL=https://your-domain.com -e ACCESS_TOKEN=your_token api-stress-test.js
```

### 3. OAuth Load Test (`oauth-load-test.js`)
Tests OAuth 2.0 token generation and usage.

**Target:** 100 concurrent users
**Duration:** ~6 minutes
**Tests:**
- OAuth password grant flow
- Token generation rate
- Token introspection
- Token usage

**Run:**
```bash
k6 run oauth-load-test.js
```

**With custom credentials:**
```bash
k6 run \
  -e BASE_URL=https://your-domain.com \
  -e CLIENT_ID=your_client_id \
  -e CLIENT_SECRET=your_client_secret \
  -e USERNAME=user@example.com \
  -e PASSWORD=your_password \
  oauth-load-test.js
```

## Performance Thresholds

All tests include performance thresholds:

### Authentication Test
- P95 response time < 200ms
- Error rate < 5%

### API Stress Test
- P95 response time < 500ms
- P99 response time < 1000ms
- Error rate < 10%

### OAuth Test
- Token generation P95 < 200ms
- Error rate < 5%

## Running All Tests

Create a shell script to run all tests:

```bash
#!/bin/bash
echo "Running performance tests..."

echo "\n=== Authentication Load Test ==="
k6 run authentication-load.js

echo "\n=== API Stress Test ==="
k6 run api-stress-test.js

echo "\n=== OAuth Load Test ==="
k6 run oauth-load-test.js

echo "\nAll performance tests completed!"
```

## Output Options

### JSON Output
```bash
k6 run --out json=results.json authentication-load.js
```

### InfluxDB Output (for Grafana)
```bash
k6 run --out influxdb=http://localhost:8086/k6 authentication-load.js
```

### CSV Output
```bash
k6 run --out csv=results.csv authentication-load.js
```

## Cloud Integration

Run tests in K6 Cloud for advanced analytics:

```bash
k6 cloud authentication-load.js
```

## Custom Test Scenarios

### Quick Smoke Test (10 users, 1 minute)
```bash
k6 run --vus 10 --duration 1m authentication-load.js
```

### Spike Test (instant 500 users)
```bash
k6 run --vus 500 --duration 30s api-stress-test.js
```

### Soak Test (100 users, 1 hour)
```bash
k6 run --vus 100 --duration 1h authentication-load.js
```

## Interpreting Results

### Key Metrics

- **http_req_duration**: Total request time (sending + waiting + receiving)
- **http_req_waiting**: Time to first byte (TTFB)
- **http_req_sending**: Time sending data
- **http_req_receiving**: Time receiving data
- **http_reqs**: Total HTTP requests
- **vus**: Virtual users (concurrent users)

### Success Criteria

✅ **Good Performance:**
- P95 < threshold
- Error rate < 5%
- Stable response times under load

⚠️ **Warning:**
- P95 approaching threshold
- Error rate 5-10%
- Response times increasing with load

❌ **Poor Performance:**
- P95 exceeds threshold
- Error rate > 10%
- Server errors (5xx)

## Best Practices

1. **Always warm up your application** before running load tests
2. **Start with small loads** and gradually increase
3. **Monitor server resources** (CPU, memory, database) during tests
4. **Run tests multiple times** to get consistent baselines
5. **Test in an isolated environment** that matches production
6. **Clear caches between tests** for consistent results
7. **Use realistic test data** and user behavior patterns

## Troubleshooting

### Connection Refused
```bash
# Check if application is running
curl http://authos.test/api/v1/health
```

### High Error Rates
- Check application logs
- Verify database connection pool size
- Check rate limiting configuration
- Ensure test data is set up correctly

### Inconsistent Results
- Run tests multiple times
- Ensure no other processes are consuming resources
- Verify network stability
- Check for time-based issues (cache TTL, session expiration)

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Performance Tests

on:
  pull_request:
    branches: [ main ]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup K6
        run: |
          sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
          echo "deb https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
          sudo apt-get update
          sudo apt-get install k6
      - name: Run performance tests
        run: |
          k6 run tests/Performance/k6/authentication-load.js
```

## References

- [K6 Documentation](https://k6.io/docs/)
- [K6 Test Types](https://k6.io/docs/test-types/introduction/)
- [K6 Metrics Reference](https://k6.io/docs/using-k6/metrics/)
- [K6 Thresholds](https://k6.io/docs/using-k6/thresholds/)
