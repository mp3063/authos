# AuthOS Performance Testing Suite

Comprehensive performance testing framework for validating Phase 7 optimization targets and ensuring production-ready performance.

## Overview

This testing suite provides:
- **API Response Time Tests** - Validate endpoint performance under various loads
- **Cache Effectiveness Tests** - Measure cache hit ratios and multi-layer caching
- **Database Performance Tests** - Detect N+1 queries and validate query optimization
- **Compression Tests** - Verify response compression ratios and overhead
- **Memory Usage Tests** - Ensure memory efficiency and detect leaks
- **Throughput Tests** - Measure requests per second and sustained load capacity
- **Bulk Operations Tests** - Validate performance with large datasets
- **Load Testing (K6)** - Simulate real-world concurrent user scenarios

## Quick Start

### Run All Performance Tests

```bash
# Using the test runner script
./run-performance-tests.sh

# Using Artisan command
herd php artisan performance:test

# Using PHPUnit directly
herd php ./vendor/bin/phpunit --testsuite=Performance
```

### Run Specific Test Suites

```bash
# API response time tests
herd php artisan performance:test --suite=api

# Cache performance tests
herd php artisan performance:test --suite=cache

# Database query tests
herd php artisan performance:test --suite=database

# Compression tests
herd php artisan performance:test --suite=compression

# Memory usage tests
herd php artisan performance:test --suite=memory

# Throughput tests
herd php artisan performance:test --suite=throughput

# Bulk operations tests
herd php artisan performance:test --suite=bulk
```

### Generate Performance Report

```bash
herd php artisan performance:test --report
```

Reports are generated in:
- **JSON**: `storage/app/performance_reports/performance_report_*.json`
- **HTML**: `storage/app/performance_reports/performance_report_*.html`
- **Text**: `storage/app/performance_reports/performance_report_*.txt`

## Phase 7 Performance Targets

| Metric | Target | Test Coverage |
|--------|--------|---------------|
| Authentication P95 Response Time | < 100ms | ✅ ApiResponseTimeTest |
| User Management P95 Response Time | < 150ms | ✅ ApiResponseTimeTest |
| OAuth Token Generation P95 | < 200ms | ✅ ApiResponseTimeTest |
| Bulk Operations (1000 records) | < 5 seconds | ✅ BulkOperationsPerformanceTest |
| Cache Hit Ratio | >= 80% | ✅ CacheEffectivenessTest |
| Queries Per Request | <= 10 | ✅ DatabaseQueryPerformanceTest |
| Memory Per Request | <= 20MB | ✅ MemoryUsageTest |
| Compression Ratio | >= 60% | ✅ CompressionPerformanceTest |

## Test Structure

### 1. API Response Time Tests (`ApiResponseTimeTest.php`)

Tests all major API endpoints for performance:

**Test Methods:**
- `authentication_login_meets_performance_target()` - Login endpoint P95 < 100ms
- `authentication_register_meets_performance_target()` - Registration P95 < 150ms
- `user_list_endpoint_meets_performance_target()` - User list P95 < 150ms
- `user_show_endpoint_meets_performance_target()` - User details P95 < 100ms
- `oauth_token_generation_meets_performance_target()` - OAuth tokens P95 < 200ms
- `application_list_endpoint_meets_performance_target()` - Apps list P95 < 150ms
- `organization_statistics_endpoint_meets_performance_target()` - Stats P95 < 200ms
- `profile_endpoint_meets_performance_target()` - Profile P95 < 100ms

**Metrics Tracked:**
- P95 response time
- Average query count
- Memory usage

### 2. Bulk Operations Tests (`BulkOperationsPerformanceTest.php`)

Validates performance with large datasets:

**Test Methods:**
- `bulk_user_import_100_records_meets_target()` - Import 100 users < 2s
- `bulk_user_import_1000_records_meets_target()` - Import 1000 users < 5s
- `bulk_user_export_100_records_meets_target()` - Export 100 users < 1s
- `bulk_user_export_1000_records_meets_target()` - Export 1000 users < 3s
- `bulk_user_update_meets_target()` - Update 50 users < 1.5s
- `bulk_user_delete_meets_target()` - Delete 30 users < 1s
- `pagination_with_large_dataset_meets_target()` - Pagination < 200ms

**Metrics Tracked:**
- Duration
- Memory usage
- Query count
- Records per second

### 3. Cache Effectiveness Tests (`CacheEffectivenessTest.php`)

Measures caching performance and effectiveness:

**Test Methods:**
- `cache_hit_ratio_meets_target()` - Hit ratio >= 80%
- `cache_warming_performance_meets_target()` - Warming < 10s
- `cached_vs_uncached_performance_comparison()` - 10x speedup
- `cache_invalidation_impact_is_minimal()` - Invalidation < 50ms
- `multi_layer_cache_effectiveness()` - Query reduction
- `cache_memory_efficiency()` - Memory per item < 0.5MB
- `cache_ttl_expiration_works_correctly()` - TTL validation
- `concurrent_cache_access_performance()` - Read < 10ms avg

**Metrics Tracked:**
- Hit ratio percentage
- Cache operation duration
- Memory efficiency
- Speedup multiplier

### 4. Compression Tests (`CompressionPerformanceTest.php`)

Validates response compression:

**Test Methods:**
- `json_response_compression_ratio_meets_target()` - Ratio >= 60%
- `compression_overhead_is_acceptable()` - Overhead < 20%
- `large_payload_compression_effectiveness()` - Large payloads >= 70%
- `different_compression_levels_comparison()` - Level optimization
- `minimal_json_response_size_optimization()` - Field selection

**Metrics Tracked:**
- Compression ratio
- Overhead percentage
- Size reduction
- Compression time

### 5. Database Query Tests (`DatabaseQueryPerformanceTest.php`)

Detects query performance issues:

**Test Methods:**
- `user_query_with_eager_loading_performs_efficiently()` - < 10 queries
- `authentication_log_pagination_performs_efficiently()` - < 5 queries
- `organization_statistics_query_performs_efficiently()` - < 200ms
- `bulk_operations_perform_efficiently()` - 100 users < 2s
- `complex_filtering_query_performs_efficiently()` - < 100ms
- `aggregate_queries_perform_efficiently()` - < 200ms
- `no_n_plus_one_queries_in_user_list()` - N+1 detection
- `index_usage_improves_query_performance()` - Index validation

**Metrics Tracked:**
- Query count
- Duration
- Index usage
- N+1 detection

### 6. Memory Usage Tests (`MemoryUsageTest.php`)

Ensures memory efficiency:

**Test Methods:**
- `memory_per_request_meets_target()` - Avg < 20MB, Max < 30MB
- `no_memory_leaks_in_repeated_requests()` - Growth < 10%
- `large_dataset_memory_efficiency()` - < 0.5MB per record
- `collection_memory_usage_optimization()` - Chunking benefits
- `eager_loading_memory_impact()` - Memory comparison
- `authentication_log_pagination_memory_efficiency()` - < 15MB
- `peak_memory_under_concurrent_load_simulation()` - Peak < 50MB

**Metrics Tracked:**
- Average memory per request
- Peak memory usage
- Memory growth
- Memory per record

### 7. Throughput Tests (`ThroughputTest.php`)

Measures system capacity:

**Test Methods:**
- `authentication_requests_per_second()` - > 10 req/s
- `api_read_requests_per_second()` - > 20 req/s
- `oauth_token_generation_rate()` - > 5 tokens/s
- `user_creation_rate()` - > 5 users/s
- `sustained_load_over_time()` - 10s sustained > 10 req/s
- `concurrent_user_operations()` - Mixed operations
- `database_write_throughput()` - > 50 writes/s

**Metrics Tracked:**
- Requests per second
- Tokens per second
- Records per second
- Sustained throughput

### 8. Load Testing (K6)

Simulate real-world load scenarios:

**Scripts:**
- `authentication-load.js` - 100 concurrent users, 6 minutes
- `api-stress-test.js` - Up to 1000 concurrent users, 11 minutes
- `oauth-load-test.js` - OAuth flow testing, 100 users

See `tests/Performance/k6/README.md` for detailed K6 documentation.

## Performance Test Framework

### Base Class: `PerformanceTestCase`

All performance tests extend this base class which provides:

**Measurement Methods:**
```php
// Start measuring
$this->startMeasuring('operation_name');

// Stop and get metrics
$metrics = $this->stopMeasuring('operation_name');

// Or use measure() helper
$result = $this->measure(function () {
    // Your code here
}, 'operation_name');
```

**Assertion Methods:**
```php
$this->assertResponseTime($actualMs, $thresholdMs);
$this->assertQueryCount($actual, $threshold);
$this->assertMemoryUsage($actualMb, $thresholdMb);
$this->assertPerformanceTargets($metrics, $targets);
```

**Baseline Management:**
```php
// Record baseline
$this->recordBaseline('test_name', $metrics);

// Compare against baseline
$comparison = $this->compareAgainstBaseline('test_name', $currentMetrics);
```

**Metrics Captured:**
- Duration (milliseconds)
- Memory used (megabytes)
- Peak memory (megabytes)
- Query count (if enabled)

## Report Generation

### Performance Report Generator

The `PerformanceReportGenerator` class creates comprehensive reports with:

**Report Contents:**
- Executive summary with overall health score
- Detailed test results with metrics
- Baseline comparisons with percent changes
- Target compliance checking
- Performance recommendations with severity levels
- Trend analysis

**Report Formats:**
- **JSON** - Machine-readable for CI/CD integration
- **HTML** - Visual dashboard with charts and colors
- **Text** - Console-friendly summary

**Health Scores:**
- **Excellent** - >50% improved metrics, <10% degraded
- **Good** - >30% improved metrics, <20% degraded
- **Fair** - <30% degraded metrics
- **Poor** - >30% degraded metrics

## Baseline Management

### Recording Baselines

```bash
# First run establishes baselines
./run-performance-tests.sh

# Baselines stored in storage/app/performance_baselines.json
```

### Comparing Against Baselines

Subsequent test runs automatically compare against baselines:

**Comparison Metrics:**
- Baseline value
- Current value
- Difference
- Percent change
- Status (improved/stable/degraded)

### Resetting Baselines

```bash
# Delete baseline file to start fresh
rm storage/app/performance_baselines.json

# Re-run tests to establish new baselines
./run-performance-tests.sh
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Performance Tests

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *' # Daily at 2 AM

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'

      - name: Install Dependencies
        run: composer install

      - name: Run Performance Tests
        run: ./run-performance-tests.sh

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: performance-reports
          path: storage/app/performance_reports/

      - name: Check Performance Thresholds
        run: |
          # Add custom threshold checking logic
          # Fail build if critical targets missed
```

## Best Practices

### 1. Test Environment

- Use isolated test environment
- Ensure consistent hardware/network
- Clear caches between test runs
- Seed database with consistent data
- Disable unnecessary services

### 2. Running Tests

- Run multiple iterations for statistical significance
- Run tests during off-peak hours
- Monitor system resources during tests
- Record environmental conditions
- Document any anomalies

### 3. Interpreting Results

- Focus on trends over absolute values
- Compare against baselines, not arbitrary numbers
- Investigate sudden performance changes
- Validate improvements with multiple runs
- Consider p95/p99 over averages

### 4. Performance Optimization

1. **Identify** bottlenecks using profiling tests
2. **Prioritize** optimizations by impact
3. **Implement** changes incrementally
4. **Validate** with performance tests
5. **Document** optimizations and results

## Troubleshooting

### Tests Timing Out

```bash
# Increase PHPUnit timeout
<ini name="max_execution_time" value="300"/>
```

### Memory Exhaustion

```bash
# Increase memory limit in phpunit.xml
<ini name="memory_limit" value="2G"/>
```

### Inconsistent Results

- Run tests multiple times
- Check for background processes
- Verify database state
- Clear all caches
- Check for time-based issues (TTL, sessions)

### Database Connection Issues

```bash
# Check database configuration
herd php artisan config:clear
herd php artisan migrate:fresh --seed
```

## Performance Monitoring in Production

### Continuous Monitoring

1. **Application Performance Monitoring (APM)**
   - New Relic, Datadog, or Scout APM
   - Real-time metrics and alerts

2. **Database Monitoring**
   - Query performance tracking
   - Slow query log analysis
   - Connection pool monitoring

3. **Cache Monitoring**
   - Hit/miss ratios
   - Memory usage
   - Eviction rates

4. **Infrastructure Monitoring**
   - CPU, memory, disk I/O
   - Network latency
   - Response times

### Alert Thresholds

Set alerts for:
- P95 response time > target
- Error rate > 1%
- Cache hit ratio < 70%
- Memory usage > 80%
- CPU usage > 80%

## Additional Resources

### Tools

- **K6** - Load testing tool (https://k6.io)
- **Apache Bench** - HTTP load testing
- **Laravel Telescope** - Query profiling
- **Blackfire** - PHP profiler
- **XDebug** - Detailed profiling

### Laravel Performance

- [Laravel Performance](https://laravel.com/docs/optimization)
- [Database Query Optimization](https://laravel.com/docs/queries)
- [Caching](https://laravel.com/docs/cache)
- [Queue Workers](https://laravel.com/docs/queues)

### General Performance

- [Web Performance](https://web.dev/performance/)
- [Database Indexing](https://use-the-index-luke.com/)
- [HTTP/2 & HTTP/3](https://www.cloudflare.com/learning/performance/http2-vs-http1.1/)

## Support

For questions or issues with the performance testing suite:

1. Check this README
2. Review test output and reports
3. Check baselines and comparisons
4. Run tests in verbose mode: `herd php artisan performance:test -v`
5. Review individual test files for implementation details

## Changelog

### Version 1.0.0 (2025)
- Initial comprehensive performance testing suite
- Phase 7 optimization validation
- Multi-format reporting system
- K6 load testing integration
- Baseline comparison system
- CI/CD integration support
