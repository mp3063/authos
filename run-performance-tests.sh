#!/bin/bash

# AuthOS Performance Test Suite Runner
# This script runs all performance tests and generates comprehensive reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PHPUNIT="./vendor/bin/phpunit"
PHP="herd php"
ARTISAN="herd php artisan"

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}         AuthOS Performance Test Suite${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo ""

# Check if application is ready
echo -e "${YELLOW}Checking application status...${NC}"
if ! $ARTISAN about > /dev/null 2>&1; then
    echo -e "${RED}Error: Application not ready. Please ensure the application is configured correctly.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Application ready${NC}"
echo ""

# Clear caches
echo -e "${YELLOW}Preparing test environment...${NC}"
$ARTISAN config:clear > /dev/null 2>&1
$ARTISAN cache:clear > /dev/null 2>&1
echo -e "${GREEN}✓ Caches cleared${NC}"
echo ""

# Run performance tests
echo -e "${BLUE}Running performance tests...${NC}"
echo ""

# API Response Time Tests
echo -e "${YELLOW}1. API Response Time Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=ApiResponseTimeTest --no-coverage || true
echo ""

# Bulk Operations Tests
echo -e "${YELLOW}2. Bulk Operations Performance Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=BulkOperationsPerformanceTest --no-coverage || true
echo ""

# Cache Performance Tests
echo -e "${YELLOW}3. Cache Effectiveness Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=CacheEffectivenessTest --no-coverage || true
echo ""

# Existing Cache Performance Tests
echo -e "${YELLOW}4. Cache Performance Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=CachePerformanceTest --no-coverage || true
echo ""

# Compression Tests
echo -e "${YELLOW}5. Compression Performance Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=CompressionPerformanceTest --no-coverage || true
echo ""

# Database Query Tests
echo -e "${YELLOW}6. Database Query Performance Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=DatabaseQueryPerformanceTest --no-coverage || true
echo ""

# Memory Usage Tests
echo -e "${YELLOW}7. Memory Usage Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=MemoryUsageTest --no-coverage || true
echo ""

# Throughput Tests
echo -e "${YELLOW}8. Throughput Tests${NC}"
$PHP $PHPUNIT --testsuite=Performance --filter=ThroughputTest --no-coverage || true
echo ""

# Generate comprehensive report
echo -e "${BLUE}==================================================================${NC}"
echo -e "${YELLOW}Generating performance report...${NC}"

if [ -f "storage/app/performance_reports" ]; then
    LATEST_REPORT=$(ls -t storage/app/performance_reports/*.html 2>/dev/null | head -1)
    if [ -n "$LATEST_REPORT" ]; then
        echo -e "${GREEN}✓ Report generated: $LATEST_REPORT${NC}"
    fi
fi

# Check for baselines
if [ -f "storage/app/performance_baselines.json" ]; then
    echo -e "${GREEN}✓ Baselines recorded${NC}"
else
    echo -e "${YELLOW}⚠ No baselines found. These will be created after the first run.${NC}"
fi

echo ""
echo -e "${BLUE}==================================================================${NC}"
echo -e "${GREEN}Performance testing complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Review the generated reports in storage/app/performance_reports/"
echo "  2. Compare results against Phase 7 targets"
echo "  3. Run K6 load tests: k6 run tests/Performance/k6/authentication-load.js"
echo "  4. Address any performance issues identified"
echo ""
echo -e "${BLUE}Phase 7 Performance Targets:${NC}"
echo "  - Authentication P95 response time: < 100ms"
echo "  - User management P95 response time: < 150ms"
echo "  - OAuth token generation P95: < 200ms"
echo "  - Bulk operations (1000 records): < 5 seconds"
echo "  - Cache hit ratio: >= 80%"
echo "  - Queries per request: <= 10"
echo "  - Memory per request: <= 20MB"
echo "  - Compression ratio: >= 60%"
echo ""
echo -e "${BLUE}==================================================================${NC}"
