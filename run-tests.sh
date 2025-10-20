#!/bin/bash

# Test runner script to prevent PHPUnit hanging issues
# Usage: ./run-tests.sh [test-path] [--filter=TestName]
#
# For even faster parallel execution, use: ./fast-tests.sh

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Detect CPU count for optimal parallelism
PROCESSES=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "4")

echo -e "${BLUE}Running tests with timeout protection (${PROCESSES} processes)...${NC}"
echo ""

# Set timeout (10 minutes for parallel execution)
TIMEOUT=600

# Build test command
if [ -z "$1" ]; then
    # Run all tests in parallel
    CMD="herd php artisan test --parallel --processes=${PROCESSES}"
else
    # Run specific test path or filter (may be parallel or single depending on args)
    CMD="herd php artisan test $@"
fi

echo "Command: $CMD"
echo ""

# Run with timeout
timeout $TIMEOUT $CMD
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 124 ]; then
    echo -e "${RED}✗ Tests timed out after ${TIMEOUT} seconds${NC}"
    exit 1
elif [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Tests failed with exit code: $EXIT_CODE${NC}"
    exit $EXIT_CODE
fi
