#!/bin/bash

# Test runner script to prevent PHPUnit hanging issues
# Usage: ./run-tests.sh [test-path] [--filter=TestName]

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Running tests with timeout protection..."

# Set timeout (5 minutes default)
TIMEOUT=300

# Build test command
if [ -z "$1" ]; then
    # Run all tests
    CMD="herd php artisan test --parallel --processes=4"
else
    # Run specific test path or filter
    CMD="herd php artisan test $@"
fi

echo "Command: $CMD"
echo ""

# Run with timeout
timeout $TIMEOUT $CMD
EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ]; then
    echo -e "${RED}Tests timed out after ${TIMEOUT} seconds${NC}"
    exit 1
elif [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Tests failed with exit code: $EXIT_CODE${NC}"
    exit $EXIT_CODE
fi
