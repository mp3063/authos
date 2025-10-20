#!/bin/bash
# Fast parallel test runner using paratest
# Usage: ./fast-tests.sh [path] [--processes=N]
#
# Examples:
#   ./fast-tests.sh                     # Run all tests in parallel
#   ./fast-tests.sh tests/Unit          # Run only unit tests
#   ./fast-tests.sh --processes=8       # Use 8 parallel processes
#   ./fast-tests.sh tests/Unit --processes=4

set -e

# Default to CPU count
PROCESSES=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "4")

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   Fast Parallel Test Runner (Paratest)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Parse arguments
PATH_ARG=""
EXTRA_ARGS=""

for arg in "$@"; do
    if [[ $arg == --processes=* ]]; then
        PROCESSES="${arg#*=}"
        EXTRA_ARGS="$EXTRA_ARGS $arg"
    elif [[ $arg == tests/* ]]; then
        PATH_ARG="$arg"
    elif [[ $arg == --* ]]; then
        EXTRA_ARGS="$EXTRA_ARGS $arg"
    else
        PATH_ARG="$arg"
    fi
done

echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Processes: ${GREEN}${PROCESSES}${NC}"
echo -e "  Path: ${GREEN}${PATH_ARG:-all tests}${NC}"
echo ""

# Run paratest
echo -e "${BLUE}Running tests in parallel...${NC}"
echo ""

if [ -n "$PATH_ARG" ]; then
    herd php vendor/bin/paratest \
        --processes=$PROCESSES \
        --runner=WrapperRunner \
        $EXTRA_ARGS \
        "$PATH_ARG"
else
    herd php vendor/bin/paratest \
        --processes=$PROCESSES \
        --runner=WrapperRunner \
        $EXTRA_ARGS
fi

# Capture exit code
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${YELLOW}✗ Some tests failed (exit code: $EXIT_CODE)${NC}"
fi

# Cleanup parallel test database files
echo ""
echo -e "${BLUE}Cleaning up test databases...${NC}"
./cleanup-test-dbs.sh

exit $EXIT_CODE
