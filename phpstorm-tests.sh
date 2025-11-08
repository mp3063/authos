#!/bin/bash
# Run tests exactly like PhpStorm does
# This mimics PhpStorm's configuration for comparison

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}   PhpStorm-Style Test Runner (Sequential, :memory:)${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Parse arguments
TEST_PATH="${1:-tests}"

echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Runner: ${GREEN}Pure PHPUnit (sequential)${NC}"
echo -e "  Config: ${GREEN}phpunit.xml${NC}"
echo -e "  Database: ${GREEN}:memory:${NC}"
echo -e "  Path: ${GREEN}${TEST_PATH}${NC}"
echo ""

echo -e "${BLUE}Running tests sequentially...${NC}"
echo ""

# Run pure PHPUnit exactly like PhpStorm
herd php vendor/bin/phpunit \
    --configuration=phpunit.xml \
    --colors=always \
    "$TEST_PATH"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Tests failed (exit code: $EXIT_CODE)${NC}"
fi

exit $EXIT_CODE
