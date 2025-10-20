#!/bin/bash
# Cleanup script for parallel test database files
# Run this after parallel test execution to remove temporary SQLite files

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Cleaning up parallel test database files...${NC}"

# Find and remove all testing_parallel_*.sqlite files
DB_DIR="database"
PATTERN="testing_parallel_*.sqlite"

if [ -d "$DB_DIR" ]; then
    FILES=$(find "$DB_DIR" -name "$PATTERN" -type f 2>/dev/null || true)

    if [ -n "$FILES" ]; then
        COUNT=$(echo "$FILES" | wc -l | tr -d ' ')
        echo -e "Found ${COUNT} test database file(s):"
        echo "$FILES"
        echo ""

        # Remove files
        find "$DB_DIR" -name "$PATTERN" -type f -delete

        echo -e "${GREEN}✓ Cleanup complete! Removed ${COUNT} file(s).${NC}"
    else
        echo -e "${GREEN}✓ No test database files found. Already clean!${NC}"
    fi
else
    echo -e "${YELLOW}Warning: database/ directory not found.${NC}"
fi
