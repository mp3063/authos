#!/bin/bash

# AuthOS E2E Testing Script
# Runs Laravel Dusk browser tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AuthOS E2E Testing Suite${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if database exists
echo -e "${YELLOW}Checking database...${NC}"
DB_EXISTS=$(herd php artisan db:check --database=authos_dusk 2>&1 || echo "not_exists")

if [[ $DB_EXISTS == *"not_exists"* ]]; then
    echo -e "${YELLOW}Creating test database...${NC}"
    herd php artisan db:create authos_dusk
fi

# Migrate database
echo -e "${YELLOW}Running migrations...${NC}"
herd php artisan migrate:fresh --seed --database=pgsql --env=testing

# Generate Passport keys
echo -e "${YELLOW}Generating Passport keys...${NC}"
herd php artisan passport:keys --force

# Install Passport client
echo -e "${YELLOW}Installing Passport client...${NC}"
herd php artisan passport:client --personal --name="Test Personal Access Client"

# Clear caches
echo -e "${YELLOW}Clearing caches...${NC}"
herd php artisan config:clear
herd php artisan cache:clear
herd php artisan view:clear

# Check if ChromeDriver is running
echo -e "${YELLOW}Checking ChromeDriver...${NC}"
if ! pgrep -x "chromedriver" > /dev/null; then
    echo -e "${YELLOW}Starting ChromeDriver...${NC}"
    herd php artisan dusk:chrome-driver &
    sleep 2
fi

# Run Dusk tests
echo ""
echo -e "${GREEN}Running E2E tests...${NC}"
echo ""

if [ -z "$1" ]; then
    # Run all tests
    herd php artisan dusk --configuration=phpunit.dusk.xml
else
    # Run specific test or directory
    herd php artisan dusk --configuration=phpunit.dusk.xml "$1"
fi

# Capture exit code
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}All E2E tests passed! ✓${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}Some E2E tests failed! ✗${NC}"
    echo -e "${RED}========================================${NC}"
    echo -e "${YELLOW}Check screenshots in tests/Browser/screenshots/${NC}"
    echo -e "${YELLOW}Check console logs in tests/Browser/console/${NC}"
fi

exit $EXIT_CODE
