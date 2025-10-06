#!/bin/bash

###############################################################################
# AuthOS Deployment Script
# This script handles the deployment process for both staging and production
###############################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

# Default values
ENVIRONMENT="${1:-staging}"
SKIP_BACKUP="${SKIP_BACKUP:-false}"
SKIP_TESTS="${SKIP_TESTS:-false}"

###############################################################################
# Helper Functions
###############################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    local required_commands=("php" "composer" "npm" "rsync" "ssh")

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Check PHP version
    local php_version=$(php -r 'echo PHP_VERSION;')
    log_info "PHP version: $php_version"

    if [[ ! $php_version =~ ^8\.[34] ]]; then
        log_error "PHP 8.3 or 8.4 is required"
        exit 1
    fi

    log_info "All requirements met"
}

run_tests() {
    if [ "$SKIP_TESTS" = "true" ]; then
        log_warn "Skipping tests as requested"
        return 0
    fi

    log_info "Running tests..."
    cd "$PROJECT_ROOT"

    php artisan test --testsuite=Unit || {
        log_error "Unit tests failed"
        exit 1
    }

    log_info "Tests passed"
}

build_application() {
    log_info "Building application..."
    cd "$PROJECT_ROOT"

    # Install dependencies
    log_info "Installing Composer dependencies..."
    composer install --prefer-dist --no-progress --no-interaction --no-dev --optimize-autoloader

    # Install and build frontend assets
    log_info "Installing NPM dependencies..."
    npm ci

    log_info "Building frontend assets..."
    npm run build

    # Cache configurations
    log_info "Caching configurations..."
    php artisan config:cache
    php artisan route:cache
    php artisan view:cache

    log_info "Build completed"
}

create_artifact() {
    log_info "Creating deployment artifact..."
    cd "$PROJECT_ROOT"

    local artifact_name="authos-${ENVIRONMENT}-${TIMESTAMP}.tar.gz"
    local artifact_path="storage/app/deployments/${artifact_name}"

    mkdir -p "storage/app/deployments"

    tar -czf "$artifact_path" \
        --exclude='.git' \
        --exclude='node_modules' \
        --exclude='tests' \
        --exclude='storage/logs/*' \
        --exclude='storage/framework/cache/*' \
        --exclude='storage/framework/sessions/*' \
        --exclude='storage/framework/views/*' \
        --exclude='.env*' \
        --exclude='phpunit.xml' \
        .

    # Generate checksum
    cd "storage/app/deployments"
    sha256sum "$artifact_name" > "${artifact_name}.sha256"

    log_info "Artifact created: $artifact_path"
    echo "$artifact_path"
}

verify_artifact() {
    local artifact_path="$1"

    log_info "Verifying artifact checksum..."

    local artifact_dir=$(dirname "$artifact_path")
    local artifact_name=$(basename "$artifact_path")

    cd "$artifact_dir"

    if ! sha256sum -c "${artifact_name}.sha256" > /dev/null 2>&1; then
        log_error "Artifact checksum verification failed"
        exit 1
    fi

    log_info "Artifact verified"
}

deploy_to_server() {
    local artifact_path="$1"
    local server_host="$2"
    local server_user="$3"
    local deploy_path="$4"

    log_info "Deploying to ${server_host}..."

    # Create release directory
    local release_dir="${TIMESTAMP}"

    # Upload artifact
    log_info "Uploading artifact..."
    scp "$artifact_path" "${server_user}@${server_host}:/tmp/"

    # Extract and setup on server
    local artifact_name=$(basename "$artifact_path")

    ssh "${server_user}@${server_host}" bash <<EOF
        set -e

        cd "${deploy_path}"

        # Create release directory
        mkdir -p "releases/${release_dir}"

        # Extract artifact
        tar -xzf "/tmp/${artifact_name}" -C "releases/${release_dir}"
        rm "/tmp/${artifact_name}"

        # Setup shared directories
        mkdir -p shared/storage/{app,framework,logs}
        mkdir -p shared/storage/framework/{cache,sessions,views}

        # Link shared directories
        cd "releases/${release_dir}"
        rm -rf storage
        ln -nfs ../../shared/storage storage

        # Link .env
        ln -nfs ../../shared/.env .env

        # Set permissions
        chmod -R 755 bootstrap/cache

        echo "Release prepared: ${release_dir}"
EOF

    log_info "Artifact deployed to server"
    echo "$release_dir"
}

run_migrations() {
    local server_host="$1"
    local server_user="$2"
    local deploy_path="$3"
    local release_dir="$4"

    log_info "Running database migrations..."

    ssh "${server_user}@${server_host}" bash <<EOF
        set -e
        cd "${deploy_path}/releases/${release_dir}"

        # Run migrations
        php artisan migrate --force

        echo "Migrations completed"
EOF

    log_info "Migrations completed"
}

switch_release() {
    local server_host="$1"
    local server_user="$2"
    local deploy_path="$3"
    local release_dir="$4"

    log_info "Switching to new release..."

    ssh "${server_user}@${server_host}" bash <<EOF
        set -e
        cd "${deploy_path}"

        # Put in maintenance mode
        if [ -d current ]; then
            cd current
            php artisan down --render="errors::503" --retry=60 || true
            cd ..
        fi

        # Switch symlink atomically
        ln -nfs "releases/${release_dir}" current_tmp
        mv -Tf current_tmp current

        # Post-deployment tasks
        cd current

        # Cache configurations
        php artisan config:cache
        php artisan route:cache
        php artisan view:cache

        # Warm caches
        php artisan cache:warm || true

        # Restart queue workers
        php artisan queue:restart

        # Bring back up
        php artisan up

        echo "Release switched successfully"
EOF

    log_info "Release switched"
}

health_check() {
    local url="$1"
    local max_attempts=30

    log_info "Running health check..."

    sleep 5  # Wait for application to stabilize

    for ((i=1; i<=max_attempts; i++)); do
        if curl -f -s "${url}/api/v1/health" > /dev/null 2>&1; then
            log_info "Health check passed!"
            return 0
        fi

        log_warn "Health check attempt $i failed, retrying..."
        sleep 5
    done

    log_error "Health check failed after $max_attempts attempts"
    return 1
}

cleanup_old_releases() {
    local server_host="$1"
    local server_user="$2"
    local deploy_path="$3"
    local keep_releases="${4:-5}"

    log_info "Cleaning up old releases (keeping last ${keep_releases})..."

    ssh "${server_user}@${server_host}" bash <<EOF
        set -e
        cd "${deploy_path}/releases"

        # Keep only the specified number of releases
        ls -t | tail -n +$((keep_releases + 1)) | xargs -r rm -rf

        echo "Cleanup completed"
EOF

    log_info "Old releases cleaned up"
}

###############################################################################
# Main Deployment Flow
###############################################################################

main() {
    log_info "Starting deployment to ${ENVIRONMENT}..."

    # Check requirements
    check_requirements

    # Load environment-specific configuration
    if [ -f "${SCRIPT_DIR}/config/${ENVIRONMENT}.env" ]; then
        source "${SCRIPT_DIR}/config/${ENVIRONMENT}.env"
    else
        log_error "Configuration file not found: ${SCRIPT_DIR}/config/${ENVIRONMENT}.env"
        exit 1
    fi

    # Validate required environment variables
    required_vars=("SERVER_HOST" "SERVER_USER" "DEPLOY_PATH" "APP_URL")
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            log_error "Required variable not set: $var"
            exit 1
        fi
    done

    # Run tests
    run_tests

    # Build application
    build_application

    # Create artifact
    artifact_path=$(create_artifact)

    # Verify artifact
    verify_artifact "$artifact_path"

    # Deploy to server
    release_dir=$(deploy_to_server "$artifact_path" "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH")

    # Run migrations
    run_migrations "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH" "$release_dir"

    # Switch to new release
    switch_release "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH" "$release_dir"

    # Health check
    if ! health_check "$APP_URL"; then
        log_error "Health check failed, initiating rollback..."

        # Rollback logic here
        log_error "Manual intervention required"
        exit 1
    fi

    # Cleanup old releases
    cleanup_old_releases "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH" 5

    log_info "Deployment completed successfully!"
    log_info "Version: ${release_dir}"
    log_info "Environment: ${ENVIRONMENT}"
    log_info "URL: ${APP_URL}"
}

# Run main function
main "$@"
