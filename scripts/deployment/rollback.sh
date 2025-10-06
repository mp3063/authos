#!/bin/bash

###############################################################################
# AuthOS Rollback Script
# This script handles rollback to previous release
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
ENVIRONMENT="${1:-staging}"
RELEASE_NUMBER="${2:-1}"  # 1 = previous, 2 = 2 releases ago, etc.

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

confirm_rollback() {
    log_warn "You are about to rollback ${ENVIRONMENT} environment"
    log_warn "This will switch to release #${RELEASE_NUMBER} (counting backwards)"

    read -p "Are you sure you want to continue? (yes/no): " response

    if [ "$response" != "yes" ]; then
        log_info "Rollback cancelled"
        exit 0
    fi
}

perform_rollback() {
    local server_host="$1"
    local server_user="$2"
    local deploy_path="$3"
    local release_number="$4"

    log_info "Performing rollback on ${server_host}..."

    ssh "${server_user}@${server_host}" bash <<EOF
        set -e
        cd "${deploy_path}"

        # Get list of releases sorted by time (newest first)
        RELEASES=(\$(ls -t releases))

        # Calculate target release index (0-based)
        TARGET_INDEX=\$((${release_number}))

        # Check if target release exists
        if [ \$TARGET_INDEX -ge \${#RELEASES[@]} ]; then
            echo "ERROR: Not enough releases available"
            echo "Available releases: \${#RELEASES[@]}"
            echo "Requested release number: ${release_number}"
            exit 1
        fi

        TARGET_RELEASE=\${RELEASES[\$TARGET_INDEX]}

        echo "Current release: \$(readlink current 2>/dev/null || echo 'None')"
        echo "Target release: \$TARGET_RELEASE"

        # Put application in maintenance mode
        if [ -d current ]; then
            cd current
            php artisan down --render="errors::503" --retry=60 || true
            cd ..
        fi

        # Switch to target release
        ln -nfs "releases/\$TARGET_RELEASE" current_tmp
        mv -Tf current_tmp current

        cd current

        # Clear caches
        php artisan cache:clear
        php artisan config:clear
        php artisan route:clear
        php artisan view:clear

        # Recache
        php artisan config:cache
        php artisan route:cache
        php artisan view:cache

        # Restart queue workers
        php artisan queue:restart

        # Check if we need to rollback migrations
        echo "NOTE: Database migrations are NOT automatically rolled back"
        echo "If migrations need to be rolled back, do it manually"

        # Bring application back up
        php artisan up

        echo "Rollback completed successfully"
        echo "Current release: \$TARGET_RELEASE"
EOF

    log_info "Rollback completed on server"
}

verify_rollback() {
    local url="$1"
    local max_attempts=15

    log_info "Verifying rollback..."

    sleep 3  # Wait for application to stabilize

    for ((i=1; i<=max_attempts; i++)); do
        if curl -f -s "${url}/api/v1/health" > /dev/null 2>&1; then
            log_info "Health check passed after rollback!"
            return 0
        fi

        log_warn "Health check attempt $i failed, retrying..."
        sleep 5
    done

    log_error "Health check failed after rollback"
    log_error "Manual intervention required!"
    return 1
}

list_releases() {
    local server_host="$1"
    local server_user="$2"
    local deploy_path="$3"

    log_info "Available releases:"

    ssh "${server_user}@${server_host}" bash <<EOF
        cd "${deploy_path}"

        CURRENT_RELEASE=\$(readlink current 2>/dev/null | sed 's/releases\///' || echo 'None')
        echo "Current release: \$CURRENT_RELEASE"
        echo ""
        echo "Available releases (newest first):"

        RELEASES=(\$(ls -t releases))
        for i in "\${!RELEASES[@]}"; do
            RELEASE=\${RELEASES[\$i]}
            MARKER=""
            if [ "\$RELEASE" == "\$CURRENT_RELEASE" ]; then
                MARKER=" <- CURRENT"
            fi
            echo "  [\$i] \$RELEASE\$MARKER"
        done
EOF
}

###############################################################################
# Main
###############################################################################

main() {
    log_info "AuthOS Rollback Tool"

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

    # If listing releases
    if [ "$RELEASE_NUMBER" == "list" ]; then
        list_releases "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH"
        exit 0
    fi

    # Confirm rollback
    confirm_rollback

    # Perform rollback
    perform_rollback "$SERVER_HOST" "$SERVER_USER" "$DEPLOY_PATH" "$RELEASE_NUMBER"

    # Verify rollback
    if ! verify_rollback "$APP_URL"; then
        log_error "Rollback verification failed"
        exit 1
    fi

    log_info "Rollback completed and verified successfully!"
}

# Show usage if help requested
if [ "${1:-}" == "--help" ] || [ "${1:-}" == "-h" ]; then
    echo "Usage: $0 [environment] [release_number|list]"
    echo ""
    echo "Arguments:"
    echo "  environment     Environment to rollback (staging|production)"
    echo "  release_number  Number of releases to go back (1 = previous, 2 = 2 releases ago, etc.)"
    echo "                  Use 'list' to see available releases"
    echo ""
    echo "Examples:"
    echo "  $0 staging 1        # Rollback staging to previous release"
    echo "  $0 production 2     # Rollback production 2 releases back"
    echo "  $0 staging list     # List available releases for staging"
    exit 0
fi

main "$@"
