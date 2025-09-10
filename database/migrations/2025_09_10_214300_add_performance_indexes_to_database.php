<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        // Optimize authentication_logs table for frequent queries
        Schema::table('authentication_logs', function (Blueprint $table) {
            // Composite index for user activity queries (most common use case)
            $table->index(['user_id', 'event', 'created_at'], 'auth_logs_user_event_created_idx');

            // Composite index for application analytics
            $table->index(['application_id', 'event', 'created_at'], 'auth_logs_app_event_created_idx');

            // Index for success/failure analysis
            $table->index(['success', 'created_at'], 'auth_logs_success_created_idx');

            // Index for IP-based security monitoring
            $table->index(['ip_address', 'created_at'], 'auth_logs_ip_created_idx');
        });

        // Optimize user_applications pivot table
        Schema::table('user_applications', function (Blueprint $table) {
            // Index for application user lookups
            $table->index(['application_id', 'last_login_at'], 'user_apps_app_last_login_idx');

            // Index for user application access patterns
            $table->index(['user_id', 'granted_at'], 'user_apps_user_granted_idx');

            // Index for login analytics
            $table->index(['login_count', 'last_login_at'], 'user_apps_login_analytics_idx');
        });

        // Optimize applications table
        Schema::table('applications', function (Blueprint $table) {
            // Composite index for organization-scoped active applications
            $table->index(['organization_id', 'is_active', 'created_at'], 'apps_org_active_created_idx');

            // Index for client lookups (OAuth flows)
            $table->index(['client_id', 'is_active'], 'apps_client_active_idx');
        });

        // Optimize users table for better query performance
        Schema::table('users', function (Blueprint $table) {
            // Composite index for organization user management
            $table->index(['organization_id', 'is_active', 'created_at'], 'users_org_active_created_idx');

            // Index for email verification status
            $table->index(['email_verified_at', 'is_active'], 'users_verified_active_idx');

            // Index for social login lookups (could be very frequent)
            $table->index(['provider', 'provider_id', 'is_active'], 'users_social_active_idx');
        });

        // Create functional index for MFA filtering using raw SQL (PostgreSQL specific)
        DB::statement('CREATE INDEX users_mfa_enabled_idx ON users ((mfa_methods IS NOT NULL), is_active)');
        DB::statement('CREATE INDEX users_password_changed_idx ON users (password_changed_at, is_active)');

        // Optimize organizations table
        Schema::table('organizations', function (Blueprint $table) {
            // Index for active organizations with slug lookups
            $table->index(['slug', 'is_active'], 'orgs_slug_active_idx');

            // Index for soft-deleted organizations
            $table->index(['deleted_at', 'is_active'], 'orgs_deleted_active_idx');
        });

        // Optimize OAuth tables for token operations (very frequent)
        if (Schema::hasTable('oauth_access_tokens')) {
            Schema::table('oauth_access_tokens', function (Blueprint $table) {
                // Index for token cleanup and validation
                $table->index(['revoked', 'expires_at'], 'oauth_tokens_revoked_expires_idx');

                // Index for user token queries
                $table->index(['user_id', 'revoked', 'expires_at'], 'oauth_tokens_user_valid_idx');

                // Index for client token analytics
                $table->index(['client_id', 'created_at'], 'oauth_tokens_client_created_idx');
            });
        }

        if (Schema::hasTable('oauth_refresh_tokens')) {
            Schema::table('oauth_refresh_tokens', function (Blueprint $table) {
                // Index for refresh token validation and cleanup
                $table->index(['revoked', 'expires_at'], 'oauth_refresh_revoked_expires_idx');

                // Index for access token relation
                $table->index(['access_token_id', 'revoked'], 'oauth_refresh_token_revoked_idx');
            });
        }

        if (Schema::hasTable('oauth_authorization_codes')) {
            Schema::table('oauth_authorization_codes', function (Blueprint $table) {
                // Index for authorization code validation (very time-sensitive)
                $table->index(['revoked', 'expires_at'], 'oauth_auth_codes_revoked_expires_idx');

                // Index for user authorization flows
                $table->index(['user_id', 'client_id', 'revoked'], 'oauth_auth_codes_user_client_idx');
            });
        }

        // Optimize SSO-related tables
        if (Schema::hasTable('sso_sessions')) {
            Schema::table('sso_sessions', function (Blueprint $table) {
                // Index for active session lookups
                $table->index(['user_id', 'logged_out_at'], 'sso_sessions_user_active_idx');

                // Index for application session analytics
                $table->index(['application_id', 'logged_out_at', 'created_at'], 'sso_sessions_app_analytics_idx');

                // Index for session cleanup
                $table->index(['expires_at', 'logged_out_at'], 'sso_sessions_cleanup_idx');
            });
        }

        // Optimize invitations table
        if (Schema::hasTable('invitations')) {
            Schema::table('invitations', function (Blueprint $table) {
                // Index for organization invitation management
                $table->index(['organization_id', 'status', 'created_at'], 'invitations_org_status_created_idx');

                // Index for email-based invitation lookups
                $table->index(['email', 'status'], 'invitations_email_status_idx');

                // Index for invitation expiry cleanup
                $table->index(['expires_at', 'status'], 'invitations_expires_status_idx');
            });
        }

        // Optimize Laravel's built-in tables
        if (Schema::hasTable('sessions')) {
            Schema::table('sessions', function (Blueprint $table) {
                // Index for session cleanup (Laravel doesn't add this by default)
                $table->index(['last_activity', 'user_id'], 'sessions_cleanup_idx');
            });
        }

        if (Schema::hasTable('jobs')) {
            Schema::table('jobs', function (Blueprint $table) {
                // Index for job processing optimization
                $table->index(['queue', 'reserved_at', 'available_at'], 'jobs_processing_idx');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        // Drop authentication_logs indexes
        Schema::table('authentication_logs', function (Blueprint $table) {
            $table->dropIndex('auth_logs_user_event_created_idx');
            $table->dropIndex('auth_logs_app_event_created_idx');
            $table->dropIndex('auth_logs_success_created_idx');
            $table->dropIndex('auth_logs_ip_created_idx');
        });

        // Drop user_applications indexes
        Schema::table('user_applications', function (Blueprint $table) {
            $table->dropIndex('user_apps_app_last_login_idx');
            $table->dropIndex('user_apps_user_granted_idx');
            $table->dropIndex('user_apps_login_analytics_idx');
        });

        // Drop applications indexes
        Schema::table('applications', function (Blueprint $table) {
            $table->dropIndex('apps_org_active_created_idx');
            $table->dropIndex('apps_client_active_idx');
        });

        // Drop users indexes
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex('users_org_active_created_idx');
            $table->dropIndex('users_verified_active_idx');
            $table->dropIndex('users_social_active_idx');
        });

        // Drop functional indexes using raw SQL
        DB::statement('DROP INDEX IF EXISTS users_mfa_enabled_idx');
        DB::statement('DROP INDEX IF EXISTS users_password_changed_idx');

        // Drop organizations indexes
        Schema::table('organizations', function (Blueprint $table) {
            $table->dropIndex('orgs_slug_active_idx');
            $table->dropIndex('orgs_deleted_active_idx');
        });

        // Drop OAuth table indexes
        if (Schema::hasTable('oauth_access_tokens')) {
            Schema::table('oauth_access_tokens', function (Blueprint $table) {
                $table->dropIndex('oauth_tokens_revoked_expires_idx');
                $table->dropIndex('oauth_tokens_user_valid_idx');
                $table->dropIndex('oauth_tokens_client_created_idx');
            });
        }

        if (Schema::hasTable('oauth_refresh_tokens')) {
            Schema::table('oauth_refresh_tokens', function (Blueprint $table) {
                $table->dropIndex('oauth_refresh_revoked_expires_idx');
                $table->dropIndex('oauth_refresh_token_revoked_idx');
            });
        }

        if (Schema::hasTable('oauth_authorization_codes')) {
            Schema::table('oauth_authorization_codes', function (Blueprint $table) {
                $table->dropIndex('oauth_auth_codes_revoked_expires_idx');
                $table->dropIndex('oauth_auth_codes_user_client_idx');
            });
        }

        // Drop SSO and other table indexes
        if (Schema::hasTable('sso_sessions')) {
            Schema::table('sso_sessions', function (Blueprint $table) {
                $table->dropIndex('sso_sessions_user_active_idx');
                $table->dropIndex('sso_sessions_app_analytics_idx');
                $table->dropIndex('sso_sessions_cleanup_idx');
            });
        }

        if (Schema::hasTable('invitations')) {
            Schema::table('invitations', function (Blueprint $table) {
                $table->dropIndex('invitations_org_status_created_idx');
                $table->dropIndex('invitations_email_status_idx');
                $table->dropIndex('invitations_expires_status_idx');
            });
        }

        if (Schema::hasTable('sessions')) {
            Schema::table('sessions', function (Blueprint $table) {
                $table->dropIndex('sessions_cleanup_idx');
            });
        }

        if (Schema::hasTable('jobs')) {
            Schema::table('jobs', function (Blueprint $table) {
                $table->dropIndex('jobs_processing_idx');
            });
        }
    }
};
