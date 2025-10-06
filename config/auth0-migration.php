<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Default Password Strategy
    |--------------------------------------------------------------------------
    |
    | The default strategy for handling user passwords during migration.
    |
    | Available strategies:
    | - 'reset': Generate temporary password and require password reset
    | - 'lazy': Migrate password on first login by verifying with Auth0
    | - 'hash': Import password hash directly (limited support)
    |
    */
    'default_strategy' => env('AUTH0_MIGRATION_PASSWORD_STRATEGY', 'lazy'),

    /*
    |--------------------------------------------------------------------------
    | Batch Size
    |--------------------------------------------------------------------------
    |
    | The number of records to process in each batch during migration.
    | Larger batch sizes are faster but use more memory.
    |
    */
    'batch_size' => env('AUTH0_MIGRATION_BATCH_SIZE', 100),

    /*
    |--------------------------------------------------------------------------
    | Timeout
    |--------------------------------------------------------------------------
    |
    | The maximum time in seconds to wait for API requests.
    |
    */
    'timeout' => env('AUTH0_MIGRATION_TIMEOUT', 300),

    /*
    |--------------------------------------------------------------------------
    | Dry Run Default
    |--------------------------------------------------------------------------
    |
    | Whether to perform a dry run by default.
    | This prevents accidental data import without review.
    |
    */
    'dry_run_default' => env('AUTH0_MIGRATION_DRY_RUN_DEFAULT', true),

    /*
    |--------------------------------------------------------------------------
    | Backup Before Migration
    |--------------------------------------------------------------------------
    |
    | Whether to create a database backup before running migration.
    | Highly recommended for production environments.
    |
    */
    'backup_before_migration' => env('AUTH0_MIGRATION_BACKUP', true),

    /*
    |--------------------------------------------------------------------------
    | Send Welcome Emails
    |--------------------------------------------------------------------------
    |
    | Whether to send welcome emails to imported users.
    | For large migrations, consider disabling this.
    |
    */
    'send_welcome_emails' => env('AUTH0_MIGRATION_SEND_EMAILS', false),

    /*
    |--------------------------------------------------------------------------
    | Skip System Clients
    |--------------------------------------------------------------------------
    |
    | List of Auth0 client names to skip during migration.
    | These are typically Auth0 system clients.
    |
    */
    'skip_clients' => [
        'All Applications',
        'Default App',
        'API Explorer Application',
        'Auth0 Management API',
    ],

    /*
    |--------------------------------------------------------------------------
    | Skip System Roles
    |--------------------------------------------------------------------------
    |
    | List of Auth0 role names to skip during migration.
    | These are typically roles that already exist in the system.
    |
    */
    'skip_roles' => [
        'admin',
        'user',
        'super-admin',
        'organization-admin',
        'organization-owner',
    ],

    /*
    |--------------------------------------------------------------------------
    | Validate After Migration
    |--------------------------------------------------------------------------
    |
    | Whether to automatically validate data after migration.
    |
    */
    'validate_after_migration' => env('AUTH0_MIGRATION_VALIDATE', true),

    /*
    |--------------------------------------------------------------------------
    | Log Migrations
    |--------------------------------------------------------------------------
    |
    | Whether to log detailed migration progress and results.
    |
    */
    'log_migrations' => env('AUTH0_MIGRATION_LOG', true),

    /*
    |--------------------------------------------------------------------------
    | Migration Log Channel
    |--------------------------------------------------------------------------
    |
    | The log channel to use for migration logs.
    |
    */
    'log_channel' => env('AUTH0_MIGRATION_LOG_CHANNEL', 'stack'),

    /*
    |--------------------------------------------------------------------------
    | Continue On Error
    |--------------------------------------------------------------------------
    |
    | Whether to continue migration even if some items fail.
    | If false, migration will stop on first error.
    |
    */
    'continue_on_error' => env('AUTH0_MIGRATION_CONTINUE_ON_ERROR', true),

    /*
    |--------------------------------------------------------------------------
    | Import Social Accounts
    |--------------------------------------------------------------------------
    |
    | Whether to import social authentication accounts.
    |
    */
    'import_social_accounts' => env('AUTH0_MIGRATION_IMPORT_SOCIAL', true),

    /*
    |--------------------------------------------------------------------------
    | Import MFA Settings
    |--------------------------------------------------------------------------
    |
    | Whether to import MFA settings for users.
    | Note: Users will need to reconfigure their MFA devices.
    |
    */
    'import_mfa_settings' => env('AUTH0_MIGRATION_IMPORT_MFA', true),

    /*
    |--------------------------------------------------------------------------
    | Import Metadata
    |--------------------------------------------------------------------------
    |
    | Whether to import user and app metadata.
    |
    */
    'import_metadata' => env('AUTH0_MIGRATION_IMPORT_METADATA', true),

    /*
    |--------------------------------------------------------------------------
    | Provider Mapping
    |--------------------------------------------------------------------------
    |
    | Mapping of Auth0 provider names to local provider names.
    |
    */
    'provider_mapping' => [
        'google-oauth2' => 'google',
        'github' => 'github',
        'facebook' => 'facebook',
        'twitter' => 'twitter',
        'linkedin' => 'linkedin',
    ],
];
