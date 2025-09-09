<?php

return [

    /*
    |--------------------------------------------------------------------------
    | OAuth 2.0 Configuration
    |--------------------------------------------------------------------------
    |
    | This file contains the configuration settings for OAuth 2.0 and OpenID
    | Connect implementation in the AuthOS application.
    |
    */

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limits for OAuth endpoints to prevent abuse.
    |
    */

    'rate_limits' => [
        'per_client' => env('OAUTH_RATE_LIMIT_CLIENT', 100), // requests per hour per client
        'per_ip' => env('OAUTH_RATE_LIMIT_IP', 200), // requests per hour per IP
        'per_user' => env('OAUTH_RATE_LIMIT_USER', 50), // requests per hour per user
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Settings
    |--------------------------------------------------------------------------
    |
    | Security configurations for OAuth implementation.
    |
    */

    'security' => [
        'require_https' => env('OAUTH_REQUIRE_HTTPS', true),
        'max_state_length' => 512,
        'max_redirect_uri_length' => 2048,
        'allowed_redirect_schemes' => ['http', 'https', 'custom'],
        'enable_pkce' => true,
        'require_pkce_for_public_clients' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Configuration
    |--------------------------------------------------------------------------
    |
    | Configure token lifetimes and settings.
    |
    */

    'tokens' => [
        'access_token_lifetime' => env('OAUTH_ACCESS_TOKEN_LIFETIME', 15 * 24 * 3600), // 15 days
        'refresh_token_lifetime' => env('OAUTH_REFRESH_TOKEN_LIFETIME', 30 * 24 * 3600), // 30 days
        'id_token_lifetime' => env('OAUTH_ID_TOKEN_LIFETIME', 3600), // 1 hour
        'authorization_code_lifetime' => env('OAUTH_AUTH_CODE_LIFETIME', 600), // 10 minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Supported Scopes
    |--------------------------------------------------------------------------
    |
    | Define the supported OAuth scopes and their descriptions.
    |
    */

    'scopes' => [
        'openid' => 'OpenID Connect access',
        'profile' => 'Access user profile information',
        'email' => 'Access user email address',
        'read' => 'Read access to your account',
        'write' => 'Write access to your account',
        'admin' => 'Administrative access (restricted)',
    ],

    /*
    |--------------------------------------------------------------------------
    | Supported Grant Types
    |--------------------------------------------------------------------------
    |
    | Define which OAuth 2.0 grant types are enabled.
    |
    */

    'grant_types' => [
        'authorization_code' => true,
        'implicit' => false, // Deprecated by OAuth 2.1
        'refresh_token' => true,
        'client_credentials' => true,
        'password' => false, // Use only for first-party clients
        'device_code' => false, // For future implementation
    ],

    /*
    |--------------------------------------------------------------------------
    | Response Types
    |--------------------------------------------------------------------------
    |
    | Define which OAuth 2.0 response types are supported.
    |
    */

    'response_types' => [
        'code' => true,
        'token' => false, // Deprecated by OAuth 2.1
        'id_token' => true,
        'code token' => false,
        'code id_token' => true,
        'token id_token' => false,
        'code token id_token' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | OpenID Connect Configuration
    |--------------------------------------------------------------------------
    |
    | Settings specific to OpenID Connect implementation.
    |
    */

    'openid_connect' => [
        'issuer' => env('OAUTH_ISSUER', config('app.url')),
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'userinfo_signing_alg_values_supported' => ['none'],
        'token_endpoint_auth_methods_supported' => [
            'client_secret_basic',
            'client_secret_post',
        ],
        'claims_supported' => [
            'sub',
            'name',
            'given_name',
            'family_name',
            'preferred_username',
            'email',
            'email_verified',
            'picture',
            'updated_at',
        ],
        'code_challenge_methods_supported' => ['S256', 'plain'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Configure OAuth-specific logging settings.
    |
    */

    'logging' => [
        'enabled' => env('OAUTH_LOGGING_ENABLED', true),
        'channel' => env('OAUTH_LOG_CHANNEL', 'oauth'),
        'log_successful_requests' => env('OAUTH_LOG_SUCCESS', false),
        'log_failed_requests' => env('OAUTH_LOG_FAILURES', true),
        'log_security_events' => env('OAUTH_LOG_SECURITY', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Client Configuration
    |--------------------------------------------------------------------------
    |
    | Default settings for OAuth clients.
    |
    */

    'clients' => [
        'default_scopes' => ['openid'],
        'auto_approve_first_party' => true,
        'require_approval_for_third_party' => true,
        'max_redirect_uris' => 10,
    ],

];
