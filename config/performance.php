<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Performance Optimization Configuration
    |--------------------------------------------------------------------------
    |
    | This file contains all performance-related configuration settings
    | including caching, compression, and optimization thresholds.
    |
    */

    'cache' => [
        /*
        | Multi-layer caching strategy
        */
        'layers' => [
            // Browser caching via HTTP headers
            'browser' => [
                'enabled' => env('CACHE_BROWSER_ENABLED', true),
                'max_age' => env('CACHE_BROWSER_MAX_AGE', 300), // 5 minutes
            ],

            // Application-level caching (Redis/Database)
            'application' => [
                'enabled' => env('CACHE_APPLICATION_ENABLED', true),
                'default_ttl' => env('CACHE_DEFAULT_TTL', 300), // 5 minutes
            ],

            // Database query result caching
            'query' => [
                'enabled' => env('CACHE_QUERY_ENABLED', true),
                'default_ttl' => env('CACHE_QUERY_TTL', 600), // 10 minutes
            ],
        ],

        /*
        | Cache warming configuration
        */
        'warming' => [
            'enabled' => env('CACHE_WARMING_ENABLED', true),
            'schedule' => env('CACHE_WARMING_SCHEDULE', '*/15 * * * *'), // Every 15 minutes
            'entities' => [
                'organizations' => true,
                'users' => true,
                'applications' => true,
                'permissions' => true,
            ],
        ],

        /*
        | Cache TTL by data type (in seconds)
        */
        'ttl' => [
            'user_permissions' => env('CACHE_TTL_USER_PERMISSIONS', 600),        // 10 minutes
            'user_profile' => env('CACHE_TTL_USER_PROFILE', 300),                // 5 minutes
            'organization_settings' => env('CACHE_TTL_ORG_SETTINGS', 1800),      // 30 minutes
            'organization_users' => env('CACHE_TTL_ORG_USERS', 600),             // 10 minutes
            'application_config' => env('CACHE_TTL_APP_CONFIG', 3600),           // 1 hour
            'application_tokens' => env('CACHE_TTL_APP_TOKENS', 1800),           // 30 minutes
            'analytics_data' => env('CACHE_TTL_ANALYTICS', 300),                 // 5 minutes
            'authentication_logs' => env('CACHE_TTL_AUTH_LOGS', 300),            // 5 minutes
            'webhook_deliveries' => env('CACHE_TTL_WEBHOOK_DELIVERIES', 300),   // 5 minutes
            'sso_configuration' => env('CACHE_TTL_SSO_CONFIG', 3600),            // 1 hour
            'ldap_configuration' => env('CACHE_TTL_LDAP_CONFIG', 3600),          // 1 hour
            'roles_permissions' => env('CACHE_TTL_ROLES_PERMS', 1800),           // 30 minutes
            'oauth_clients' => env('CACHE_TTL_OAUTH_CLIENTS', 3600),             // 1 hour
        ],

        /*
        | Cache invalidation strategies
        */
        'invalidation' => [
            'strategy' => env('CACHE_INVALIDATION_STRATEGY', 'aggressive'), // aggressive|lazy|mixed
            'cascade' => env('CACHE_INVALIDATION_CASCADE', true),           // Cascade to related entities
            'async' => env('CACHE_INVALIDATION_ASYNC', false),              // Queue invalidation jobs
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Response Compression
    |--------------------------------------------------------------------------
    */
    'compression' => [
        'enabled' => env('COMPRESSION_ENABLED', true),
        'min_length' => env('COMPRESSION_MIN_LENGTH', 1024),    // 1KB minimum
        'level' => env('COMPRESSION_LEVEL', 6),                 // 1-9 (higher = better compression, slower)
        'types' => [
            'application/json',
            'application/javascript',
            'text/html',
            'text/css',
            'text/plain',
            'text/xml',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Database Query Optimization
    |--------------------------------------------------------------------------
    */
    'database' => [
        'query_cache' => [
            'enabled' => env('DB_QUERY_CACHE_ENABLED', true),
            'ttl' => env('DB_QUERY_CACHE_TTL', 600),
        ],

        'connection_pool' => [
            'min' => env('DB_POOL_MIN', 2),
            'max' => env('DB_POOL_MAX', 10),
            'idle_timeout' => env('DB_POOL_IDLE_TIMEOUT', 60),
        ],

        'slow_query_threshold' => env('DB_SLOW_QUERY_THRESHOLD', 1000), // milliseconds

        'eager_loading' => [
            'enabled' => true,
            'max_depth' => 3,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | API Response Optimization
    |--------------------------------------------------------------------------
    */
    'api' => [
        'pagination' => [
            'default_per_page' => env('API_DEFAULT_PER_PAGE', 15),
            'max_per_page' => env('API_MAX_PER_PAGE', 100),
        ],

        'field_filtering' => [
            'enabled' => env('API_FIELD_FILTERING_ENABLED', true),
        ],

        'rate_limiting' => [
            'enabled' => true,
            'cache_driver' => env('RATE_LIMIT_CACHE_DRIVER', 'redis'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Performance Monitoring
    |--------------------------------------------------------------------------
    */
    'monitoring' => [
        'enabled' => env('PERFORMANCE_MONITORING_ENABLED', true),

        'thresholds' => [
            'response_time_warning' => env('PERF_RESPONSE_TIME_WARNING', 500),    // ms
            'response_time_critical' => env('PERF_RESPONSE_TIME_CRITICAL', 1000), // ms
            'memory_warning' => env('PERF_MEMORY_WARNING', 64),                   // MB
            'memory_critical' => env('PERF_MEMORY_CRITICAL', 128),                // MB
            'query_count_warning' => env('PERF_QUERY_COUNT_WARNING', 20),
            'query_count_critical' => env('PERF_QUERY_COUNT_CRITICAL', 50),
        ],

        'logging' => [
            'slow_requests' => env('PERF_LOG_SLOW_REQUESTS', true),
            'high_memory' => env('PERF_LOG_HIGH_MEMORY', true),
            'many_queries' => env('PERF_LOG_MANY_QUERIES', true),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Asset Optimization
    |--------------------------------------------------------------------------
    */
    'assets' => [
        'cdn' => [
            'enabled' => env('ASSET_CDN_ENABLED', false),
            'url' => env('ASSET_CDN_URL', ''),
        ],

        'versioning' => [
            'enabled' => env('ASSET_VERSIONING_ENABLED', true),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Benchmark Targets
    |--------------------------------------------------------------------------
    |
    | Performance targets for critical endpoints
    |
    */
    'benchmarks' => [
        'p95_response_time' => 100,  // 95th percentile < 100ms
        'p99_response_time' => 250,  // 99th percentile < 250ms
        'max_response_time' => 1000, // Max < 1 second
        'target_throughput' => 1000, // requests per second
    ],
];
