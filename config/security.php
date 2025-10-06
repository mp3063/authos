<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | This file contains security settings for the AuthOS application
    | including intrusion detection thresholds and lockout policies.
    |
    */

    'brute_force' => [
        'email_threshold' => env('BRUTE_FORCE_EMAIL_THRESHOLD', 5),
        'ip_threshold' => env('BRUTE_FORCE_IP_THRESHOLD', 10),
        'detection_window_minutes' => env('BRUTE_FORCE_WINDOW', 15),
    ],

    'credential_stuffing' => [
        'threshold' => env('CREDENTIAL_STUFFING_THRESHOLD', 10),
        'detection_window_minutes' => env('CREDENTIAL_STUFFING_WINDOW', 5),
    ],

    'api_rate' => [
        'anomaly_threshold' => env('API_ANOMALY_THRESHOLD', 100),
        'monitoring_window_minutes' => env('API_MONITORING_WINDOW', 1),
    ],

    'lockout_schedule' => [
        3 => 5,      // 3 attempts = 5 minutes
        5 => 15,     // 5 attempts = 15 minutes
        7 => 30,     // 7 attempts = 30 minutes
        10 => 60,    // 10 attempts = 1 hour
        15 => 1440,  // 15 attempts = 24 hours
    ],

    'ip_blocklist' => [
        'auto_block_threshold' => env('IP_AUTO_BLOCK_THRESHOLD', 20),
        'default_block_duration_hours' => env('IP_BLOCK_DURATION', 24),
    ],

    'security_headers' => [
        'enabled' => env('SECURITY_HEADERS_ENABLED', true),
        'csp_nonce_enabled' => env('CSP_NONCE_ENABLED', true),
    ],
];
