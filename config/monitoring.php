<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Alert Email Recipients
    |--------------------------------------------------------------------------
    |
    | Email addresses that should receive system alert notifications.
    | Leave empty to disable email alerts.
    |
    */
    'alert_emails' => env('MONITORING_ALERT_EMAILS') ? explode(',', env('MONITORING_ALERT_EMAILS')) : [],

    /*
    |--------------------------------------------------------------------------
    | Alert Thresholds
    |--------------------------------------------------------------------------
    |
    | Configure thresholds for triggering system alerts.
    |
    */
    'thresholds' => [
        'error_rate' => env('MONITORING_ERROR_RATE_THRESHOLD', 10), // Percentage
        'response_time' => env('MONITORING_RESPONSE_TIME_THRESHOLD', 2000), // Milliseconds
        'memory_usage' => env('MONITORING_MEMORY_USAGE_THRESHOLD', 85), // Percentage
        'oauth_revocations' => env('MONITORING_OAUTH_REVOCATIONS_THRESHOLD', 50), // Count per hour
    ],

    /*
    |--------------------------------------------------------------------------
    | Minimum Request Volume
    |--------------------------------------------------------------------------
    |
    | Minimum number of requests required before triggering alerts.
    | This prevents false positives from low-volume periods.
    |
    */
    'min_requests' => [
        'error_rate' => env('MONITORING_MIN_REQUESTS_ERROR_RATE', 10),
        'response_time' => env('MONITORING_MIN_REQUESTS_RESPONSE_TIME', 5),
    ],
];
