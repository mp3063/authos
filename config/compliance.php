<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Audit-Log Retention (days)
    |--------------------------------------------------------------------------
    |
    | Used by ComplianceReportService when an organization has not configured
    | settings.security.retention_period_days. The retention enforcement
    | command (compliance:enforce-retention) does not delete data unless
    | settings.security.auto_pruning_enabled is true on the org.
    |
    */
    'default_retention_days' => env('COMPLIANCE_DEFAULT_RETENTION_DAYS', 365),

    /*
    |--------------------------------------------------------------------------
    | Compliance Report Retention (days)
    |--------------------------------------------------------------------------
    |
    | Generated PDF/JSON reports are kept for this many days. After
    | expiry, compliance:cleanup-expired-reports removes the row and
    | the storage files.
    |
    */
    'report_retention_days' => env('COMPLIANCE_REPORT_RETENTION_DAYS', 180),

    /*
    |--------------------------------------------------------------------------
    | Maximum Reporting Period (days)
    |--------------------------------------------------------------------------
    |
    | Caps the (period_end - period_start) span requested by the API.
    | Prevents runaway query cost on multi-year requests.
    |
    */
    'max_period_days' => env('COMPLIANCE_MAX_PERIOD_DAYS', 365),

    /*
    |--------------------------------------------------------------------------
    | PII Redaction
    |--------------------------------------------------------------------------
    |
    | When true, the PDF renderer masks user emails / IPs in incident
    | tables. Useful for reports shared outside the security team.
    |
    */
    'pdf' => [
        'redact_pii' => env('COMPLIANCE_PDF_REDACT_PII', false),
    ],

];
