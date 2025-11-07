<?php

namespace App\Http\Requests\Organization;

use Illuminate\Foundation\Http\FormRequest;

class UpdateOrganizationSettingsRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        // Don't check permission here - let controller handle it after organization scope check
        // This allows us to return 404 instead of 403 for cross-org access
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        // Accept both nested (settings.*) and flat structures for compatibility
        return [
            'settings' => ['sometimes', 'array'],

            // Security settings (nested)
            'settings.require_mfa' => ['sometimes', 'boolean'],
            'settings.enforce_2fa_for_admins' => ['sometimes', 'boolean'],
            'settings.allowed_ip_ranges' => ['sometimes', 'array'],
            'settings.password_expiry_days' => ['sometimes', 'integer', 'min:0', 'max:365'],
            'settings.mfa_grace_period' => ['sometimes', 'integer', 'min:0', 'max:90'],
            'settings.mfa_methods' => ['sometimes', 'array'],

            // Security settings (flat)
            'require_mfa' => ['sometimes', 'boolean'],
            'enforce_2fa_for_admins' => ['sometimes', 'boolean'],
            'allowed_ip_ranges' => ['sometimes', 'array'],
            'password_expiry_days' => ['sometimes', 'integer', 'min:0', 'max:365'],
            'mfa_grace_period' => ['sometimes', 'integer', 'min:0', 'max:90'],
            'mfa_methods' => ['sometimes', 'array'],

            // Session settings (nested)
            'settings.session_timeout' => ['sometimes', 'integer', 'min:300', 'max:10080'],
            'settings.session_absolute_timeout' => ['sometimes', 'integer', 'min:1', 'max:43200'],
            'settings.session_idle_timeout' => ['sometimes', 'integer', 'min:1', 'max:1440'],
            'settings.require_reauth_for_sensitive' => ['sometimes', 'boolean'],

            // Session settings (flat)
            'session_timeout' => ['sometimes', 'integer', 'min:300', 'max:10080'],
            'session_absolute_timeout' => ['sometimes', 'integer', 'min:1', 'max:43200'],
            'session_idle_timeout' => ['sometimes', 'integer', 'min:1', 'max:1440'],
            'require_reauth_for_sensitive' => ['sometimes', 'boolean'],

            // Lockout policy (nested)
            'settings.lockout_policy' => ['sometimes', 'array'],
            'settings.lockout_policy.enabled' => ['sometimes', 'boolean'],
            'settings.lockout_policy.max_attempts' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'settings.lockout_policy.lockout_duration' => ['sometimes', 'integer', 'min:1'],
            'settings.lockout_policy.progressive_lockout' => ['sometimes', 'boolean'],
            'settings.lockout_policy.notify_user' => ['sometimes', 'boolean'],
            'settings.lockout_policy.notify_admin' => ['sometimes', 'boolean'],

            // Lockout policy (flat)
            'lockout_policy' => ['sometimes', 'array'],
            'lockout_policy.enabled' => ['sometimes', 'boolean'],
            'lockout_policy.max_attempts' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'lockout_policy.lockout_duration' => ['sometimes', 'integer', 'min:1'],
            'lockout_policy.progressive_lockout' => ['sometimes', 'boolean'],
            'lockout_policy.notify_user' => ['sometimes', 'boolean'],
            'lockout_policy.notify_admin' => ['sometimes', 'boolean'],

            // Password policy (nested)
            'settings.password_policy' => ['sometimes', 'array'],
            'settings.password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'settings.password_policy.max_length' => ['sometimes', 'integer', 'min:8', 'max:256', 'gte:settings.password_policy.min_length'],
            'settings.password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'settings.password_policy.require_numbers' => ['sometimes', 'boolean'],
            'settings.password_policy.require_symbols' => ['sometimes', 'boolean'],
            'settings.password_policy.prevent_reuse' => ['sometimes', 'integer', 'min:0', 'max:24'],
            'settings.password_policy.expiry_days' => ['sometimes', 'integer', 'min:0', 'max:365'],
            'settings.password_policy.expiry_warning_days' => ['sometimes', 'integer', 'min:0', 'max:90'],
            'settings.password_policy.prevent_common_passwords' => ['sometimes', 'boolean'],

            // Password policy (flat)
            'password_policy' => ['sometimes', 'array'],
            'password_policy.min_length' => ['sometimes', 'integer', 'min:6', 'max:128'],
            'password_policy.max_length' => ['sometimes', 'integer', 'min:8', 'max:256', 'gte:password_policy.min_length'],
            'password_policy.require_uppercase' => ['sometimes', 'boolean'],
            'password_policy.require_lowercase' => ['sometimes', 'boolean'],
            'password_policy.require_numbers' => ['sometimes', 'boolean'],
            'password_policy.require_symbols' => ['sometimes', 'boolean'],
            'password_policy.prevent_reuse' => ['sometimes', 'integer', 'min:0', 'max:24'],
            'password_policy.expiry_days' => ['sometimes', 'integer', 'min:0', 'max:365'],
            'password_policy.expiry_warning_days' => ['sometimes', 'integer', 'min:0', 'max:90'],
            'password_policy.prevent_common_passwords' => ['sometimes', 'boolean'],

            // Branding (nested)
            'settings.branding' => ['sometimes', 'array'],
            'settings.branding.primary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'settings.branding.secondary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],

            // Branding (flat)
            'branding' => ['sometimes', 'array'],
            'branding.primary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],
            'branding.secondary_color' => ['sometimes', 'string', 'regex:/^#[0-9A-Fa-f]{6}$/'],

            // Notification settings (nested)
            'settings.notifications' => ['sometimes', 'array'],
            'settings.notifications.login_alerts' => ['sometimes', 'boolean'],
            'settings.notifications.security_incidents' => ['sometimes', 'boolean'],
            'settings.notifications.failed_login_threshold' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'settings.notifications.new_user_notifications' => ['sometimes', 'boolean'],
            'settings.notifications.api_key_expiry_warning' => ['sometimes', 'boolean'],
            'settings.notifications.webhook_failure_alerts' => ['sometimes', 'boolean'],

            // Notification settings (flat)
            'notifications' => ['sometimes', 'array'],
            'notifications.login_alerts' => ['sometimes', 'boolean'],
            'notifications.security_incidents' => ['sometimes', 'boolean'],
            'notifications.failed_login_threshold' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'notifications.new_user_notifications' => ['sometimes', 'boolean'],
            'notifications.api_key_expiry_warning' => ['sometimes', 'boolean'],
            'notifications.webhook_failure_alerts' => ['sometimes', 'boolean'],

            // OAuth settings (nested)
            'settings.oauth' => ['sometimes', 'array'],
            'settings.oauth.enabled' => ['sometimes', 'boolean'],
            'settings.oauth.allow_implicit_flow' => ['sometimes', 'boolean'],
            'settings.oauth.require_pkce' => ['sometimes', 'boolean'],
            'settings.oauth.token_lifetime' => ['sometimes', 'integer', 'min:300', 'max:86400'],
            'settings.oauth.refresh_token_lifetime' => ['sometimes', 'integer', 'min:3600', 'max:31536000'],
            'settings.oauth.rotate_refresh_tokens' => ['sometimes', 'boolean'],
            'settings.oauth.allowed_scopes' => ['sometimes', 'array'],

            // OAuth settings (flat)
            'oauth' => ['sometimes', 'array'],
            'oauth.enabled' => ['sometimes', 'boolean'],
            'oauth.allow_implicit_flow' => ['sometimes', 'boolean'],
            'oauth.require_pkce' => ['sometimes', 'boolean'],
            'oauth.token_lifetime' => ['sometimes', 'integer', 'min:300', 'max:86400'],
            'oauth.refresh_token_lifetime' => ['sometimes', 'integer', 'min:3600', 'max:31536000'],
            'oauth.rotate_refresh_tokens' => ['sometimes', 'boolean'],
            'oauth.allowed_scopes' => ['sometimes', 'array'],

            // Other settings (nested)
            'settings.allowed_domains' => ['sometimes', 'array'],
            'settings.sso_enabled' => ['sometimes', 'boolean'],

            // Other settings (flat)
            'allowed_domains' => ['sometimes', 'array'],
            'sso_enabled' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * Get custom error messages for validation rules.
     */
    public function messages(): array
    {
        return [
            'settings.required' => 'Settings are required.',
            'settings.array' => 'Settings must be an array.',
            'settings.allow_registration.boolean' => 'Allow registration must be true or false.',
            'settings.require_email_verification.boolean' => 'Require email verification must be true or false.',
            'settings.session_lifetime.integer' => 'Session lifetime must be an integer.',
            'settings.session_lifetime.min' => 'Session lifetime must be at least 15 minutes.',
            'settings.session_lifetime.max' => 'Session lifetime cannot exceed 10080 minutes (1 week).',
            'settings.password_policy.array' => 'Password policy must be an array.',
            'settings.password_policy.min_length.integer' => 'Minimum password length must be an integer.',
            'settings.password_policy.min_length.min' => 'Minimum password length must be at least 6 characters.',
            'settings.password_policy.min_length.max' => 'Minimum password length cannot exceed 128 characters.',
            'settings.password_policy.require_uppercase.boolean' => 'Require uppercase must be true or false.',
            'settings.password_policy.require_lowercase.boolean' => 'Require lowercase must be true or false.',
            'settings.password_policy.require_numbers.boolean' => 'Require numbers must be true or false.',
            'settings.password_policy.require_symbols.boolean' => 'Require symbols must be true or false.',
        ];
    }
}
