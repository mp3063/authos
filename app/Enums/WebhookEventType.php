<?php

namespace App\Enums;

enum WebhookEventType: string
{
    // User Events (6 events)
    case USER_CREATED = 'user.created';
    case USER_UPDATED = 'user.updated';
    case USER_DELETED = 'user.deleted';
    case USER_LOCKED = 'user.locked';
    case USER_UNLOCKED = 'user.unlocked';
    case USER_VERIFIED = 'user.verified';

    // Authentication Events (10 events)
    case AUTHENTICATION_LOGIN = 'authentication.login';
    case AUTHENTICATION_LOGOUT = 'authentication.logout';
    case AUTHENTICATION_FAILED = 'authentication.failed';
    case AUTHENTICATION_PASSWORD_RESET = 'authentication.password_reset';
    case AUTHENTICATION_SESSION_EXPIRED = 'authentication.session_expired';
    case AUTHENTICATION_MFA_CHALLENGED = 'authentication.mfa_challenged';
    case AUTHENTICATION_MFA_COMPLETED = 'authentication.mfa_completed';
    case AUTHENTICATION_PASSWORD_CHANGED = 'authentication.password_changed';
    case AUTHENTICATION_EMAIL_VERIFIED = 'authentication.email_verified';
    case AUTHENTICATION_LOCKOUT = 'authentication.lockout';

    // Application Events (4 events)
    case APPLICATION_CREATED = 'application.created';
    case APPLICATION_UPDATED = 'application.updated';
    case APPLICATION_DELETED = 'application.deleted';
    case APPLICATION_CREDENTIALS_ROTATED = 'application.credentials_rotated';

    // Organization Events (7 events)
    case ORGANIZATION_CREATED = 'organization.created';
    case ORGANIZATION_UPDATED = 'organization.updated';
    case ORGANIZATION_DELETED = 'organization.deleted';
    case ORGANIZATION_MEMBER_ADDED = 'organization.member_added';
    case ORGANIZATION_MEMBER_REMOVED = 'organization.member_removed';
    case ORGANIZATION_SETTINGS_CHANGED = 'organization.settings_changed';
    case ORGANIZATION_BRANDING_UPDATED = 'organization.branding_updated';

    // MFA Events (7 events)
    case MFA_ENABLED = 'mfa.enabled';
    case MFA_DISABLED = 'mfa.disabled';
    case MFA_VERIFIED = 'mfa.verified';
    case MFA_RECOVERY_USED = 'mfa.recovery_used';
    case MFA_BACKUP_CODES_REGENERATED = 'mfa.backup_codes_regenerated';
    case MFA_RECOVERY_CODES_GENERATED = 'mfa.recovery_codes_generated';
    case MFA_METHOD_ADDED = 'mfa.method_added';

    // SSO Events (5 events)
    case SSO_SESSION_CREATED = 'sso.session_created';
    case SSO_SESSION_ENDED = 'sso.session_ended';
    case SSO_CONFIGURATION_CREATED = 'sso.configuration_created';
    case SSO_CONFIGURATION_UPDATED = 'sso.configuration_updated';
    case SSO_CONFIGURATION_DELETED = 'sso.configuration_deleted';

    // Role Events (5 events)
    case ROLE_ASSIGNED = 'role.assigned';
    case ROLE_REVOKED = 'role.revoked';
    case ROLE_CREATED = 'role.created';
    case ROLE_UPDATED = 'role.updated';
    case ROLE_DELETED = 'role.deleted';

    public function getCategory(): string
    {
        return match ($this) {
            self::USER_CREATED,
            self::USER_UPDATED,
            self::USER_DELETED,
            self::USER_LOCKED,
            self::USER_UNLOCKED,
            self::USER_VERIFIED => 'user',

            self::AUTHENTICATION_LOGIN,
            self::AUTHENTICATION_LOGOUT,
            self::AUTHENTICATION_FAILED,
            self::AUTHENTICATION_PASSWORD_RESET,
            self::AUTHENTICATION_SESSION_EXPIRED,
            self::AUTHENTICATION_MFA_CHALLENGED,
            self::AUTHENTICATION_MFA_COMPLETED,
            self::AUTHENTICATION_PASSWORD_CHANGED,
            self::AUTHENTICATION_EMAIL_VERIFIED,
            self::AUTHENTICATION_LOCKOUT => 'authentication',

            self::APPLICATION_CREATED,
            self::APPLICATION_UPDATED,
            self::APPLICATION_DELETED,
            self::APPLICATION_CREDENTIALS_ROTATED => 'application',

            self::ORGANIZATION_CREATED,
            self::ORGANIZATION_UPDATED,
            self::ORGANIZATION_DELETED,
            self::ORGANIZATION_MEMBER_ADDED,
            self::ORGANIZATION_MEMBER_REMOVED,
            self::ORGANIZATION_SETTINGS_CHANGED,
            self::ORGANIZATION_BRANDING_UPDATED => 'organization',

            self::MFA_ENABLED,
            self::MFA_DISABLED,
            self::MFA_VERIFIED,
            self::MFA_RECOVERY_USED,
            self::MFA_BACKUP_CODES_REGENERATED,
            self::MFA_RECOVERY_CODES_GENERATED,
            self::MFA_METHOD_ADDED => 'mfa',

            self::SSO_SESSION_CREATED,
            self::SSO_SESSION_ENDED,
            self::SSO_CONFIGURATION_CREATED,
            self::SSO_CONFIGURATION_UPDATED,
            self::SSO_CONFIGURATION_DELETED => 'sso',

            self::ROLE_ASSIGNED,
            self::ROLE_REVOKED,
            self::ROLE_CREATED,
            self::ROLE_UPDATED,
            self::ROLE_DELETED => 'role',
        };
    }

    public function getDescription(): string
    {
        return match ($this) {
            self::USER_CREATED => 'Triggered when a new user account is created',
            self::USER_UPDATED => 'Triggered when user profile or settings are updated',
            self::USER_DELETED => 'Triggered when a user account is deleted',
            self::USER_LOCKED => 'Triggered when a user account is locked',
            self::USER_UNLOCKED => 'Triggered when a user account is unlocked',
            self::USER_VERIFIED => 'Triggered when a user email is verified',

            self::AUTHENTICATION_LOGIN => 'Triggered when a user successfully logs in',
            self::AUTHENTICATION_LOGOUT => 'Triggered when a user logs out',
            self::AUTHENTICATION_FAILED => 'Triggered when a login attempt fails',
            self::AUTHENTICATION_PASSWORD_RESET => 'Triggered when a password reset is completed',
            self::AUTHENTICATION_SESSION_EXPIRED => 'Triggered when a session expires',
            self::AUTHENTICATION_MFA_CHALLENGED => 'Triggered when MFA challenge is presented',
            self::AUTHENTICATION_MFA_COMPLETED => 'Triggered when MFA challenge is completed successfully',
            self::AUTHENTICATION_PASSWORD_CHANGED => 'Triggered when a user changes their password',
            self::AUTHENTICATION_EMAIL_VERIFIED => 'Triggered when an email verification is completed',
            self::AUTHENTICATION_LOCKOUT => 'Triggered when a user is locked out due to failed attempts',

            self::APPLICATION_CREATED => 'Triggered when a new OAuth application is created',
            self::APPLICATION_UPDATED => 'Triggered when application settings are modified',
            self::APPLICATION_DELETED => 'Triggered when an application is deleted',
            self::APPLICATION_CREDENTIALS_ROTATED => 'Triggered when client secret is regenerated',

            self::ORGANIZATION_CREATED => 'Triggered when a new organization is created',
            self::ORGANIZATION_UPDATED => 'Triggered when organization settings are changed',
            self::ORGANIZATION_DELETED => 'Triggered when an organization is deleted',
            self::ORGANIZATION_MEMBER_ADDED => 'Triggered when a new member joins the organization',
            self::ORGANIZATION_MEMBER_REMOVED => 'Triggered when a member is removed from the organization',
            self::ORGANIZATION_SETTINGS_CHANGED => 'Triggered when security or compliance settings are modified',
            self::ORGANIZATION_BRANDING_UPDATED => 'Triggered when organization branding is updated',

            self::MFA_ENABLED => 'Triggered when MFA is enabled for a user',
            self::MFA_DISABLED => 'Triggered when MFA is disabled for a user',
            self::MFA_VERIFIED => 'Triggered when MFA verification succeeds',
            self::MFA_RECOVERY_USED => 'Triggered when a recovery code is used',
            self::MFA_BACKUP_CODES_REGENERATED => 'Triggered when backup codes are regenerated',
            self::MFA_RECOVERY_CODES_GENERATED => 'Triggered when recovery codes are initially generated',
            self::MFA_METHOD_ADDED => 'Triggered when a new MFA method is added',

            self::SSO_SESSION_CREATED => 'Triggered when an SSO session is established',
            self::SSO_SESSION_ENDED => 'Triggered when an SSO session is terminated',
            self::SSO_CONFIGURATION_CREATED => 'Triggered when a new SSO configuration is added',
            self::SSO_CONFIGURATION_UPDATED => 'Triggered when SSO configuration is modified',
            self::SSO_CONFIGURATION_DELETED => 'Triggered when an SSO configuration is deleted',

            self::ROLE_ASSIGNED => 'Triggered when a role is assigned to a user',
            self::ROLE_REVOKED => 'Triggered when a role is revoked from a user',
            self::ROLE_CREATED => 'Triggered when a new custom role is created',
            self::ROLE_UPDATED => 'Triggered when role permissions are modified',
            self::ROLE_DELETED => 'Triggered when a role is deleted',
        };
    }

    /**
     * Get all event types by category
     */
    public static function getByCategory(string $category): array
    {
        return array_filter(
            self::cases(),
            fn (self $event) => $event->getCategory() === $category
        );
    }

    /**
     * Get all available categories
     */
    public static function getCategories(): array
    {
        return array_unique(
            array_map(
                fn (self $event) => $event->getCategory(),
                self::cases()
            )
        );
    }

    /**
     * Check if event type exists
     */
    public static function isValid(string $eventType): bool
    {
        return in_array($eventType, array_column(self::cases(), 'value'));
    }
}
