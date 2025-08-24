<?php

namespace App\Enums;

use Filament\Support\Contracts\HasIcon;
use Filament\Support\Contracts\HasLabel;

enum NavigationGroup: string implements HasLabel, HasIcon
{
    case UserManagement = 'user-management';
    case OAuthManagement = 'oauth-management';
    case SecurityMonitoring = 'security-monitoring';
    case AccessControl = 'access-control';

    public function getLabel(): string
    {
        return match ($this) {
            self::UserManagement => 'User Management',
            self::OAuthManagement => 'OAuth Management',
            self::SecurityMonitoring => 'Security & Monitoring',
            self::AccessControl => 'Access Control',
        };
    }

    public function getIcon(): ?string
    {
        return match ($this) {
            self::UserManagement => 'heroicon-o-users',
            self::OAuthManagement => 'heroicon-o-squares-2x2',
            self::SecurityMonitoring => 'heroicon-o-shield-check',
            self::AccessControl => 'heroicon-o-lock-closed',
        };
    }
}