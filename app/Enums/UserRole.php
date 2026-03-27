<?php

namespace App\Enums;

enum UserRole: string
{
    case SuperAdmin = 'super-admin';
    case OrganizationOwner = 'organization-owner';
    case OrganizationAdmin = 'organization-admin';
    case User = 'user';

    public function label(): string
    {
        return match ($this) {
            self::SuperAdmin => 'Super Admin',
            self::OrganizationOwner => 'Organization Owner',
            self::OrganizationAdmin => 'Organization Admin',
            self::User => 'User',
        };
    }
}
