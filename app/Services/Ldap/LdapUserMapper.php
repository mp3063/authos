<?php

namespace App\Services\Ldap;

use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Log;

class LdapUserMapper
{
    private const DEFAULT_ATTRIBUTE_MAPPING = [
        'mail' => 'email',
        'displayName' => 'name',
        'cn' => 'name_fallback',
        'givenName' => 'first_name',
        'sn' => 'last_name',
        'userPrincipalName' => 'email_fallback',
    ];

    /**
     * Map LDAP user to User model
     *
     * @throws Exception
     */
    public function map(array $ldapUser, Organization $organization, ?array $attributeMapping = null): User
    {
        $mapping = $attributeMapping ?? self::DEFAULT_ATTRIBUTE_MAPPING;

        $email = $this->resolveMappedValue($ldapUser, $mapping, 'email', 'email_fallback');

        if (! $email) {
            throw new Exception('No email found in LDAP user data');
        }

        $name = $this->resolveMappedValue($ldapUser, $mapping, 'name', 'name_fallback');

        // Fallback: combine first_name + last_name
        if (! $name) {
            $firstName = $this->lastMappedValue($ldapUser, $mapping, 'first_name');
            $lastName = $this->lastMappedValue($ldapUser, $mapping, 'last_name');
            $name = trim("$firstName $lastName");
        }

        if (! $name) {
            $name = explode('@', $email)[0];
        }

        return User::updateOrCreate(
            [
                'email' => $email,
                'organization_id' => $organization->id,
            ],
            [
                'name' => $name,
                'password' => bcrypt(bin2hex(random_bytes(16))), // Random password since LDAP handles auth
                'email_verified_at' => now(), // Auto-verify LDAP users
            ]
        );
    }

    /**
     * Assign application roles to a user based on their LDAP group memberships
     */
    public function assignRolesFromGroups(User $user, array $ldapUser, array $groupRoleMapping, string $groupAttribute = 'memberof'): void
    {
        if (empty($groupRoleMapping)) {
            return;
        }

        $userGroups = $ldapUser[strtolower($groupAttribute)] ?? [];
        if (isset($userGroups['count'])) {
            unset($userGroups['count']);
        }

        foreach ($groupRoleMapping as $ldapGroupDn => $roleName) {
            if (in_array($ldapGroupDn, $userGroups, true)) {
                try {
                    $user->assignRole($roleName);
                } catch (Exception $e) {
                    Log::warning("Failed to assign role '{$roleName}' to user {$user->email}: {$e->getMessage()}");
                }
            }
        }
    }

    /**
     * First value mapped to the primary field, otherwise the last value mapped to the fallback field.
     */
    private function resolveMappedValue(array $ldapUser, array $mapping, string $primaryField, string $fallbackField): mixed
    {
        $value = null;
        foreach ($mapping as $ldapAttr => $userField) {
            if (in_array($userField, [$primaryField, $fallbackField]) && ! empty($ldapUser[strtolower($ldapAttr)][0])) {
                $value = $ldapUser[strtolower($ldapAttr)][0];
                if ($userField === $primaryField) {
                    break;
                }
            }
        }

        return $value;
    }

    private function lastMappedValue(array $ldapUser, array $mapping, string $field): mixed
    {
        $value = '';
        foreach ($mapping as $ldapAttr => $userField) {
            if ($userField === $field && ! empty($ldapUser[strtolower($ldapAttr)][0])) {
                $value = $ldapUser[strtolower($ldapAttr)][0];
            }
        }

        return $value;
    }
}
