<?php

namespace App\Services;

use App\Jobs\SyncLdapUsersJob;
use App\Models\AuthenticationLog;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use App\Services\Ldap\LdapConnector;
use App\Services\Ldap\LdapUserMapper;
use Exception;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;

class LdapAuthService
{
    public function __construct(
        private readonly LdapConnector $connector,
        private readonly LdapUserMapper $userMapper,
    ) {}

    /**
     * Sync users asynchronously using a queued job
     */
    public function syncUsersAsync(LdapConfiguration $config): void
    {
        $config->update(['sync_status' => 'pending']);
        SyncLdapUsersJob::dispatch($config);
    }

    /**
     * Test LDAP connection
     *
     * @throws Exception
     */
    public function testConnection(LdapConfiguration $config): array
    {
        if (! $config->isTestable()) {
            throw new InvalidArgumentException('LDAP configuration is incomplete');
        }

        try {
            $ldapConnection = $this->connector->connect($config);

            // Count users
            $userCount = 0;
            $searchFilter = $config->user_filter ?: '(objectClass=person)';
            $searchResult = $this->connector->search($ldapConnection, $config, $searchFilter, ['dn']);

            if ($searchResult) {
                $entries = ldap_get_entries($ldapConnection, $searchResult);
                $userCount = $entries['count'] ?? 0;
                ldap_free_result($searchResult);
            }

            ldap_unbind($ldapConnection);

            $this->logAuthenticationEvent($config->organization_id, null, 'ldap_test_success', true, [
                'host' => $config->host,
                'user_count' => $userCount,
            ]);

            return [
                'success' => true,
                'user_count' => $userCount,
                'message' => 'LDAP connection successful',
            ];
        } catch (Exception $e) {
            $this->logAuthenticationEvent($config->organization_id, null, 'ldap_test_failed', false, [
                'host' => $config->host,
                'error' => $e->getMessage(),
            ]);

            Log::error('LDAP connection test failed', [
                'config_id' => $config->id,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('LDAP connection test failed: '.$e->getMessage());
        }
    }

    /**
     * Sync users from LDAP to database
     *
     * @throws Exception
     */
    public function syncUsers(LdapConfiguration $config, Organization $organization): array
    {
        if (! $config->isTestable()) {
            throw new InvalidArgumentException('LDAP configuration is incomplete');
        }

        $stats = [
            'created' => 0,
            'updated' => 0,
            'errors' => 0,
            'total' => 0,
        ];

        try {
            $ldapConnection = $this->connector->connect($config);
            $ldapUsers = $this->connector->searchUsers($ldapConnection, $config);

            $attributeMapping = $config->sync_settings['attribute_mapping'] ?? null;
            $groupRoleMapping = $config->sync_settings['group_role_mapping'] ?? [];
            $groupAttribute = $config->sync_settings['group_attribute'] ?? 'memberOf';

            foreach ($ldapUsers as $ldapUser) {
                $stats['total']++;

                try {
                    $user = $this->userMapper->map($ldapUser, $organization, $attributeMapping);

                    if (! empty($groupRoleMapping)) {
                        $this->userMapper->assignRolesFromGroups($user, $ldapUser, $groupRoleMapping, $groupAttribute);
                    }

                    if ($user->wasRecentlyCreated) {
                        $stats['created']++;
                    } else {
                        $stats['updated']++;
                    }

                    $this->logAuthenticationEvent($organization->id, null, 'ldap_user_synced', true, [
                        'user_id' => $user->id,
                        'email' => $user->email,
                        'action' => $user->wasRecentlyCreated ? 'created' : 'updated',
                    ]);
                } catch (Exception $e) {
                    $stats['errors']++;
                    Log::error('Failed to sync LDAP user', [
                        'ldap_user' => $ldapUser,
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            ldap_unbind($ldapConnection);

            // Update last sync timestamp
            $config->update(['last_sync_at' => now()]);

            $this->logAuthenticationEvent($organization->id, null, 'ldap_sync_completed', true, $stats);

            return $stats;
        } catch (Exception $e) {
            $this->logAuthenticationEvent($organization->id, null, 'ldap_sync_failed', false, [
                'error' => $e->getMessage(),
            ]);

            Log::error('LDAP sync failed', [
                'config_id' => $config->id,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('LDAP user sync failed: '.$e->getMessage());
        }
    }

    /**
     * Get users from LDAP (paginated)
     *
     * @throws Exception
     */
    public function getUsersFromLdap(LdapConfiguration $config, int $limit = 100): array
    {
        if (! $config->isTestable()) {
            throw new InvalidArgumentException('LDAP configuration is incomplete');
        }

        try {
            $ldapConnection = $this->connector->connect($config);
            $users = $this->connector->searchUsers($ldapConnection, $config, $limit);
            ldap_unbind($ldapConnection);

            return $users;
        } catch (Exception $e) {
            Log::error('Failed to fetch LDAP users', [
                'config_id' => $config->id,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('Failed to fetch LDAP users: '.$e->getMessage());
        }
    }

    /**
     * Authenticate user against LDAP
     *
     * @throws Exception
     */
    public function authenticateUser(string $username, string $password, LdapConfiguration $config): ?User
    {
        if (! $config->is_active) {
            throw new Exception('LDAP configuration is not active');
        }

        try {
            $ldapConnection = $this->connector->connect($config);

            // Determine attributes to fetch, including group attribute
            $groupAttribute = $config->sync_settings['group_attribute'] ?? 'memberOf';
            $searchAttributes = ['dn', 'cn', 'mail', 'displayName', 'givenName', 'sn', 'userPrincipalName', strtolower($groupAttribute)];

            // Search for user
            $searchFilter = "(&({$config->user_attribute}={$username})".($config->user_filter ?: '(objectClass=person)').')';
            $searchResult = $this->connector->search($ldapConnection, $config, $searchFilter, $searchAttributes);

            if (! $searchResult) {
                ldap_unbind($ldapConnection);
                $this->logAuthenticationEvent($config->organization_id, null, 'ldap_user_not_found', false, [
                    'username' => $username,
                ]);

                return null;
            }

            $entries = ldap_get_entries($ldapConnection, $searchResult);

            if ($entries['count'] === 0) {
                ldap_free_result($searchResult);
                ldap_unbind($ldapConnection);
                $this->logAuthenticationEvent($config->organization_id, null, 'ldap_user_not_found', false, [
                    'username' => $username,
                ]);

                return null;
            }

            $userEntry = $entries[0];
            $userDn = $userEntry['dn'];

            // Attempt to bind as user
            $userBind = $this->connector->bind($ldapConnection, $userDn, $password);

            ldap_free_result($searchResult);
            ldap_unbind($ldapConnection);

            if (! $userBind) {
                $this->logAuthenticationEvent($config->organization_id, null, 'ldap_auth_failed', false, [
                    'username' => $username,
                ]);

                return null;
            }

            // Authentication successful - find or create user
            $attributeMapping = $config->sync_settings['attribute_mapping'] ?? null;
            $user = $this->userMapper->map($userEntry, $config->organization, $attributeMapping);

            // Assign roles based on LDAP group membership
            $groupRoleMapping = $config->sync_settings['group_role_mapping'] ?? [];
            if (! empty($groupRoleMapping)) {
                $this->userMapper->assignRolesFromGroups($user, $userEntry, $groupRoleMapping, $groupAttribute);
            }

            $this->logAuthenticationEvent($config->organization_id, $user->id, 'ldap_auth_success', true, [
                'username' => $username,
            ]);

            return $user;
        } catch (Exception $e) {
            Log::error('LDAP authentication failed', [
                'config_id' => $config->id,
                'username' => $username,
                'error' => $e->getMessage(),
            ]);

            $this->logAuthenticationEvent($config->organization_id, null, 'ldap_auth_error', false, [
                'username' => $username,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('LDAP authentication failed: '.$e->getMessage());
        }
    }

    /**
     * Log authentication events for audit trail
     */
    private function logAuthenticationEvent(?int $organizationId, ?int $userId, string $event, bool $success, array $metadata = []): void
    {
        try {
            AuthenticationLog::create([
                'user_id' => $userId,
                'application_id' => null,
                'event' => $event,
                'success' => $success,
                'ip_address' => request()->ip() ?? '127.0.0.1',
                'user_agent' => request()->userAgent() ?? 'LDAP Service',
                'metadata' => array_merge($metadata, [
                    'organization_id' => $organizationId,
                ]),
            ]);
        } catch (Exception $e) {
            Log::error('Failed to log LDAP authentication event', [
                'error' => $e->getMessage(),
                'event' => $event,
            ]);
        }
    }
}
