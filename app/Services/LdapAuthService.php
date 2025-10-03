<?php

namespace App\Services;

use App\Jobs\SyncLdapUsersJob;
use App\Models\AuthenticationLog;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use Exception;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;

class LdapAuthService
{
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

        $connectionString = $config->getConnectionString();

        try {
            $ldapConnection = @ldap_connect($connectionString);

            if (! $ldapConnection) {
                throw new Exception('Failed to connect to LDAP server');
            }

            // Set LDAP options
            ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, config('services.ldap.version', 3));
            ldap_set_option($ldapConnection, LDAP_OPT_NETWORK_TIMEOUT, config('services.ldap.timeout', 5));
            ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);

            // Enable TLS if configured
            if ($config->use_tls && ! $config->use_ssl) {
                if (! @ldap_start_tls($ldapConnection)) {
                    throw new Exception('Failed to start TLS: '.ldap_error($ldapConnection));
                }
            }

            // Attempt to bind
            $bindResult = @ldap_bind($ldapConnection, $config->username, $config->password);

            if (! $bindResult) {
                $error = ldap_error($ldapConnection);
                ldap_unbind($ldapConnection);
                throw new Exception('LDAP bind failed: '.$error);
            }

            // Count users
            $userCount = 0;
            $searchFilter = $config->user_filter ?: '(objectClass=person)';
            $searchResult = @ldap_search($ldapConnection, $config->base_dn, $searchFilter, ['dn']);

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
            $ldapConnection = $this->connectToLdap($config);
            $ldapUsers = $this->getUsersFromLdapConnection($ldapConnection, $config);

            foreach ($ldapUsers as $ldapUser) {
                $stats['total']++;

                try {
                    $user = $this->mapLdapUser($ldapUser, $organization);

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
            $ldapConnection = $this->connectToLdap($config);
            $users = $this->getUsersFromLdapConnection($ldapConnection, $config, $limit);
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
            $ldapConnection = $this->connectToLdap($config);

            // Search for user
            $searchFilter = "(&({$config->user_attribute}={$username})".($config->user_filter ?: '(objectClass=person)').')';
            $searchResult = @ldap_search(
                $ldapConnection,
                $config->base_dn,
                $searchFilter,
                ['dn', 'cn', 'mail', 'displayName', 'givenName', 'sn']
            );

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
            $userBind = @ldap_bind($ldapConnection, $userDn, $password);

            ldap_free_result($searchResult);
            ldap_unbind($ldapConnection);

            if (! $userBind) {
                $this->logAuthenticationEvent($config->organization_id, null, 'ldap_auth_failed', false, [
                    'username' => $username,
                ]);

                return null;
            }

            // Authentication successful - find or create user
            $user = $this->mapLdapUser($userEntry, $config->organization);

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
     * Connect to LDAP server
     *
     * @return resource
     *
     * @throws Exception
     */
    private function connectToLdap(LdapConfiguration $config)
    {
        $connectionString = $config->getConnectionString();

        $ldapConnection = @ldap_connect($connectionString);

        if (! $ldapConnection) {
            throw new Exception('Failed to connect to LDAP server');
        }

        // Set LDAP options
        ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, config('services.ldap.version', 3));
        ldap_set_option($ldapConnection, LDAP_OPT_NETWORK_TIMEOUT, config('services.ldap.timeout', 5));
        ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);

        // Enable TLS if configured
        if ($config->use_tls && ! $config->use_ssl) {
            if (! @ldap_start_tls($ldapConnection)) {
                throw new Exception('Failed to start TLS: '.ldap_error($ldapConnection));
            }
        }

        // Bind to LDAP
        $bindResult = @ldap_bind($ldapConnection, $config->username, $config->password);

        if (! $bindResult) {
            $error = ldap_error($ldapConnection);
            ldap_unbind($ldapConnection);
            throw new Exception('LDAP bind failed: '.$error);
        }

        return $ldapConnection;
    }

    /**
     * Get users from LDAP connection
     */
    private function getUsersFromLdapConnection($ldapConnection, LdapConfiguration $config, int $limit = 100): array
    {
        $searchFilter = $config->user_filter ?: '(objectClass=person)';
        $searchResult = @ldap_search(
            $ldapConnection,
            $config->base_dn,
            $searchFilter,
            ['dn', 'cn', 'mail', 'displayName', 'givenName', 'sn', 'userPrincipalName'],
            0,
            $limit
        );

        if (! $searchResult) {
            throw new Exception('LDAP search failed: '.ldap_error($ldapConnection));
        }

        $entries = ldap_get_entries($ldapConnection, $searchResult);
        ldap_free_result($searchResult);

        $users = [];
        for ($i = 0; $i < $entries['count']; $i++) {
            $users[] = $entries[$i];
        }

        return $users;
    }

    /**
     * Map LDAP user to User model
     */
    private function mapLdapUser(array $ldapUser, Organization $organization): User
    {
        // Extract email from various LDAP attributes
        $email = $ldapUser['mail'][0] ?? $ldapUser['userprincipalname'][0] ?? null;

        if (! $email) {
            throw new Exception('No email found in LDAP user data');
        }

        // Extract name from various LDAP attributes
        $name = $ldapUser['displayname'][0] ??
            $ldapUser['cn'][0] ??
            ($ldapUser['givenname'][0] ?? '').' '.($ldapUser['sn'][0] ?? '');

        $name = trim($name);

        if (! $name) {
            $name = explode('@', $email)[0];
        }

        // Find or create user
        $user = User::updateOrCreate(
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

        return $user;
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
