<?php

namespace App\Services\Ldap;

use App\Models\LdapConfiguration;
use Exception;
use LDAP\Connection;
use LDAP\Result;

class LdapConnector
{
    /**
     * Connect and bind to the LDAP server with the configured service account
     *
     * @throws Exception
     */
    public function connect(LdapConfiguration $config): Connection
    {
        $connectionString = $config->getConnectionString();

        $ldapConnection = $this->withoutWarnings(fn () => ldap_connect($connectionString));

        if (! $ldapConnection) {
            throw new Exception('Failed to connect to LDAP server');
        }

        // Set LDAP options
        ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, config('services.ldap.version', 3));
        ldap_set_option($ldapConnection, LDAP_OPT_NETWORK_TIMEOUT, config('services.ldap.timeout', 5));
        ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);

        // Enable TLS if configured
        if ($config->use_tls && ! $config->use_ssl) {
            if (! $this->withoutWarnings(fn () => ldap_start_tls($ldapConnection))) {
                throw new Exception('Failed to start TLS: '.ldap_error($ldapConnection));
            }
        }

        // Bind to LDAP
        $bindResult = $this->bind($ldapConnection, $config->username, $config->password);

        if (! $bindResult) {
            $error = ldap_error($ldapConnection);
            ldap_unbind($ldapConnection);
            throw new Exception('LDAP bind failed: '.$error);
        }

        return $ldapConnection;
    }

    public function bind(Connection $connection, ?string $dn, ?string $password): bool
    {
        return $this->withoutWarnings(fn () => ldap_bind($connection, $dn, $password));
    }

    public function search(Connection $connection, LdapConfiguration $config, string $filter, array $attributes): Result|false
    {
        return $this->withoutWarnings(fn () => ldap_search($connection, $config->base_dn, $filter, $attributes));
    }

    /**
     * Get users from LDAP connection
     *
     * @throws Exception
     */
    public function searchUsers(Connection $connection, LdapConfiguration $config, int $limit = 100): array
    {
        $groupAttribute = $config->sync_settings['group_attribute'] ?? 'memberOf';
        $attributes = ['dn', 'cn', 'mail', 'displayName', 'givenName', 'sn', 'userPrincipalName', strtolower($groupAttribute)];

        $searchFilter = $config->user_filter ?: '(objectClass=person)';
        $searchResult = $this->withoutWarnings(fn () => ldap_search(
            $connection,
            $config->base_dn,
            $searchFilter,
            $attributes,
            0,
            $limit
        ));

        if (! $searchResult) {
            throw new Exception('LDAP search failed: '.ldap_error($connection));
        }

        $entries = ldap_get_entries($connection, $searchResult);
        ldap_free_result($searchResult);

        $users = [];
        for ($i = 0; $i < $entries['count']; $i++) {
            $users[] = $entries[$i];
        }

        return $users;
    }

    /**
     * Run an ext-ldap call with PHP warnings silenced, as these calls report failure through their return value.
     */
    private function withoutWarnings(callable $operation): mixed
    {
        set_error_handler(static fn (): bool => true);

        try {
            return $operation();
        } finally {
            restore_error_handler();
        }
    }
}
