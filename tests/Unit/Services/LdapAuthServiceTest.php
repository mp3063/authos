<?php

namespace Tests\Unit\Services;

use App\Models\AuthenticationLog;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use App\Services\LdapAuthService;
use Exception;
use Mockery;
use Tests\TestCase;

class LdapAuthServiceTest extends TestCase
{
    private LdapAuthService $service;

    private Organization $organization;

    private LdapConfiguration $config;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new LdapAuthService;

        $this->organization = Organization::factory()->create();

        $this->config = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'username' => 'cn=admin,dc=example,dc=com',
            'password' => encrypt('test-password'),
            'user_filter' => '(objectClass=person)',
            'user_attribute' => 'uid',
            'is_active' => true,
        ]);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_test_connection_validates_incomplete_config(): void
    {
        // Create a valid config then manually set invalid values to test validation
        $incompleteConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Manually set host to null (bypasses database constraints for testing)
        $incompleteConfig->host = null;
        $incompleteConfig->port = null;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('LDAP configuration is incomplete');

        $this->service->testConnection($incompleteConfig);
    }

    public function test_test_connection_logs_authentication_event(): void
    {
        if (! function_exists('ldap_connect')) {
            $this->markTestSkipped('LDAP extension not installed');
        }

        // Mock LDAP functions
        $this->expectException(Exception::class);

        try {
            $this->service->testConnection($this->config);
        } catch (Exception $e) {
            // Check that authentication log was created
            $this->assertDatabaseHas('authentication_logs', [
                'event' => 'ldap_test_failed',
                'success' => false,
            ]);

            throw $e;
        }
    }

    public function test_sync_users_validates_incomplete_config(): void
    {
        // Create a valid config then manually set invalid values to test validation
        $incompleteConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Manually set host to null (bypasses database constraints for testing)
        $incompleteConfig->host = null;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('LDAP configuration is incomplete');

        $this->service->syncUsers($incompleteConfig, $this->organization);
    }

    public function test_authenticate_user_requires_active_config(): void
    {
        $inactiveConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'is_active' => false,
        ]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('LDAP configuration is not active');

        $this->service->authenticateUser('testuser', 'password', $inactiveConfig);
    }

    public function test_get_users_from_ldap_validates_incomplete_config(): void
    {
        // Create a valid config then manually set invalid values to test validation
        $incompleteConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        // Manually set host to null (bypasses database constraints for testing)
        $incompleteConfig->host = null;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('LDAP configuration is incomplete');

        $this->service->getUsersFromLdap($incompleteConfig);
    }

    public function test_creates_authentication_log_on_sync_completion(): void
    {
        if (! function_exists('ldap_connect')) {
            $this->markTestSkipped('LDAP extension not installed');
        }

        $this->expectException(Exception::class);

        try {
            $this->service->syncUsers($this->config, $this->organization);
        } catch (Exception $e) {
            // Verify authentication log was created
            $this->assertDatabaseHas('authentication_logs', [
                'event' => 'ldap_sync_failed',
                'success' => false,
            ]);

            throw $e;
        }
    }

    public function test_handles_ldap_connection_failure_gracefully(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('LDAP connection test failed');

        $badConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'host' => 'invalid.domain.local',
            'port' => 389,
            'base_dn' => 'dc=invalid,dc=local',
            'username' => 'cn=admin,dc=invalid,dc=local',
            'password' => encrypt('password'),
        ]);

        $this->service->testConnection($badConfig);
    }

    public function test_maps_ldap_user_with_email(): void
    {
        $ldapUser = [
            'mail' => ['test@example.com'],
            'cn' => ['Test User'],
            'displayname' => ['Test User Display'],
        ];

        $reflection = new \ReflectionClass($this->service);
        $method = $reflection->getMethod('mapLdapUser');
        $method->setAccessible(true);

        $user = $method->invoke($this->service, $ldapUser, $this->organization);

        $this->assertInstanceOf(User::class, $user);
        $this->assertEquals('test@example.com', $user->email);
        $this->assertEquals('Test User Display', $user->name);
        $this->assertEquals($this->organization->id, $user->organization_id);
        $this->assertNotNull($user->email_verified_at);
    }

    public function test_maps_ldap_user_without_email_throws_exception(): void
    {
        $ldapUser = [
            'cn' => ['Test User'],
        ];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('No email found in LDAP user data');

        $reflection = new \ReflectionClass($this->service);
        $method = $reflection->getMethod('mapLdapUser');
        $method->setAccessible(true);

        $method->invoke($this->service, $ldapUser, $this->organization);
    }

    public function test_updates_existing_user_from_ldap(): void
    {
        $existingUser = User::factory()->create([
            'email' => 'existing@example.com',
            'organization_id' => $this->organization->id,
            'name' => 'Old Name',
        ]);

        $ldapUser = [
            'mail' => ['existing@example.com'],
            'displayname' => ['Updated Name'],
        ];

        $reflection = new \ReflectionClass($this->service);
        $method = $reflection->getMethod('mapLdapUser');
        $method->setAccessible(true);

        $user = $method->invoke($this->service, $ldapUser, $this->organization);

        $this->assertEquals($existingUser->id, $user->id);
        $this->assertEquals('Updated Name', $user->name);
    }

    public function test_generates_name_from_email_when_missing(): void
    {
        $ldapUser = [
            'mail' => ['testuser@example.com'],
        ];

        $reflection = new \ReflectionClass($this->service);
        $method = $reflection->getMethod('mapLdapUser');
        $method->setAccessible(true);

        $user = $method->invoke($this->service, $ldapUser, $this->organization);

        $this->assertEquals('testuser', $user->name);
    }

    public function test_logs_failed_user_sync_errors(): void
    {
        if (! function_exists('ldap_connect')) {
            $this->markTestSkipped('LDAP extension not installed');
        }

        $this->expectException(Exception::class);

        try {
            $this->service->syncUsers($this->config, $this->organization);
        } catch (Exception $e) {
            // Verify error was logged in authentication_logs
            $log = AuthenticationLog::where('event', 'ldap_sync_failed')->first();
            $this->assertNotNull($log);
            $this->assertFalse($log->success);
            $this->assertArrayHasKey('error', $log->metadata);

            throw $e;
        }
    }
}
