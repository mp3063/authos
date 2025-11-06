<?php

namespace Tests\Integration\Enterprise;

use App\Jobs\SyncLdapUsersJob;
use App\Models\AuthenticationLog;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use App\Services\LdapAuthService;
use Exception;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

/**
 * Integration tests for LDAP Authentication & Sync
 *
 * Tests comprehensive LDAP functionality including:
 * - Connection testing (TLS/SSL)
 * - User authentication and validation
 * - User discovery and sync operations
 * - Error handling and security
 * - Job scheduling and progress tracking
 * - Multi-server support
 *
 * Note: These tests verify LDAP configuration and error handling
 * behavior without requiring an actual LDAP server.
 */
class LdapAuthenticationTest extends IntegrationTestCase
{
    private LdapConfiguration $ldapConfig;

    private Organization $organization;

    private LdapAuthService $ldapService;

    protected function setUp(): void
    {
        parent::setUp();

        // Skip LDAP tests if LDAP extension not available
        if (! extension_loaded('ldap')) {
            $this->markTestSkipped('LDAP extension not available');
        }

        // Create organization for testing
        $this->organization = Organization::factory()->create([
            'name' => 'LDAP Test Corp',
        ]);

        // Create LDAP configuration
        $this->ldapConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Test LDAP Server',
            'host' => 'ldap.testcorp.com',
            'port' => 389,
            'base_dn' => 'dc=testcorp,dc=com',
            'username' => 'cn=admin,dc=testcorp,dc=com',
            'password' => 'admin-password',
            'use_ssl' => false,
            'use_tls' => false, // Disable TLS for testing (would fail without real server)
            'user_filter' => '(objectClass=person)',
            'user_attribute' => 'uid',
            'is_active' => true,
        ]);

        $this->ldapService = app(LdapAuthService::class);
    }

    // ============================================================
    // CONNECTION TESTS (Focus on configuration validation)
    // ============================================================

    #[Test]
    public function ldap_connection_string_generated_correctly_for_ldap()
    {
        // ARRANGE: Config with standard LDAP
        $this->ldapConfig->update([
            'use_ssl' => false,
            'port' => 389,
        ]);

        // ACT: Get connection string
        $connectionString = $this->ldapConfig->getConnectionString();

        // ASSERT: Correct LDAP connection string
        $this->assertEquals('ldap://ldap.testcorp.com:389', $connectionString);
    }

    #[Test]
    public function ldap_connection_string_generated_correctly_for_ldaps()
    {
        // ARRANGE: Update config for SSL
        $this->ldapConfig->update([
            'use_ssl' => true,
            'use_tls' => false,
            'port' => 636,
        ]);

        // ACT: Get connection string
        $connectionString = $this->ldapConfig->getConnectionString();

        // ASSERT: Connection string uses LDAPS protocol
        $this->assertEquals('ldaps://ldap.testcorp.com:636', $connectionString);
    }

    #[Test]
    public function ldap_connection_fails_with_nonexistent_host()
    {
        // ARRANGE: Config with invalid host (will fail to connect)
        $this->ldapConfig->update([
            'host' => 'nonexistent-ldap-server-999.invalid',
        ]);

        // ACT & ASSERT: Connection fails with exception
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/LDAP connection test failed/');

        $this->ldapService->testConnection($this->ldapConfig);
    }

    #[Test]
    public function ldap_connection_logs_failure_on_error()
    {
        // ARRANGE: Config with invalid host
        $this->ldapConfig->update([
            'host' => 'nonexistent-server.invalid',
        ]);

        // ACT: Attempt connection (will fail)
        try {
            $this->ldapService->testConnection($this->ldapConfig);
        } catch (Exception $e) {
            // Expected to fail
        }

        // ASSERT: Failed audit log created
        $this->assertDatabaseHas('authentication_logs', [
            'event' => 'ldap_test_failed',
            'success' => false,
        ]);
    }

    #[Test]
    public function incomplete_ldap_configuration_cannot_be_tested()
    {
        // ARRANGE: Create incomplete config (missing password)
        $incompleteConfig = LdapConfiguration::factory()->make([
            'organization_id' => $this->organization->id,
            'password' => null,
        ]);

        // ACT & ASSERT: Configuration is not testable
        $this->assertFalse($incompleteConfig->isTestable());
    }

    #[Test]
    public function complete_ldap_configuration_is_testable()
    {
        // ARRANGE: Use complete config from setUp
        // ACT & ASSERT: Configuration is testable
        $this->assertTrue($this->ldapConfig->isTestable());
    }

    // ============================================================
    // USER AUTHENTICATION TESTS (Configuration validation)
    // ============================================================

    #[Test]
    public function ldap_authentication_fails_for_nonexistent_host()
    {
        // ARRANGE: Config with invalid host
        $this->ldapConfig->update([
            'host' => 'nonexistent-server.invalid',
        ]);

        // ACT & ASSERT: Authentication fails
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/LDAP authentication failed/');

        $this->ldapService->authenticateUser('john.doe', 'password', $this->ldapConfig);
    }

    #[Test]
    public function inactive_ldap_configuration_rejects_authentication()
    {
        // ARRANGE: Deactivate LDAP config
        $this->ldapConfig->update(['is_active' => false]);

        // ACT & ASSERT: Authentication rejected
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('LDAP configuration is not active');

        $this->ldapService->authenticateUser('john.doe', 'password', $this->ldapConfig);
    }

    // ============================================================
    // LDAP CONFIGURATION TESTS
    // ============================================================

    #[Test]
    public function ldap_configuration_encrypts_password()
    {
        // ARRANGE: Create config with password
        $config = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'password' => 'test-password',
        ]);

        // ACT: Retrieve raw password from database
        $rawPassword = \DB::table('ldap_configurations')
            ->where('id', $config->id)
            ->value('password');

        // ASSERT: Password is encrypted (not plain text)
        $this->assertNotEquals('test-password', $rawPassword);
        $this->assertStringContainsString('eyJpdiI6', $rawPassword); // Laravel encryption format

        // ASSERT: Decrypted password matches original
        $this->assertEquals('test-password', $config->password);
    }

    #[Test]
    public function ldap_configuration_has_correct_attribute_casts()
    {
        // ACT: Check casts
        $casts = $this->ldapConfig->getCasts();

        // ASSERT: Correct types
        $this->assertEquals('integer', $casts['port']);
        $this->assertEquals('boolean', $casts['use_ssl']);
        $this->assertEquals('boolean', $casts['use_tls']);
        $this->assertEquals('boolean', $casts['is_active']);
        $this->assertEquals('datetime', $casts['last_sync_at']);
        $this->assertEquals('array', $casts['last_sync_result']);
        $this->assertEquals('array', $casts['sync_settings']);
    }

    #[Test]
    public function ldap_configuration_hides_password_in_json()
    {
        // ACT: Convert to array
        $array = $this->ldapConfig->toArray();

        // ASSERT: Password not included
        $this->assertArrayNotHasKey('password', $array);
    }

    #[Test]
    public function ldap_configuration_belongs_to_organization()
    {
        // ACT: Get organization relationship
        $organization = $this->ldapConfig->organization;

        // ASSERT: Correct organization
        $this->assertInstanceOf(Organization::class, $organization);
        $this->assertEquals($this->organization->id, $organization->id);
    }

    // ============================================================
    // JOB SCHEDULING TESTS
    // ============================================================

    #[Test]
    public function sync_job_is_dispatched_for_async_execution()
    {
        // ARRANGE: Fake queue
        Queue::fake();

        // ACT: Dispatch async sync
        $this->ldapService->syncUsersAsync($this->ldapConfig);

        // ASSERT: Job dispatched
        Queue::assertPushed(SyncLdapUsersJob::class, function ($job) {
            return $job->ldapConfig->id === $this->ldapConfig->id;
        });

        // ASSERT: Sync status set to pending
        $this->ldapConfig->refresh();
        $this->assertEquals('pending', $this->ldapConfig->sync_status);
    }

    #[Test]
    public function sync_job_has_correct_configuration()
    {
        // ARRANGE: Create job instance
        $job = new SyncLdapUsersJob($this->ldapConfig);

        // ASSERT: Job configuration
        $this->assertEquals(300, $job->timeout); // 5 minutes
        $this->assertEquals(3, $job->tries);
        $this->assertEquals(60, $job->backoff); // 60 seconds
    }

    #[Test]
    public function sync_job_updates_status_on_failure()
    {
        // ARRANGE: Config with invalid host (will fail)
        $this->ldapConfig->update([
            'host' => 'nonexistent-server.invalid',
        ]);

        // Create job instance
        $job = new SyncLdapUsersJob($this->ldapConfig);

        // ACT & ASSERT: Job throws exception
        try {
            $job->handle($this->ldapService);
        } catch (Exception $e) {
            // Expected - invalid host
        }

        // ASSERT: Status updated to failed
        $this->ldapConfig->refresh();
        $this->assertEquals('failed', $this->ldapConfig->sync_status);
        $this->assertNotNull($this->ldapConfig->last_sync_error);
    }

    #[Test]
    public function sync_job_failed_handler_updates_status()
    {
        // ARRANGE: Create job
        $job = new SyncLdapUsersJob($this->ldapConfig);
        $exception = new Exception('Test failure');

        // ACT: Call failed handler
        $job->failed($exception);

        // ASSERT: Status marked as failed
        $this->ldapConfig->refresh();
        $this->assertEquals('failed', $this->ldapConfig->sync_status);
        $this->assertEquals('Test failure', $this->ldapConfig->last_sync_error);
    }

    // ============================================================
    // MULTIPLE SERVER SUPPORT TESTS
    // ============================================================

    #[Test]
    public function organization_can_have_multiple_ldap_servers()
    {
        // ARRANGE: Create additional LDAP configurations
        $ldapConfig2 = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Secondary LDAP Server',
            'host' => 'ldap2.testcorp.com',
        ]);

        $ldapConfig3 = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'Tertiary LDAP Server',
            'host' => 'ldap3.testcorp.com',
        ]);

        // ACT: Retrieve LDAP configs for organization
        $configs = LdapConfiguration::where('organization_id', $this->organization->id)->get();

        // ASSERT: All configs present
        $this->assertCount(3, $configs);
        $this->assertTrue($configs->contains('id', $this->ldapConfig->id));
        $this->assertTrue($configs->contains('id', $ldapConfig2->id));
        $this->assertTrue($configs->contains('id', $ldapConfig3->id));
    }

    #[Test]
    public function can_query_only_active_ldap_configurations()
    {
        // ARRANGE: Create mix of active and inactive configs
        LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'is_active' => false,
        ]);

        LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        // ACT: Query active configs
        $activeConfigs = LdapConfiguration::where('organization_id', $this->organization->id)
            ->active()
            ->get();

        // ASSERT: Only active configs returned
        $this->assertCount(2, $activeConfigs); // Original + new active
        $this->assertTrue($activeConfigs->every(fn ($config) => $config->is_active));
    }

    #[Test]
    public function ldap_configuration_scope_filters_active_only()
    {
        // ARRANGE: Query using active scope
        $activeCount = LdapConfiguration::where('organization_id', $this->organization->id)
            ->active()
            ->count();

        // ASSERT: Correct count (original config is active)
        $this->assertGreaterThanOrEqual(1, $activeCount);
    }

    // ============================================================
    // PASSWORD ENCRYPTION TESTS
    // ============================================================

    #[Test]
    public function ldap_password_is_stored_encrypted()
    {
        // ARRANGE: Create config with known password
        $testPassword = 'MySecurePassword123!';
        $config = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'password' => $testPassword,
        ]);

        // ACT: Check raw database value
        $rawValue = \DB::table('ldap_configurations')
            ->where('id', $config->id)
            ->value('password');

        // ASSERT: Raw value is encrypted
        $this->assertNotEquals($testPassword, $rawValue);
        $this->assertNotEmpty($rawValue);

        // ASSERT: Accessor decrypts correctly
        $this->assertEquals($testPassword, $config->password);
    }

    #[Test]
    public function ldap_password_can_be_updated()
    {
        // ARRANGE: Update password
        $newPassword = 'NewPassword456!';
        $this->ldapConfig->update(['password' => $newPassword]);

        // ACT: Refresh and check
        $this->ldapConfig->refresh();

        // ASSERT: New password is set and encrypted
        $this->assertEquals($newPassword, $this->ldapConfig->password);
    }

    #[Test]
    public function ldap_configuration_with_null_password_handled()
    {
        // ARRANGE: Create config without password
        $config = LdapConfiguration::factory()->make([
            'organization_id' => $this->organization->id,
            'password' => null,
        ]);

        // ACT & ASSERT: Null password is not testable
        $this->assertFalse($config->isTestable());
    }
}
