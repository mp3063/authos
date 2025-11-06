<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\SyncLdapUsersJob;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\User;
use App\Services\LdapAuthService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class SyncLdapUsersJobTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private LdapConfiguration $ldapConfig;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        $this->ldapConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
            'host' => 'ldap.example.com',
            'port' => 389,
            'base_dn' => 'dc=example,dc=com',
            'username' => 'cn=admin,dc=example,dc=com',
            'password' => 'password',
        ]);
    }

    #[Test]
    public function job_can_be_dispatched(): void
    {
        Queue::fake();

        SyncLdapUsersJob::dispatch($this->ldapConfig);

        Queue::assertPushed(SyncLdapUsersJob::class, function ($job) {
            return $job->ldapConfig->id === $this->ldapConfig->id;
        });
    }

    #[Test]
    public function job_has_correct_configuration(): void
    {
        $job = new SyncLdapUsersJob($this->ldapConfig);

        $this->assertEquals(300, $job->timeout);
        $this->assertEquals(3, $job->tries);
        $this->assertEquals(60, $job->backoff);
    }

    #[Test]
    public function job_executes_successfully_with_valid_ldap_config(): void
    {
        // Mock the LDAP service
        $mockService = Mockery::mock(LdapAuthService::class);
        $mockService->shouldReceive('syncUsers')
            ->once()
            ->with($this->ldapConfig, $this->organization)
            ->andReturn([
                'created' => 5,
                'updated' => 3,
                'failed' => 0,
            ]);

        $this->app->instance(LdapAuthService::class, $mockService);

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($mockService);

        // Verify LDAP config was updated
        $this->ldapConfig->refresh();
        $this->assertEquals('completed', $this->ldapConfig->sync_status);
        $this->assertNotNull($this->ldapConfig->last_sync_at);
        $this->assertEquals([
            'created' => 5,
            'updated' => 3,
            'failed' => 0,
        ], $this->ldapConfig->last_sync_result);
    }

    #[Test]
    public function job_creates_new_users_from_ldap(): void
    {
        // Mock the LDAP service to create users
        $mockService = Mockery::mock(LdapAuthService::class);
        $mockService->shouldReceive('syncUsers')
            ->once()
            ->andReturnUsing(function ($ldapConfig, $organization) {
                // Simulate creating users
                User::factory()->count(3)->create([
                    'organization_id' => $organization->id,
                    'provider' => 'ldap',
                ]);

                return [
                    'created' => 3,
                    'updated' => 0,
                    'failed' => 0,
                ];
            });

        $this->app->instance(LdapAuthService::class, $mockService);

        $initialUserCount = User::where('organization_id', $this->organization->id)->count();

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($mockService);

        $finalUserCount = User::where('organization_id', $this->organization->id)->count();
        $this->assertEquals($initialUserCount + 3, $finalUserCount);
    }

    #[Test]
    public function job_updates_existing_users(): void
    {
        // Create existing LDAP users
        $existingUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'ldap.user@example.com',
            'provider' => 'ldap',
            'name' => 'Old Name',
        ]);

        // Mock the LDAP service to update users
        $mockService = Mockery::mock(LdapAuthService::class);
        $mockService->shouldReceive('syncUsers')
            ->once()
            ->andReturnUsing(function () use ($existingUser) {
                // Simulate updating user
                $existingUser->update(['name' => 'Updated Name']);

                return [
                    'created' => 0,
                    'updated' => 1,
                    'failed' => 0,
                ];
            });

        $this->app->instance(LdapAuthService::class, $mockService);

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($mockService);

        $existingUser->refresh();
        $this->assertEquals('Updated Name', $existingUser->name);
    }

    #[Test]
    public function job_handles_ldap_connection_failures_gracefully(): void
    {
        Log::shouldReceive('info')
            ->with(Mockery::pattern('/Starting LDAP sync/'), Mockery::any())
            ->once();
        Log::shouldReceive('error')
            ->with(Mockery::pattern('/LDAP sync failed/'), Mockery::any())
            ->once();

        // Mock the LDAP service to throw connection exception
        $mockService = Mockery::mock(LdapAuthService::class);
        $mockService->shouldReceive('syncUsers')
            ->once()
            ->andThrow(new \Exception('LDAP connection failed'));

        $this->app->instance(LdapAuthService::class, $mockService);

        $job = new SyncLdapUsersJob($this->ldapConfig);

        try {
            $job->handle($mockService);
            $this->fail('Expected exception was not thrown');
        } catch (\Exception $e) {
            $this->assertEquals('LDAP connection failed', $e->getMessage());
        }

        // Verify error was recorded
        $this->ldapConfig->refresh();
        $this->assertEquals('failed', $this->ldapConfig->sync_status);
        $this->assertEquals('LDAP connection failed', $this->ldapConfig->last_sync_error);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }
}
