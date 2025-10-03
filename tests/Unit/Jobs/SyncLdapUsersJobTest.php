<?php

namespace Tests\Unit\Jobs;

use App\Jobs\SyncLdapUsersJob;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Services\LdapAuthService;
use Exception;
use Illuminate\Support\Facades\Queue;
use Mockery;
use Tests\TestCase;

class SyncLdapUsersJobTest extends TestCase
{
    private LdapConfiguration $ldapConfig;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();

        $this->ldapConfig = LdapConfiguration::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
    }

    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_can_be_dispatched_to_queue(): void
    {
        Queue::fake();

        SyncLdapUsersJob::dispatch($this->ldapConfig);

        Queue::assertPushed(SyncLdapUsersJob::class, function ($job) {
            return $job->ldapConfig->id === $this->ldapConfig->id;
        });
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_has_correct_configuration(): void
    {
        $job = new SyncLdapUsersJob($this->ldapConfig);

        $this->assertEquals(300, $job->timeout);
        $this->assertEquals(3, $job->tries);
        $this->assertEquals(60, $job->backoff);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calls_ldap_service_sync_users(): void
    {
        $service = Mockery::mock(LdapAuthService::class);
        $service->shouldReceive('syncUsers')
            ->once()
            ->with($this->ldapConfig, $this->ldapConfig->organization)
            ->andReturn([
                'created' => 5,
                'updated' => 3,
                'errors' => 0,
                'total' => 8,
            ]);

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($service);

        $this->ldapConfig->refresh();
        $this->assertEquals('completed', $this->ldapConfig->sync_status);
        $this->assertNotNull($this->ldapConfig->last_sync_at);
        $this->assertIsArray($this->ldapConfig->last_sync_result);
        $this->assertEquals(5, $this->ldapConfig->last_sync_result['created']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_sync_status_to_completed(): void
    {
        $service = Mockery::mock(LdapAuthService::class);
        $service->shouldReceive('syncUsers')
            ->once()
            ->andReturn([
                'created' => 2,
                'updated' => 1,
                'errors' => 0,
                'total' => 3,
            ]);

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($service);

        $this->assertDatabaseHas('ldap_configurations', [
            'id' => $this->ldapConfig->id,
            'sync_status' => 'completed',
        ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_sync_status_on_failure(): void
    {
        $service = Mockery::mock(LdapAuthService::class);
        $service->shouldReceive('syncUsers')
            ->once()
            ->andThrow(new Exception('LDAP connection failed'));

        $job = new SyncLdapUsersJob($this->ldapConfig);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('LDAP connection failed');

        $job->handle($service);

        $this->ldapConfig->refresh();
        $this->assertEquals('failed', $this->ldapConfig->sync_status);
        $this->assertEquals('LDAP connection failed', $this->ldapConfig->last_sync_error);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_calls_failed_method_on_permanent_failure(): void
    {
        $exception = new Exception('Permanent failure');

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->failed($exception);

        $this->ldapConfig->refresh();
        $this->assertEquals('failed', $this->ldapConfig->sync_status);
        $this->assertEquals('Permanent failure', $this->ldapConfig->last_sync_error);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_stores_sync_results_in_database(): void
    {
        $results = [
            'created' => 10,
            'updated' => 5,
            'errors' => 1,
            'total' => 16,
        ];

        $service = Mockery::mock(LdapAuthService::class);
        $service->shouldReceive('syncUsers')
            ->once()
            ->andReturn($results);

        $job = new SyncLdapUsersJob($this->ldapConfig);
        $job->handle($service);

        $this->ldapConfig->refresh();
        $this->assertEquals($results, $this->ldapConfig->last_sync_result);
    }
}
