<?php

declare(strict_types=1);

namespace Tests\Integration\Jobs;

use App\Jobs\ProcessAuth0MigrationJob;
use App\Jobs\ProcessOktaMigrationJob;
use App\Models\Application;
use App\Models\CustomRole;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Migration\Auth0MigrationService;
use App\Services\Auth0\Migration\ImportResult;
use App\Services\Auth0\Migration\MigrationPlan;
use App\Services\Auth0\Migration\MigrationResult;
use Illuminate\Support\Facades\Http;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Tests\Integration\IntegrationTestCase;

class MigrationRollbackTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
    }

    #[Test]
    public function it_rolls_back_only_the_records_the_job_created(): void
    {
        $existingUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $existingApplication = Application::factory()->create(['organization_id' => $this->organization->id]);
        $createdUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $createdApplication = Application::factory()->create(['organization_id' => $this->organization->id]);
        $createdRole = CustomRole::factory()->create(['organization_id' => $this->organization->id]);
        $job = $this->completedJobWithCreatedIds([
            'users' => [$createdUser->id],
            'applications' => [$createdApplication->id],
            'roles' => [$createdRole->id],
        ]);

        $job->rollback();

        $this->assertNotNull(User::find($existingUser->id));
        $this->assertNotNull(Application::find($existingApplication->id));
        $this->assertNull(User::withTrashed()->find($createdUser->id));
        $this->assertNull(Application::find($createdApplication->id));
        $this->assertNull(CustomRole::withTrashed()->find($createdRole->id));
        $this->assertSame('rolled_back', $job->fresh()->status);
    }

    #[Test]
    public function it_does_not_roll_back_records_of_another_organization(): void
    {
        $otherOrganization = Organization::factory()->create();
        $foreignUser = User::factory()->create(['organization_id' => $otherOrganization->id]);
        $job = $this->completedJobWithCreatedIds(['users' => [$foreignUser->id]]);

        $job->rollback();

        $this->assertNotNull(User::find($foreignUser->id));
    }

    #[Test]
    public function it_refuses_to_roll_back_a_job_without_recorded_ids(): void
    {
        User::factory()->count(2)->create(['organization_id' => $this->organization->id]);
        $job = MigrationJob::factory()->completed()->create(['organization_id' => $this->organization->id]);
        $userCount = User::count();

        $this->assertThrows(fn () => $job->rollback(), RuntimeException::class);
        $this->assertSame($userCount, User::count());
        $this->assertSame('completed', $job->fresh()->status);
    }

    #[Test]
    public function it_rolls_back_a_failed_job_from_the_ids_it_recorded(): void
    {
        $existingUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $createdUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $job = $this->completedJobWithCreatedIds(['users' => [$createdUser->id]]);
        $job->update(['status' => 'failed']);

        $job->rollback();

        $this->assertNotNull(User::find($existingUser->id));
        $this->assertNull(User::withTrashed()->find($createdUser->id));
        $this->assertSame('rolled_back', $job->fresh()->status);
    }

    #[Test]
    public function it_records_created_ids_for_an_auth0_migration(): void
    {
        $firstUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $secondUser = User::factory()->create(['organization_id' => $this->organization->id]);
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $role = CustomRole::factory()->create(['organization_id' => $this->organization->id]);
        $users = new ImportResult;
        $users->addSuccess('first', $firstUser->id);
        $users->addSuccess('dry-run', null);
        $users->addSuccess('second', $secondUser->id);
        $applications = new ImportResult;
        $applications->addSuccess('app', $application->id);
        $roles = new ImportResult;
        $roles->addSuccess('role', $role->id);
        $this->mockAuth0Migration(new MigrationResult(
            organizations: new ImportResult,
            roles: $roles,
            applications: $applications,
            users: $users,
        ));
        $job = MigrationJob::factory()->create([
            'organization_id' => $this->organization->id,
            'source' => 'auth0',
            'config' => ['tenant_domain' => 'tenant.auth0.com', 'api_token' => 'token'],
        ]);

        (new ProcessAuth0MigrationJob($job))->handle();

        $createdIds = $job->fresh()->migrated_data['created_ids'];
        $this->assertSame([$firstUser->id, $secondUser->id], $createdIds['users']);
        $this->assertSame([$application->id], $createdIds['applications']);
        $this->assertSame([$role->id], $createdIds['roles']);
        $this->assertSame([], $createdIds['organizations']);
    }

    #[Test]
    public function it_records_created_ids_for_an_okta_migration_even_when_it_fails_midway(): void
    {
        Http::fake([
            '*/api/v1/users*' => Http::response([
                $this->oktaUser('okta-1', 'first@okta.test'),
                $this->oktaUser('okta-2', 'second@okta.test'),
            ]),
        ]);
        MigrationJob::updating(function (MigrationJob $job): void {
            if ($job->isDirty('status') && in_array($job->status, ['completed', 'failed'], true)) {
                throw new RuntimeException('Worker lost before the migration finished');
            }
        });
        $job = MigrationJob::factory()->create([
            'organization_id' => $this->organization->id,
            'source' => 'okta',
            'config' => ['okta_domain' => 'tenant.okta.com', 'okta_api_token' => 'token', 'migrate_users' => true],
        ]);

        $this->assertThrows(fn () => (new ProcessOktaMigrationJob($job))->handle(), RuntimeException::class);

        $this->assertSame(
            User::whereIn('email', ['first@okta.test', 'second@okta.test'])->orderBy('id')->pluck('id')->all(),
            $job->fresh()->migrated_data['created_ids']['users'],
        );
    }

    #[Test]
    public function it_lets_a_rolled_back_migration_run_again(): void
    {
        $createdUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'imported@example.com',
        ]);
        $createdRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'imported-role',
        ]);
        $job = $this->completedJobWithCreatedIds([
            'users' => [$createdUser->id],
            'roles' => [$createdRole->id],
        ]);

        $job->rollback();
        $reimportedUser = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'imported@example.com',
        ]);
        $reimportedRole = CustomRole::factory()->create([
            'organization_id' => $this->organization->id,
            'name' => 'imported-role',
        ]);

        $this->assertNotSame($createdUser->id, $reimportedUser->id);
        $this->assertNotSame($createdRole->id, $reimportedRole->id);
    }

    /**
     * @param  array{organizations?: int[], roles?: int[], applications?: int[], users?: int[]}  $createdIds
     */
    private function completedJobWithCreatedIds(array $createdIds): MigrationJob
    {
        return MigrationJob::factory()->completed()->create([
            'organization_id' => $this->organization->id,
            'migrated_data' => [
                'created_ids' => array_merge(
                    ['organizations' => [], 'roles' => [], 'applications' => [], 'users' => []],
                    $createdIds,
                ),
            ],
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function oktaUser(string $id, string $email): array
    {
        return [
            'id' => $id,
            'status' => 'ACTIVE',
            'profile' => ['email' => $email, 'firstName' => 'Okta', 'lastName' => 'User'],
        ];
    }

    private function mockAuth0Migration(MigrationResult $result): void
    {
        $service = Mockery::mock(Auth0MigrationService::class);
        $service->shouldReceive('discover')->once()->andReturn(new MigrationPlan(users: [], applications: [], roles: []));
        $service->shouldReceive('migrate')->once()->andReturn($result);

        $this->app->bind(Auth0Client::class, fn () => Mockery::mock(Auth0Client::class));
        $this->app->bind(Auth0MigrationService::class, fn () => $service);
    }
}
