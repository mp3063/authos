<?php

namespace Tests\Integration\BulkOperations;

use App\Jobs\ProcessBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\BulkUserDataService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class BulkImportDefaultRoleTest extends IntegrationTestCase
{
    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        Queue::fake();

        $this->organization = $this->createOrganization();
    }

    #[Test]
    public function it_assigns_the_default_role_to_imported_users(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        $importJob = $this->importJob($owner, 'User Manager', ['first@example.com', 'second@example.com']);

        (new ProcessBulkImportJob($importJob))->handle();

        $this->assertSame(2, $importJob->refresh()->successful_records);
        foreach (['first@example.com', 'second@example.com'] as $email) {
            $imported = User::where('email', $email)->firstOrFail();
            $this->assertCount(1, $this->assignedRolesNamed($imported, 'User Manager'));
        }
    }

    #[Test]
    public function it_rejects_a_default_role_the_importer_cannot_grant_with_422(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);

        $this->actingAsApiUserWithToken($admin, ['users.manage'])
            ->postJson('/api/v1/bulk/users/import', [
                'file' => $this->csv(['first@example.com']),
                'format' => 'csv',
                'default_role' => 'Organization Owner',
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('default_role');

        Queue::assertNothingPushed();
        $this->assertSame(0, BulkImportJob::count());
    }

    #[Test]
    public function it_does_not_assign_a_default_role_the_importer_cannot_grant_when_the_job_runs(): void
    {
        $admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
        $importJob = $this->importJob($admin, 'Organization Owner', ['imported@example.com']);

        (new ProcessBulkImportJob($importJob))->handle();

        $importJob->refresh();
        $this->assertSame(1, $importJob->failed_records);
        $this->assertSame(0, $importJob->successful_records);
        $this->assertNotEmpty($importJob->errors);
        $this->assertDatabaseMissing('users', ['email' => 'imported@example.com']);
    }

    #[Test]
    public function it_rejects_another_organizations_role_as_default_role_with_422(): void
    {
        $owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
        Role::create([
            'name' => 'Foreign Role',
            'guard_name' => 'api',
            'organization_id' => $this->createOrganization()->id,
        ]);

        $this->actingAsApiUserWithToken($owner, ['users.manage'])
            ->postJson('/api/v1/bulk/users/import', [
                'file' => $this->csv(['first@example.com']),
                'format' => 'csv',
                'default_role' => 'Foreign Role',
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('default_role');

        $this->actingAs($owner, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file' => $this->csv(['first@example.com'], 'Password123!'),
                'default_role' => 'Foreign Role',
            ])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('default_role');

        Queue::assertNothingPushed();
        $this->assertDatabaseMissing('users', ['email' => 'first@example.com']);
    }

    #[Test]
    public function it_requires_users_update_to_update_existing_users_on_import(): void
    {
        $caller = $this->createApiUser(['organization_id' => $this->organization->id]);
        $caller->givePermissionTo('users.create');
        $existing = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@example.com',
            'name' => 'Original Name',
        ]);

        $this->actingAsApiUserWithToken($caller, ['users.manage'])
            ->postJson('/api/v1/bulk/users/import', [
                'file' => $this->csv(['existing@example.com']),
                'format' => 'csv',
                'update_existing' => true,
                'default_role' => 'Unknown Role',
            ])
            ->assertForbidden();

        $this->actingAs($caller, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file' => $this->csv(['existing@example.com'], 'Password123!', 'Changed Name'),
                'update_existing' => true,
            ])
            ->assertForbidden();

        $this->actingAs($caller, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/bulk/import-users", [
                'file' => $this->csv(['existing@example.com'], 'Password123!', 'Changed Name'),
                'options' => ['update_existing' => true],
            ])
            ->assertForbidden();

        Queue::assertNothingPushed();
        $this->assertSame('Original Name', $existing->fresh()->name);

        $this->actingAsApiUserWithToken($caller, ['users.manage'])
            ->postJson('/api/v1/bulk/users/import', [
                'file' => $this->csv(['new@example.com']),
                'format' => 'csv',
            ])
            ->assertCreated();
    }

    #[Test]
    public function it_does_not_update_existing_users_in_the_importer_without_users_update(): void
    {
        $caller = $this->createApiUser(['organization_id' => $this->organization->id]);
        $caller->givePermissionTo('users.create');
        $existing = User::factory()->create([
            'organization_id' => $this->organization->id,
            'email' => 'existing@example.com',
            'name' => 'Original Name',
        ]);

        $results = app(BulkUserDataService::class)->importUsersExtended(
            $this->csv(['existing@example.com'], 'Password123!', 'Changed Name'),
            $this->organization,
            ['update_existing' => true, 'default_role' => 'User'],
            $caller
        );

        $this->assertSame([], $results['updated']);
        $this->assertSame('You cannot update existing users', $results['failed'][0]['reason']);
        $this->assertSame('Original Name', $existing->fresh()->name);
    }

    /**
     * @param  list<string>  $emails
     */
    private function importJob(User $creator, string $defaultRole, array $emails): BulkImportJob
    {
        return BulkImportJob::factory()->create([
            'type' => BulkImportJob::TYPE_IMPORT,
            'organization_id' => $this->organization->id,
            'created_by' => $creator->id,
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => ['format' => 'csv', 'default_role' => $defaultRole],
            'records' => array_map(fn (string $email): array => ['name' => 'Imported User', 'email' => $email], $emails),
        ]);
    }

    /**
     * @param  list<string>  $emails
     */
    private function csv(array $emails, string $password = 'Password123!', string $name = 'Imported User'): UploadedFile
    {
        $rows = array_map(fn (string $email): string => "{$email},{$name},{$password}", $emails);

        return UploadedFile::fake()->createWithContent('users.csv', "email,name,password\n".implode("\n", $rows));
    }
}
