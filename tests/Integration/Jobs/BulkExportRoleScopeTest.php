<?php

namespace Tests\Integration\Jobs;

use App\Jobs\ExportUsersJob;
use App\Jobs\ProcessBulkExportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use App\Services\UserRoleService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class BulkExportRoleScopeTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private User $ownAuditor;

    private User $foreignAuditorHolder;

    private User $globalRoleHolder;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->organization = $this->createOrganization();
        $foreignOrganization = $this->createOrganization();
        $roles = app(UserRoleService::class);

        $this->ownAuditor = User::factory()->create(['organization_id' => $this->organization->id]);
        $roles->assignRole($this->ownAuditor, (string) $this->roleNamed('Auditor', $this->organization->id)->id);

        $this->foreignAuditorHolder = User::factory()->create(['organization_id' => $this->organization->id]);
        $roles->assignRole($this->foreignAuditorHolder, (string) $this->roleNamed('Auditor', $foreignOrganization->id)->id);

        $this->globalRoleHolder = User::factory()->create(['organization_id' => $this->organization->id]);
        $globalRole = Role::create(['name' => 'Platform Support', 'guard_name' => 'api', 'organization_id' => null]);
        $roles->assignRole($this->globalRoleHolder, (string) $globalRole->id);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob(storage_path('app/exports/users_export_*')) ?: []);

        parent::tearDown();
    }

    private function roleNamed(string $name, int $organizationId): Role
    {
        return Role::where('name', $name)->where('guard_name', 'api')->where('organization_id', $organizationId)->firstOrFail();
    }

    #[Test]
    public function the_bulk_export_job_role_filter_only_matches_organization_and_global_roles(): void
    {
        $exportJob = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'export',
            'export_type' => 'users',
            'format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
            'filters' => ['roles' => ['Auditor', 'Platform Support']],
        ]);

        (new ProcessBulkExportJob($exportJob))->handle();

        $this->assertSame(2, $exportJob->refresh()->total_records);
    }

    #[Test]
    public function the_users_export_job_filters_and_labels_roles_without_an_ambient_team(): void
    {
        $exportJob = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'export',
            'file_format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => [
                'organization_id' => $this->organization->id,
                'fields' => ['email', 'roles'],
                'roles' => ['Auditor', 'Platform Support'],
            ],
        ]);
        $captured = [];
        $parser = Mockery::mock();
        $parser->shouldReceive('generate')->andReturnUsing(function (array $records, string $filename) use (&$captured) {
            $captured = $records;
            $path = storage_path('app/exports/'.$filename);
            @mkdir(dirname($path), 0755, true);
            file_put_contents($path, 'x');

            return 'exports/'.$filename;
        });
        $service = Mockery::mock(BulkImportService::class);
        $service->shouldReceive('getParser')->andReturn($parser);

        (new ExportUsersJob($exportJob))->handle($service);

        $rolesByEmail = collect($captured)->pluck('roles', 'email')->all();
        $this->assertEqualsCanonicalizing(
            [$this->ownAuditor->email, $this->globalRoleHolder->email],
            array_keys($rolesByEmail)
        );
        $this->assertSame('Auditor', $rolesByEmail[$this->ownAuditor->email]);
        $this->assertSame('Platform Support', $rolesByEmail[$this->globalRoleHolder->email]);
    }
}
