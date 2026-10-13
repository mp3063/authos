<?php

namespace Tests\Integration\Jobs;

use App\Exports\UsersExport;
use App\Jobs\ExportUsersJob;
use App\Models\BulkImportJob;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use App\Services\BulkImport\BulkImportService;
use App\Services\BulkUserDataService;
use App\Services\UserRoleService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Maatwebsite\Excel\Facades\Excel;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class BulkExportRoleScopeTest extends TestCase
{
    use RefreshDatabase;

    private Organization $organization;

    private Organization $foreignOrganization;

    private User $ownAuditor;

    private User $foreignAuditorHolder;

    private User $globalRoleHolder;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->organization = $this->createOrganization();
        $foreignOrganization = $this->foreignOrganization = $this->createOrganization();
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

    private function holderOfOwnAndForeignRoles(): User
    {
        $user = User::factory()->create(['organization_id' => $this->organization->id]);
        $roles = app(UserRoleService::class);
        $roles->assignRole($user, (string) $this->roleNamed('Auditor', $this->organization->id)->id);
        $roles->assignRole($user, (string) $this->roleNamed('Organization Admin', $this->foreignOrganization->id)->id);
        CustomRole::factory()->forOrganization($this->organization)->create(['name' => 'Own Custom'])->assignToUser($user);
        CustomRole::factory()->forOrganization($this->foreignOrganization)->create(['name' => 'Foreign Custom'])->assignToUser($user);

        return $user;
    }

    #[Test]
    public function the_csv_user_export_lists_only_roles_and_custom_roles_of_the_exported_organization(): void
    {
        $holder = $this->holderOfOwnAndForeignRoles();

        $result = app(BulkUserDataService::class)->exportUsersExtended($this->organization, ['format' => 'csv']);

        $rows = array_map('str_getcsv', array_filter(explode("\n", Storage::get('exports/'.$result['filename']))));
        $header = array_shift($rows);
        $row = array_combine($header, collect($rows)->firstWhere(0, (string) $holder->id));
        $this->assertSame('Auditor', $row['Roles']);
        $this->assertSame('Own Custom', $row['Custom Roles']);
    }

    #[Test]
    public function the_xlsx_user_export_lists_only_roles_and_custom_roles_of_the_exported_organization(): void
    {
        Excel::fake();
        $holder = $this->holderOfOwnAndForeignRoles();

        $result = app(BulkUserDataService::class)->exportUsersExtended($this->organization, ['format' => 'xlsx']);

        Excel::assertStored('exports/'.$result['filename'], function (UsersExport $export) use ($holder): bool {
            $row = array_combine($export->headings(), $export->map($export->collection()->firstWhere('id', $holder->id)));
            $this->assertSame('Auditor', $row['Roles']);
            $this->assertSame('Own Custom', $row['Custom Roles']);

            return true;
        });
    }

    #[Test]
    public function the_users_export_job_lists_only_roles_of_the_users_organization(): void
    {
        $holder = $this->holderOfOwnAndForeignRoles();
        $exportJob = BulkImportJob::factory()->create([
            'organization_id' => $this->organization->id,
            'type' => 'export',
            'file_format' => 'csv',
            'status' => BulkImportJob::STATUS_PENDING,
            'options' => [
                'organization_id' => $this->organization->id,
                'fields' => ['email', 'roles'],
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

        $this->assertSame('Auditor', collect($captured)->pluck('roles', 'email')->get($holder->email));
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
