<?php

namespace Tests\Integration\Organizations;

use App\Models\Application;
use App\Models\AuditExport;
use App\Models\Organization;
use App\Models\Role;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class OrganizationUsersExportTest extends IntegrationTestCase
{
    protected Organization $organization;

    protected User $owner;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');
        $this->organization = $this->createOrganization();
        $this->owner = $this->createApiOrganizationOwner(['organization_id' => $this->organization->id]);
    }

    private function exportedUsers(): array
    {
        $response = $this->actingAs($this->owner, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/export", [
                'format' => 'json',
                'data_type' => 'users',
            ]);

        $response->assertOk();
        $filePath = AuditExport::findOrFail($response->json('data.export_id'))->file_path;

        return json_decode(Storage::disk('local')->get($filePath), true);
    }

    #[Test]
    public function it_exports_only_members_of_the_organization(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $outsider = User::factory()->create(['organization_id' => $this->createOrganization()->id]);
        $outsider->applications()->attach($application->id);
        $member = User::factory()->create(['organization_id' => $this->organization->id]);

        $emails = array_column($this->exportedUsers(), 'email');

        $this->assertContains($member->email, $emails);
        $this->assertNotContains($outsider->email, $emails);
    }

    #[Test]
    public function it_never_exports_secret_user_columns(): void
    {
        User::factory()->create(['organization_id' => $this->organization->id]);

        $rows = $this->exportedUsers();

        $this->assertNotEmpty($rows);
        foreach ($rows as $row) {
            $this->assertSame(
                ['id', 'name', 'email', 'is_active', 'mfa_enabled', 'email_verified_at', 'created_at', 'last_login_at', 'roles', 'applications'],
                array_keys($row)
            );
            foreach (['mfa_backup_codes', 'mfa_secret', 'password', 'remember_token', 'metadata', 'provider_data', 'mfa_methods'] as $secret) {
                $this->assertArrayNotHasKey($secret, $row);
            }
        }
    }

    #[Test]
    public function it_exports_only_roles_of_the_organization(): void
    {
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $otherOrganization = $this->createOrganization();
        $globalRole = Role::create(['name' => 'Global Export Role', 'guard_name' => 'web', 'organization_id' => null]);
        $orgRole = Role::create(['name' => 'Org Export Role', 'guard_name' => 'web', 'organization_id' => $this->organization->id]);
        $foreignRole = Role::create(['name' => 'Foreign Export Role', 'guard_name' => 'web', 'organization_id' => $otherOrganization->id]);
        foreach ([[$globalRole, null], [$orgRole, $this->organization->id], [$foreignRole, $otherOrganization->id]] as [$role, $teamId]) {
            DB::table('model_has_roles')->insert([
                'role_id' => $role->id,
                'model_type' => $member->getMorphClass(),
                'model_id' => $member->id,
                'organization_id' => $teamId ?? $this->organization->id,
            ]);
        }

        $row = collect($this->exportedUsers())->firstWhere('email', $member->email);
        $roles = explode(', ', $row['roles']);

        $this->assertEqualsCanonicalizing(['Global Export Role', 'Org Export Role'], $roles);
    }
}
