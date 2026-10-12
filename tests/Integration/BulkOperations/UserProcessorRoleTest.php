<?php

namespace Tests\Integration\BulkOperations;

use App\Models\User;
use App\Services\BulkImport\DTOs\ImportOptions;
use App\Services\BulkImport\UserProcessor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\PermissionRegistrar;
use Tests\TestCase;

class UserProcessorRoleTest extends TestCase
{
    use RefreshDatabase;

    #[Test]
    public function it_assigns_the_imported_role_of_the_target_organization_without_an_ambient_team(): void
    {
        $organization = $this->createOrganization();
        $this->createOrganization();
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
        $processor = new UserProcessor(ImportOptions::fromArray(['format' => 'csv', 'organization_id' => $organization->id]));

        $result = $processor->process(['email' => 'new@example.com', 'name' => 'New Person', 'role' => 'Organization Member']);

        $this->assertTrue($result['success'], $result['error'] ?? '');
        $assigned = $this->assignedRolesNamed(User::findOrFail($result['user_id']), 'Organization Member');
        $this->assertCount(1, $assigned);
        $this->assertSame($organization->id, $assigned->first()->organization_id);
        $this->assertSame('api', $assigned->first()->guard_name);
    }
}
