<?php

namespace Tests\Integration\Applications;

use App\Models\CustomRole;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class DropRegenerateCredentialsPermissionMigrationTest extends IntegrationTestCase
{
    #[Test]
    public function it_removes_the_permission_from_every_custom_role(): void
    {
        $withPermission = CustomRole::factory()->create([
            'permissions' => ['applications.read', 'applications.regenerate_credentials', 'users.read'],
        ]);
        $withoutPermission = CustomRole::factory()->create(['permissions' => ['users.read']]);

        (require database_path('migrations/2026_10_15_163025_drop_applications_regenerate_credentials_permission.php'))->up();

        $this->assertSame(['applications.read', 'users.read'], $withPermission->fresh()->permissions);
        $this->assertSame(['users.read'], $withoutPermission->fresh()->permissions);
    }
}
