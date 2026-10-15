<?php

namespace Tests\Unit;

use App\Models\CustomRole;
use App\Models\Organization;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class NoUnusedPermissionsTest extends TestCase
{
    #[Test]
    public function it_defines_no_applications_regenerate_credentials_permission(): void
    {
        $permission = 'applications.regenerate_credentials';

        $defaultRolePermissions = collect((new Organization)->getDefaultRoles())->flatten()->all();

        $this->assertNotContains($permission, $defaultRolePermissions);
        $this->assertNotContains($permission, CustomRole::getAvailablePermissions());
    }
}
