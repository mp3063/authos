<?php

namespace Tests\Unit\Models;

use App\Models\CustomRole;
use App\Models\Organization;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class CustomRolePermissionCatalogTest extends TestCase
{
    #[Test]
    public function the_panel_categories_offer_exactly_the_permissions_the_api_accepts(): void
    {
        $categorized = array_merge(...array_values(CustomRole::getPermissionCategories()));

        $this->assertSame(count($categorized), count(array_unique($categorized)));
        $this->assertEqualsCanonicalizing(CustomRole::getAvailablePermissions(), $categorized);
    }

    #[Test]
    public function every_offered_permission_is_one_the_default_roles_use(): void
    {
        $matrix = array_unique(array_merge(...array_values((new Organization)->getDefaultRoles())));

        $this->assertSame([], array_values(array_diff(CustomRole::getAvailablePermissions(), $matrix)));
    }
}
