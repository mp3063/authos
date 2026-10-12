<?php

use App\Models\Role;
use Illuminate\Database\Migrations\Migration;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;

return new class extends Migration
{
    public function up(): void
    {
        Role::whereIn('name', ['Organization Owner', 'Organization Admin'])
            ->whereNotNull('organization_id')
            ->each(function (Role $role): void {
                $permission = Permission::query()->firstOrCreate([
                    'name' => 'admin.access',
                    'guard_name' => $role->guard_name,
                    'organization_id' => $role->organization_id,
                ]);

                $role->permissions()->syncWithoutDetaching([$permission->id]);
            });

        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    public function down(): void {}
};
