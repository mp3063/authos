<?php

use App\Models\Role;
use Illuminate\Database\Migrations\Migration;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\PermissionRegistrar;

return new class extends Migration
{
    public function up(): void
    {
        Role::where('name', 'Organization Owner')
            ->whereNotNull('organization_id')
            ->each(function (Role $role): void {
                $permission = Permission::query()->firstOrCreate([
                    'name' => 'roles.assign',
                    'guard_name' => $role->guard_name,
                    'organization_id' => $role->organization_id,
                ]);

                $role->permissions()->syncWithoutDetaching([$permission->id]);
            });

        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    public function down(): void {}
};
