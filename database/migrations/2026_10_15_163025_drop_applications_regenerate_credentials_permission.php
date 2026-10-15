<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\PermissionRegistrar;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $permissionIds = DB::table('permissions')
            ->where('name', 'applications.regenerate_credentials')
            ->pluck('id');

        DB::table('role_has_permissions')->whereIn('permission_id', $permissionIds)->delete();
        DB::table('model_has_permissions')->whereIn('permission_id', $permissionIds)->delete();
        DB::table('permissions')->whereIn('id', $permissionIds)->delete();

        DB::table('custom_roles')->select(['id', 'permissions'])->orderBy('id')->chunkById(100, function ($roles) {
            foreach ($roles as $role) {
                $permissions = json_decode($role->permissions ?? '[]', true) ?: [];
                $kept = array_values(array_diff($permissions, ['applications.regenerate_credentials']));

                if ($kept !== $permissions) {
                    DB::table('custom_roles')->where('id', $role->id)->update(['permissions' => json_encode($kept)]);
                }
            }
        });

        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void {}
};
