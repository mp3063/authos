<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Collection;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class Organization extends Model
{
    use HasFactory;
    use SoftDeletes;

    protected $fillable = [
        'name',
        'slug',
        'description',
        'website',
        'settings',
        'is_active',
        'logo',
    ];

    protected $casts = [
        'settings' => 'array',
        'is_active' => 'boolean',
    ];

    public function applications(): HasMany
    {
        return $this->hasMany(Application::class);
    }

    public function roles(): HasMany
    {
        return $this->hasMany(Role::class);
    }

    public function permissions(): HasMany
    {
        return $this->hasMany(Permission::class);
    }

    public function organizationUsers(): HasMany
    {
        return $this->hasMany(User::class);
    }

    public function invitations(): HasMany
    {
        return $this->hasMany(Invitation::class);
    }

    public function customRoles(): HasMany
    {
        return $this->hasMany(CustomRole::class);
    }

    public function branding(): HasOne
    {
        return $this->hasOne(OrganizationBranding::class);
    }

    public function customDomains(): HasMany
    {
        return $this->hasMany(CustomDomain::class);
    }

    public function ldapConfigurations(): HasMany
    {
        return $this->hasMany(LdapConfiguration::class);
    }

    public function auditExports(): HasMany
    {
        return $this->hasMany(AuditExport::class);
    }

    public function webhooks(): HasMany
    {
        return $this->hasMany(Webhook::class);
    }

    /**
     * Get all users who have access to any application in this organization
     */
    public function users(): Builder
    {
        return User::whereHas('applications', function ($query) {
            $query->where('organization_id', $this->id);
        })->distinct();
    }

    /**
     * Get users with their application access details for this organization
     */
    public function usersWithApplications(): Collection
    {
        return $this->applications()
            ->with(['users' => function ($query) {
                $query->withPivot(['granted_at', 'last_login_at', 'login_count']);
            }])
            ->get()
            ->pluck('users')
            ->flatten()
            ->unique('id');
    }

    /**
     * Create a new role for this organization
     */
    public function createRole(string $name, array $permissions = [], string $guard = 'web'): Role
    {
        $role = Role::firstOrCreate([
            'name' => $name,
            'guard_name' => $guard,
            'organization_id' => $this->id,
        ]);

        if (! empty($permissions)) {
            $role->givePermissionTo($permissions);
        }

        return $role;
    }

    /**
     * Create a new permission for this organization
     */
    public function createPermission(string $name, string $guardName = 'web'): Permission
    {
        return Permission::create([
            'name' => $name,
            'guard_name' => $guardName,
            'organization_id' => $this->id,
        ]);
    }

    /**
     * Get default roles that should be created for this organization
     */
    public function getDefaultRoles(): array
    {
        return [
            'Organization Owner' => [
                'users.create', 'users.read', 'users.update', 'users.delete',
                'applications.create', 'applications.read', 'applications.update', 'applications.delete',
                'applications.regenerate_credentials',
                'organizations.read', 'organizations.update',
                'roles.create', 'roles.read', 'roles.update', 'roles.delete',
                'permissions.create', 'permissions.read', 'permissions.update', 'permissions.delete',
                'auth_logs.read', 'auth_logs.export',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'Organization Admin' => [
                'users.create', 'users.read', 'users.update',
                'applications.create', 'applications.read', 'applications.update',
                'organizations.read',
                'roles.read', 'roles.assign',
                'permissions.read',
                'auth_logs.read',
                'webhooks.create', 'webhooks.read', 'webhooks.update', 'webhooks.delete',
            ],
            'Organization Member' => [
                'users.read',
                'applications.read',
                'organizations.read',
            ],
            'Application Manager' => [
                'applications.create', 'applications.read', 'applications.update',
                'applications.regenerate_credentials',
                'users.read',
            ],
            'User Manager' => [
                'users.create', 'users.read', 'users.update',
                'roles.read', 'roles.assign',
                'applications.read',
            ],
            'Auditor' => [
                'users.read',
                'applications.read',
                'organizations.read',
                'auth_logs.read', 'auth_logs.export',
            ],
            'User' => [
                'users.read',
                'applications.read',
                'organizations.read',
            ],
        ];
    }

    /**
     * Setup default roles and permissions for this organization
     */
    public function setupDefaultRoles(): void
    {
        $defaultRoles = $this->getDefaultRoles();

        // First, ensure all required permissions exist for this organization
        $allRequiredPermissions = collect($defaultRoles)->flatten()->unique();

        foreach ($allRequiredPermissions as $permissionName) {
            // Create permission for web guard
            Permission::firstOrCreate([
                'name' => $permissionName,
                'guard_name' => 'web',
                'organization_id' => $this->id,
            ]);

            // Also create permission for api guard for API authentication
            Permission::firstOrCreate([
                'name' => $permissionName,
                'guard_name' => 'api',
                'organization_id' => $this->id,
            ]);
        }

        // Then create roles and assign permissions for both web and api guards
        foreach ($defaultRoles as $roleName => $permissions) {
            // Create role for web guard
            $existingWebRole = Role::where('name', $roleName)
                ->where('guard_name', 'web')
                ->where('organization_id', $this->id)
                ->first();

            if (! $existingWebRole) {
                $this->createRole($roleName, $permissions, 'web');
            }

            // Create role for api guard
            $existingApiRole = Role::where('name', $roleName)
                ->where('guard_name', 'api')
                ->where('organization_id', $this->id)
                ->first();

            if (! $existingApiRole) {
                $this->createRole($roleName, $permissions, 'api');
            }
        }
    }

    /**
     * Get all permissions available to this organization (org-specific + global)
     */
    public function getAvailablePermissions(): Collection
    {
        return Permission::where(function ($query) {
            $query->where('organization_id', $this->id)
                ->orWhereNull('organization_id');
        })->get();
    }

    /**
     * Get all roles available to this organization (org-specific + global)
     */
    public function getAvailableRoles(): Collection
    {
        return Role::where(function ($query) {
            $query->where('organization_id', $this->id)
                ->orWhereNull('organization_id');
        })->get();
    }

    /**
     * Check if user has any role in this organization
     */
    public function hasUser(User $user): bool
    {
        return $user->organization_id === $this->id ||
               $user->roles()->where('organization_id', $this->id)->exists();
    }

    /**
     * Get statistics for this organization
     */
    public function getStatistics(): array
    {
        return [
            'users_count' => $this->organizationUsers()->count(),
            'applications_count' => $this->applications()->count(),
            'roles_count' => $this->roles()->count(),
            'permissions_count' => $this->permissions()->count(),
        ];
    }
}
