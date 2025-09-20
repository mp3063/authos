<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\SoftDeletes;

class CustomRole extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'name',
        'display_name',
        'description',
        'organization_id',
        'created_by',
        'permissions',
        'is_system',
        'is_active',
        'is_default',
    ];

    protected $casts = [
        'permissions' => 'array',
        'is_system' => 'boolean',
        'is_active' => 'boolean',
        'is_default' => 'boolean',
    ];

    /**
     * Get the organization that owns the custom role
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * Get the user who created this custom role
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * The users that have this custom role
     */
    public function users(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'user_custom_roles')
            ->withPivot(['granted_at', 'granted_by'])
            ->withTimestamps();
    }

    /**
     * Scope to get active custom roles
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope to get system-defined custom roles
     */
    public function scopeSystem($query)
    {
        return $query->where('is_system', true);
    }

    /**
     * Scope to get user-defined custom roles
     */
    public function scopeUserDefined($query)
    {
        return $query->where('is_system', false);
    }

    /**
     * Scope to get default roles
     */
    public function scopeDefault($query)
    {
        return $query->where('is_default', true);
    }

    /**
     * Scope to filter by organization
     */
    public function scopeForOrganization($query, $organizationId)
    {
        return $query->where('organization_id', $organizationId);
    }

    /**
     * Check if the role has a specific permission
     */
    public function hasPermission(string $permission): bool
    {
        $permissions = $this->permissions ?? [];

        return in_array($permission, $permissions);
    }

    /**
     * Add a permission to this role
     */
    public function grantPermission(string $permission): void
    {
        $permissions = $this->permissions ?? [];
        if (! in_array($permission, $permissions)) {
            $permissions[] = $permission;
            $this->update(['permissions' => $permissions]);
        }
    }

    /**
     * Remove a permission from this role
     */
    public function revokePermission(string $permission): void
    {
        $permissions = $this->permissions ?? [];
        $filteredPermissions = array_filter($permissions, fn ($p) => $p !== $permission);
        $this->update(['permissions' => array_values($filteredPermissions)]);
    }

    /**
     * Sync permissions for this role
     */
    public function syncPermissions(array $permissions): void
    {
        $this->update(['permissions' => $permissions]);
    }

    /**
     * Add a permission to this role (alias for grantPermission)
     */
    public function addPermission(string $permission): void
    {
        $this->grantPermission($permission);
    }

    /**
     * Remove a permission from this role (alias for revokePermission)
     */
    public function removePermission(string $permission): void
    {
        $this->revokePermission($permission);
    }

    /**
     * Add multiple permissions to this role
     */
    public function addPermissions(array $permissions): void
    {
        $currentPermissions = $this->permissions ?? [];
        $newPermissions = array_unique(array_merge($currentPermissions, $permissions));
        $this->update(['permissions' => $newPermissions]);
    }

    /**
     * Remove multiple permissions from this role
     */
    public function removePermissions(array $permissions): void
    {
        $currentPermissions = $this->permissions ?? [];
        $filteredPermissions = array_filter($currentPermissions, fn ($p) => ! in_array($p, $permissions));
        $this->update(['permissions' => array_values($filteredPermissions)]);
    }

    /**
     * Get the count of permissions for this role
     */
    public function getPermissionCount(): int
    {
        return count($this->permissions ?? []);
    }

    /**
     * Check if this is an admin role (has admin-level permissions)
     */
    public function isAdminRole(): bool
    {
        $adminPermissions = ['users.delete', 'organization.manage_settings', 'roles.create', 'roles.delete'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($adminPermissions, $currentPermissions));
    }

    /**
     * Check if the role can manage users
     */
    public function canManageUsers(): bool
    {
        $userManagementPermissions = ['users.create', 'users.update', 'users.delete', 'users.manage_roles'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($userManagementPermissions, $currentPermissions));
    }

    /**
     * Check if the role can manage applications
     */
    public function canManageApplications(): bool
    {
        $appManagementPermissions = ['applications.create', 'applications.update', 'applications.delete', 'applications.manage_users'];
        $currentPermissions = $this->permissions ?? [];

        return ! empty(array_intersect($appManagementPermissions, $currentPermissions));
    }

    /**
     * Assign this role to a user
     */
    public function assignToUser(User|int $user, ?User $grantedBy = null): void
    {
        $userId = $user instanceof User ? $user->id : $user;

        if (! $this->users()->where('user_id', $userId)->exists()) {
            $this->users()->attach($userId, [
                'granted_at' => now(),
                'granted_by' => $grantedBy?->id,
            ]);
        }
    }

    /**
     * Remove this role from a user
     */
    public function unassignFromUser(User|int $user): void
    {
        $userId = $user instanceof User ? $user->id : $user;
        $this->users()->detach($userId);
    }

    /**
     * Get the count of users assigned to this role
     */
    public function getUserCount(): int
    {
        return $this->users()->count();
    }

    /**
     * Clone this role with a new name
     */
    public function cloneRole(string $newName, ?string $newDisplayName = null): self
    {
        return self::create([
            'name' => $newName,
            'display_name' => $newDisplayName ?: $this->display_name,
            'description' => $this->description,
            'organization_id' => $this->organization_id,
            'permissions' => $this->permissions,
            'is_active' => true,
            'is_default' => false,
        ]);
    }

    /**
     * Get the display name or fallback to name
     */
    public function getDisplayNameAttribute($value): string
    {
        return $value ?: ucfirst(str_replace(['_', '-'], ' ', $this->name));
    }

    /**
     * Check if this is a system role that shouldn't be modified
     */
    public function isSystemRole(): bool
    {
        return $this->is_system;
    }

    /**
     * Check if role can be deleted
     */
    public function canBeDeleted(): bool
    {
        return ! $this->is_system && $this->users()->count() === 0;
    }

    /**
     * Get available permissions for the organization
     */
    public static function getAvailablePermissions(): array
    {
        return [
            // User Management
            'users.create',
            'users.read',
            'users.update',
            'users.delete',

            // Application Management
            'applications.create',
            'applications.read',
            'applications.update',
            'applications.delete',
            'applications.regenerate_credentials',

            // Organization Management
            'organizations.read',
            'organizations.update',

            // Role Management
            'roles.create',
            'roles.read',
            'roles.update',
            'roles.delete',
            'roles.assign',

            // Permission Management
            'permissions.create',
            'permissions.read',
            'permissions.update',
            'permissions.delete',

            // Authentication Logs
            'auth_logs.read',
            'auth_logs.export',
        ];
    }

    /**
     * Get permission categories for UI organization
     */
    public static function getPermissionCategories(): array
    {
        return [
            'User Management' => [
                'users.read', 'users.create', 'users.update', 'users.delete',
                'users.manage_roles', 'users.manage_sessions', 'users.view_activity',
            ],
            'Application Management' => [
                'applications.read', 'applications.create', 'applications.update', 'applications.delete',
                'applications.manage_users', 'applications.manage_tokens', 'applications.view_analytics',
            ],
            'Organization Management' => [
                'organization.read', 'organization.update', 'organization.manage_settings',
                'organization.manage_invitations', 'organization.view_analytics', 'organization.export_data',
            ],
            'Role Management' => [
                'roles.read', 'roles.create', 'roles.update', 'roles.delete', 'roles.assign',
            ],
            'Security & Audit' => [
                'security.view_logs', 'security.manage_mfa', 'security.manage_sessions', 'security.export_reports',
            ],
        ];
    }

    /**
     * Get permissions grouped by their prefix (category)
     */
    public function getGroupedPermissions(): array
    {
        $permissions = $this->permissions ?? [];
        $grouped = [];

        foreach ($permissions as $permission) {
            $parts = explode('.', $permission);
            $category = $parts[0] ?? 'other';

            if (! isset($grouped[$category])) {
                $grouped[$category] = [];
            }

            $grouped[$category][] = $permission;
        }

        return $grouped;
    }
}
