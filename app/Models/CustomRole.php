<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;

/**
 * @method static \Illuminate\Database\Eloquent\Builder where($column, $operator = null, $value = null, $boolean = 'and')
 * @method static \Illuminate\Database\Eloquent\Builder whereIn($column, $values, $boolean = 'and', $not = false)
 * @method static static create(array $attributes = [])
 * @method static static findOrFail($id, $columns = ['*'])
 * @method static \Illuminate\Database\Eloquent\Builder with($relations)
 * @method static \Illuminate\Database\Eloquent\Builder withCount($relations)
 * @method static \Illuminate\Database\Eloquent\Builder forOrganization($organizationId)
 * @method static \Illuminate\Database\Eloquent\Builder active()
 * @method static \Illuminate\Database\Eloquent\Builder system()
 * @method static \Illuminate\Database\Eloquent\Builder userDefined()
 * @method static array getAvailablePermissions()
 * @method static array getPermissionCategories()
 * @method canBeDeleted()
 * @method isSystemRole()
 * @property-read \Illuminate\Database\Eloquent\Collection|User[] $users
 * @property-read User|null $creator
 * @property-read Organization $organization
 */
class CustomRole extends Model
{
    use HasFactory, SoftDeletes;

    protected $fillable = [
        'organization_id',
        'name',
        'display_name',
        'description',
        'permissions',
        'is_system',
        'created_by',
        'is_active',
    ];

    protected $casts = [
        'permissions' => 'array',
        'is_system' => 'boolean',
        'is_active' => 'boolean',
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
        if (!in_array($permission, $permissions)) {
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
        $filteredPermissions = array_filter($permissions, fn($p) => $p !== $permission);
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
        return !$this->is_system && $this->users()->count() === 0;
    }

    /**
     * Get available permissions for the organization
     */
    public static function getAvailablePermissions(): array
    {
        return [
            // User Management
            'users.read',
            'users.create',
            'users.update',
            'users.delete',
            'users.manage_roles',
            'users.manage_sessions',
            'users.view_activity',
            
            // Application Management
            'applications.read',
            'applications.create',
            'applications.update',
            'applications.delete',
            'applications.manage_users',
            'applications.manage_tokens',
            'applications.view_analytics',
            
            // Organization Management
            'organization.read',
            'organization.update',
            'organization.manage_settings',
            'organization.manage_invitations',
            'organization.view_analytics',
            'organization.export_data',
            
            // Role Management
            'roles.read',
            'roles.create',
            'roles.update',
            'roles.delete',
            'roles.assign',
            
            // Security & Audit
            'security.view_logs',
            'security.manage_mfa',
            'security.manage_sessions',
            'security.export_reports',
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
                'users.manage_roles', 'users.manage_sessions', 'users.view_activity'
            ],
            'Application Management' => [
                'applications.read', 'applications.create', 'applications.update', 'applications.delete',
                'applications.manage_users', 'applications.manage_tokens', 'applications.view_analytics'
            ],
            'Organization Management' => [
                'organization.read', 'organization.update', 'organization.manage_settings',
                'organization.manage_invitations', 'organization.view_analytics', 'organization.export_data'
            ],
            'Role Management' => [
                'roles.read', 'roles.create', 'roles.update', 'roles.delete', 'roles.assign'
            ],
            'Security & Audit' => [
                'security.view_logs', 'security.manage_mfa', 'security.manage_sessions', 'security.export_reports'
            ],
        ];
    }
}
