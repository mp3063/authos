<?php

namespace App\Models;

use App\Models\Concerns\AssignableToUsers;
use App\Models\Concerns\HasPermissionList;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class CustomRole extends Model
{
    use AssignableToUsers;
    use HasFactory;
    use HasPermissionList;
    use SoftDeletes;

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

    protected function casts(): array
    {
        return [
            'permissions' => 'array',
            'is_system' => 'boolean',
            'is_active' => 'boolean',
            'is_default' => 'boolean',
        ];
    }

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
}
