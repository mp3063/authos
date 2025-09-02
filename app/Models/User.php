<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;
use App\Traits\BelongsToOrganization;

/**
 * @method static \Illuminate\Database\Eloquent\Builder where($column, $operator = null, $value = null, $boolean = 'and')
 * @method static \Illuminate\Database\Eloquent\Builder whereIn($column, $values, $boolean = 'and', $not = false)
 * @method static \Illuminate\Database\Eloquent\Builder whereHas($relation, $callback = null, $operator = '>=', $count = 1)
 * @method static \Illuminate\Database\Eloquent\Builder whereBetween($column, $values, $boolean = 'and', $not = false)
 * @method static static create(array $attributes = [])
 * @method static static findOrFail($id, $columns = ['*'])
 * @method static static firstOrCreate(array $attributes = [], array $values = [])
 * @method static \Illuminate\Database\Eloquent\Builder with($relations)
 * @method static \Illuminate\Database\Eloquent\Builder withCount($relations)
 * @method assignRole(...$roles)
 * @method removeRole($role)
 * @method hasRole($role, $guardName = null)
 * @method hasOrganizationRole($role, $organizationId)
 * @method assignOrganizationRole($role, $organizationId) 
 * @method removeOrganizationRole($role, $organizationId)
 * @method isSuperAdmin()
 * @method hasMfaEnabled()
 * @property-read \Illuminate\Database\Eloquent\Collection|\Spatie\Permission\Models\Role[] $roles
 * @property-read \Illuminate\Database\Eloquent\Collection|Application[] $applications
 * @property-read \Illuminate\Database\Eloquent\Collection|CustomRole[] $customRoles
 * @property-read Organization|null $organization
 */
class User extends Authenticatable
{
    use HasFactory, Notifiable, HasApiTokens, HasRoles, BelongsToOrganization;

    protected $fillable = [
        'name',
        'email',
        'password',
        'avatar',
        'profile',
        'organization_id',
        'email_verified_at',
        'password_changed_at',
        'two_factor_secret',
        'two_factor_recovery_codes',
        'two_factor_confirmed_at',
        'mfa_methods',
        'is_active',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'profile' => 'array',
            'two_factor_confirmed_at' => 'datetime',
            'mfa_methods' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function applications(): BelongsToMany
    {
        return $this->belongsToMany(Application::class, 'user_applications')
            ->withPivot(['metadata', 'last_login_at', 'login_count'])
            ->withTimestamps();
    }

    public function ssoSessions(): HasMany
    {
        return $this->hasMany(\App\Models\SSOSession::class);
    }

    public function customRoles(): BelongsToMany
    {
        return $this->belongsToMany(CustomRole::class, 'user_custom_roles')
            ->withPivot(['granted_at', 'granted_by'])
            ->withTimestamps();
    }

    public function hasMfaEnabled(): bool
    {
        return !empty($this->mfa_methods);
    }

    public function getMfaMethods(): array
    {
        return $this->mfa_methods ?? [];
    }

    /**
     * Set the organization context for permission/role operations
     */
    public function setPermissionsTeamId($organizationId = null): void
    {
        $this->permissionsTeamId = $organizationId ?? $this->organization_id;
    }

    /**
     * Get roles for a specific organization
     */
    public function getOrganizationRoles($organizationId = null)
    {
        $orgId = $organizationId ?? $this->organization_id;
        
        return $this->roles()
            ->where(function($query) use ($orgId) {
                $query->where('roles.organization_id', $orgId)
                      ->orWhereNull('roles.organization_id'); // Include global roles
            })
            ->get();
    }

    /**
     * Get permissions for a specific organization
     */
    public function getOrganizationPermissions($organizationId = null)
    {
        $orgId = $organizationId ?? $this->organization_id;
        
        // Get permissions from roles
        $rolePermissions = $this->getOrganizationRoles($orgId)
            ->flatMap(fn($role) => $role->permissions);
        
        // Get direct permissions
        $directPermissions = $this->permissions()
            ->where(function($query) use ($orgId) {
                $query->where('permissions.organization_id', $orgId)
                      ->orWhereNull('permissions.organization_id'); // Include global permissions
            })
            ->get();
        
        return $rolePermissions->merge($directPermissions)->unique('id');
    }

    /**
     * Check if user has a role within their organization
     */
    public function hasOrganizationRole($role, $organizationId = null): bool
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);
        
        return $this->hasRole($role);
    }

    /**
     * Check if user has a permission within their organization
     */
    public function hasOrganizationPermission($permission, $organizationId = null): bool
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);
        
        return $this->hasPermissionTo($permission);
    }

    /**
     * Assign role to user within organization context
     */
    public function assignOrganizationRole($role, $organizationId = null): void
    {
        $orgId = $organizationId ?? $this->organization_id;
        
        // Find the role within the organization context
        $roleModel = \Spatie\Permission\Models\Role::where('name', $role)
            ->where('organization_id', $orgId)
            ->first();
            
        if (!$roleModel) {
            throw new \Spatie\Permission\Exceptions\RoleDoesNotExist("Role '{$role}' does not exist for organization {$orgId}");
        }
        
        // Attach the role with organization context
        $this->roles()->attach($roleModel->id, ['organization_id' => $orgId]);
    }

    /**
     * Assign a global role to user (bypasses organization context)
     */
    public function assignGlobalRole($role): void
    {
        // For global roles, we directly assign without organization context
        $this->roles()->attach(
            \Spatie\Permission\Models\Role::where('name', $role)
                ->whereNull('organization_id')
                ->first()
        );
    }

    /**
     * Remove role from user within organization context
     */
    public function removeOrganizationRole($role, $organizationId = null): void
    {
        $orgId = $organizationId ?? $this->organization_id;
        $this->setPermissionsTeamId($orgId);
        
        $this->removeRole($role);
    }

    /**
     * Check if user is owner of their organization
     */
    public function isOrganizationOwner(): bool
    {
        return $this->hasOrganizationRole('Organization Owner');
    }

    /**
     * Check if user is admin of their organization
     */
    public function isOrganizationAdmin(): bool
    {
        return $this->hasOrganizationRole('Organization Admin') || $this->isOrganizationOwner();
    }

    /**
     * Check if user has global system roles
     */
    public function hasGlobalRole($role): bool
    {
        return $this->roles()->where('roles.name', $role)->whereNull('roles.organization_id')->exists();
    }

    /**
     * Check if user is a super admin (global role)
     */
    public function isSuperAdmin(): bool
    {
        return $this->hasGlobalRole('Super Admin');
    }
}
