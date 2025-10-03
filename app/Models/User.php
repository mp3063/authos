<?php

namespace App\Models;

use App\Traits\BelongsToOrganization;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Exceptions\RoleDoesNotExist;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable implements FilamentUser
{
    use BelongsToOrganization, HasApiTokens, HasFactory, HasRoles, Notifiable;

    /**
     * Transient properties that should not be saved to database
     */
    public $permissionsTeamId;

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
        'provider',
        'provider_id',
        'provider_token',
        'provider_refresh_token',
        'provider_data',
        // Virtual attributes for backward compatibility
        'mfa_secret',
        'mfa_backup_codes',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'two_factor_recovery_codes',
        'provider_token',
        'provider_refresh_token',
    ];

    /**
     * Attributes that should never be mass assigned or saved to database
     */
    // Note: Using $fillable instead of $guarded for explicit mass assignment protection
    // The permissionsTeamId is a transient property (public $permissionsTeamId) and won't be saved to DB

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'profile' => 'array',
            'two_factor_confirmed_at' => 'datetime',
            'mfa_methods' => 'array',
            'provider_data' => 'array',
            'two_factor_recovery_codes' => 'array',
            'mfa_backup_codes' => 'array',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function applications(): BelongsToMany
    {
        return $this->belongsToMany(Application::class, 'user_applications')
            ->withPivot(['permissions', 'metadata', 'last_login_at', 'login_count', 'granted_at', 'granted_by'])
            ->withTimestamps()
            ->using(UserApplication::class);
    }

    public function ssoSessions(): HasMany
    {
        return $this->hasMany(SSOSession::class);
    }

    public function customRoles(): BelongsToMany
    {
        return $this->belongsToMany(CustomRole::class, 'user_custom_roles')
            ->withPivot(['granted_at', 'granted_by'])
            ->withTimestamps();
    }

    public function authenticationLogs(): HasMany
    {
        return $this->hasMany(AuthenticationLog::class);
    }

    public function hasMfaEnabled(): bool
    {
        return ! empty($this->mfa_methods);
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
            ->where(function ($query) use ($orgId) {
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
            ->flatMap(fn ($role) => $role->permissions);

        // Get direct permissions
        $directPermissions = $this->permissions()
            ->where(function ($query) use ($orgId) {
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

        if (! $roleModel) {
            throw new RoleDoesNotExist("Role '$role' does not exist for organization $orgId");
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
        return $this->hasOrganizationRole('Organization Admin') ||
               $this->hasOrganizationRole('organization admin') ||
               $this->isOrganizationOwner();
    }

    /**
     * Check if user has global system roles
     */
    public function hasGlobalRole($role): bool
    {
        // Temporarily clear team context to check global roles
        $registrar = app(\Spatie\Permission\PermissionRegistrar::class);
        $registrarTeamId = $registrar->getPermissionsTeamId();

        // Clear team context
        $this->setPermissionsTeamId(null);
        $registrar->setPermissionsTeamId(null);

        try {
            $hasRole = $this->roles()->where('roles.name', $role)->whereNull('roles.organization_id')->exists();
        } finally {
            // Restore original team context
            $this->setPermissionsTeamId($registrarTeamId);
            $registrar->setPermissionsTeamId($registrarTeamId);
        }

        return $hasRole;
    }

    /**
     * Check if user is a super admin (global role)
     */
    public function isSuperAdmin(): bool
    {
        return $this->hasGlobalRole('Super Admin');
    }

    /**
     * Check if user is a social login user
     */
    public function isSocialUser(): bool
    {
        return ! empty($this->provider) && ! empty($this->provider_id);
    }

    /**
     * Check if user has a local password
     */
    public function hasPassword(): bool
    {
        return ! empty($this->password);
    }

    /**
     * Get the social provider display name
     */
    public function getProviderDisplayName(): string
    {
        if (! $this->provider) {
            return 'Local';
        }

        return match ($this->provider) {
            'google' => 'Google',
            'github' => 'GitHub',
            'facebook' => 'Facebook',
            'twitter' => 'Twitter',
            'linkedin' => 'LinkedIn',
            default => ucfirst($this->provider)
        };
    }

    /**
     * Find a user by provider and provider ID
     */
    public static function findBySocialProvider(string $provider, string $providerId): ?User
    {
        return static::where('provider', $provider)
            ->where('provider_id', $providerId)
            ->first();
    }

    /**
     * Create or update a social user
     */
    public static function createOrUpdateFromSocial(
        string $provider,
        string $providerId,
        array $userData,
        ?string $token = null,
        ?string $refreshToken = null
    ): User {
        $user = static::findBySocialProvider($provider, $providerId);

        $attributes = [
            'provider' => $provider,
            'provider_id' => $providerId,
            'name' => $userData['name'],
            'email' => $userData['email'],
            'provider_data' => $userData,
            'email_verified_at' => now(), // Social providers typically verify emails
        ];

        if ($token) {
            $attributes['provider_token'] = $token;
        }

        if ($refreshToken) {
            $attributes['provider_refresh_token'] = $refreshToken;
        }

        if ($user) {
            $user->update($attributes);

            return $user;
        }

        // Create new user
        return static::create($attributes);
    }

    /**
     * MFA Secret Accessor - Provides backward compatibility for tests
     */
    public function getMfaSecretAttribute(): ?string
    {
        return $this->two_factor_secret;
    }

    /**
     * MFA Secret Mutator - Provides backward compatibility for tests
     */
    public function setMfaSecretAttribute(?string $value): void
    {
        $this->attributes['two_factor_secret'] = $value;
    }

    /**
     * MFA Backup Codes Accessor - Provides backward compatibility for tests
     */
    public function getMfaBackupCodesAttribute(): array
    {
        if (empty($this->two_factor_recovery_codes)) {
            return [];
        }

        // Handle both string and array formats
        if (is_string($this->two_factor_recovery_codes)) {
            return json_decode($this->two_factor_recovery_codes, true) ?? [];
        }

        return $this->two_factor_recovery_codes ?? [];
    }

    /**
     * MFA Backup Codes Mutator - Provides backward compatibility for tests
     */
    public function setMfaBackupCodesAttribute(array $value): void
    {
        $this->attributes['two_factor_recovery_codes'] = json_encode($value);
    }

    /**
     * Check if user can access the Filament admin panel
     */
    public function canAccessPanel(Panel $panel): bool
    {
        // Allow access if user has admin permissions or is super admin
        return $this->isSuperAdmin() ||
               $this->isOrganizationAdmin() ||
               $this->isOrganizationOwner() ||
               $this->hasOrganizationPermission('admin.access');
    }
}
