<?php

namespace App\Models;

use App\Models\Concerns\HasSocialLogin;
use App\Models\Concerns\InteractsWithOrganizationRoles;
use App\Traits\BelongsToOrganization;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\HasApiTokens;
use Override;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable implements FilamentUser
{
    use BelongsToOrganization;
    use HasApiTokens;
    use HasFactory;
    use HasRoles;
    use HasSocialLogin;
    use InteractsWithOrganizationRoles;
    use Notifiable;
    use SoftDeletes;

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
        'metadata',
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
            'password_changed_at' => 'datetime',
            'profile' => 'array',
            'metadata' => 'array',
            'two_factor_confirmed_at' => 'datetime',
            'mfa_methods' => 'array',
            'provider_data' => 'array',
            'two_factor_recovery_codes' => 'array',
            'mfa_backup_codes' => 'array',
        ];
    }

    protected $appends = [
        'mfa_enabled',
    ];

    /**
     * Override Spatie Permission to dynamically determine guard based on authentication context
     * This ensures roles work correctly whether authenticated via 'web' or 'api' guard
     */
    public function getDefaultGuardName(): string
    {
        // If authenticated via API guard, use 'api' for permission checks
        if (auth('api')->check() && auth('api')->id() === $this->id) {
            return 'api';
        }

        return 'web';
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
     * Get MFA enabled status as virtual attribute
     */
    protected function mfaEnabled(): Attribute
    {
        return Attribute::get(fn (): bool => $this->hasMfaEnabled());
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
     * Validate user for Laravel Passport password grant
     * This method is called by Passport to perform additional validation
     * during password grant authentication
     */
    public function validateForPassportPasswordGrant(string $password): bool
    {
        // Check if user account is active
        if (! $this->is_active) {
            return false;
        }

        // Verify password
        return Hash::check($password, $this->password);
    }

    /**
     * Check if user can access the Filament admin panel
     */
    #[Override]
    public function canAccessPanel(Panel $panel): bool
    {
        // Allow access if user has admin permissions or is super admin
        return $this->isSuperAdmin() ||
               $this->isOrganizationAdmin() ||
               $this->isOrganizationOwner() ||
               $this->hasOrganizationPermission('admin.access');
    }
}
