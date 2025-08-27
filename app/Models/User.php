<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasFactory, Notifiable, HasApiTokens, HasRoles;

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

    public function hasMfaEnabled(): bool
    {
        return !empty($this->mfa_methods);
    }

    public function getMfaMethods(): array
    {
        return $this->mfa_methods ?? [];
    }
}
