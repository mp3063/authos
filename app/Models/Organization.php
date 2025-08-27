<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Organization extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'settings',
        'is_active',
    ];

    protected $casts = [
        'settings' => 'array',
        'is_active' => 'boolean',
    ];

    public function applications(): HasMany
    {
        return $this->hasMany(Application::class);
    }

    /**
     * Get all users who have access to any application in this organization
     */
    public function users()
    {
        return User::whereHas('applications', function ($query) {
            $query->where('organization_id', $this->id);
        })->distinct();
    }

    /**
     * Get users with their application access details for this organization
     */
    public function usersWithApplications()
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
}
