<?php

namespace App\Models;

use App\Models\Concerns\HasComplianceRecords;
use App\Models\Concerns\HasEnterpriseIntegrations;
use App\Models\Concerns\ManagesOrganizationRoles;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Collection;

class Organization extends Model
{
    use HasComplianceRecords;
    use HasEnterpriseIntegrations;
    use HasFactory;
    use ManagesOrganizationRoles;
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

    protected function casts(): array
    {
        return [
            'settings' => 'array',
            'is_active' => 'boolean',
        ];
    }

    public function applications(): HasMany
    {
        return $this->hasMany(Application::class);
    }

    public function organizationUsers(): HasMany
    {
        return $this->hasMany(User::class);
    }

    public function invitations(): HasMany
    {
        return $this->hasMany(Invitation::class);
    }

    public function applicationGroups(): HasMany
    {
        return $this->hasMany(ApplicationGroup::class);
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
