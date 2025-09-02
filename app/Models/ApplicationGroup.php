<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use App\Traits\BelongsToOrganization;

class ApplicationGroup extends Model
{
    use HasFactory, BelongsToOrganization;

    protected $fillable = [
        'organization_id',
        'name',
        'description',
        'parent_application_id',
        'child_application_ids',
        'cascade_permissions',
        'settings',
    ];

    protected $casts = [
        'child_application_ids' => 'array',
        'cascade_permissions' => 'boolean',
        'settings' => 'array',
    ];

    /**
     * Get the parent application
     */
    public function parentApplication(): BelongsTo
    {
        return $this->belongsTo(Application::class, 'parent_application_id');
    }

    /**
     * Get all child applications
     */
    public function childApplications()
    {
        if (!$this->child_application_ids || empty($this->child_application_ids)) {
            return collect();
        }

        return Application::whereIn('id', $this->child_application_ids)
            ->where('organization_id', $this->organization_id)
            ->get();
    }

    /**
     * Add a child application to the group
     */
    public function addChildApplication(int $applicationId): bool
    {
        // Verify the application belongs to the same organization
        $application = Application::where('id', $applicationId)
            ->where('organization_id', $this->organization_id)
            ->first();

        if (!$application) {
            return false;
        }

        $childIds = $this->child_application_ids ?? [];
        
        if (!in_array($applicationId, $childIds)) {
            $childIds[] = $applicationId;
            $this->child_application_ids = $childIds;
            $this->save();
        }

        return true;
    }

    /**
     * Remove a child application from the group
     */
    public function removeChildApplication(int $applicationId): bool
    {
        $childIds = $this->child_application_ids ?? [];
        
        if (($key = array_search($applicationId, $childIds)) !== false) {
            unset($childIds[$key]);
            $this->child_application_ids = array_values($childIds);
            $this->save();
            return true;
        }

        return false;
    }

    /**
     * Check if an application is a child of this group
     */
    public function hasChildApplication(int $applicationId): bool
    {
        return in_array($applicationId, $this->child_application_ids ?? []);
    }

    /**
     * Get all application IDs (parent + children)
     */
    public function getAllApplicationIds(): array
    {
        $ids = [$this->parent_application_id];
        
        if ($this->child_application_ids) {
            $ids = array_merge($ids, $this->child_application_ids);
        }

        return array_unique($ids);
    }

    /**
     * Check if permissions should be cascaded
     */
    public function shouldCascadePermissions(): bool
    {
        return $this->cascade_permissions;
    }

    /**
     * Get users who have access to the parent application
     */
    public function getParentApplicationUsers()
    {
        return $this->parentApplication
            ->users()
            ->where('organization_id', $this->organization_id)
            ->get();
    }
}