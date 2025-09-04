<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Builder;
use App\Traits\BelongsToOrganization;

class ApplicationGroup extends Model
{
    use HasFactory, BelongsToOrganization;

    protected $fillable = [
        'name',
        'description',
        'organization_id',
        'parent_id',
        'is_active',
        'settings',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'settings' => 'array',
    ];

    /**
     * Get the parent group
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(ApplicationGroup::class, 'parent_id');
    }

    /**
     * Get child groups
     */
    public function children(): HasMany
    {
        return $this->hasMany(ApplicationGroup::class, 'parent_id');
    }

    /**
     * Get applications attached to this group
     */
    public function applications(): BelongsToMany
    {
        return $this->belongsToMany(Application::class, 'application_group_applications');
    }

    /**
     * Scope: Active groups only
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope: Groups for specific organization
     */
    public function scopeForOrganization(Builder $query, int $organizationId): Builder
    {
        return $query->where('organization_id', $organizationId);
    }

    /**
     * Scope: Root level groups (no parent)
     */
    public function scopeRootGroups(Builder $query): Builder
    {
        return $query->whereNull('parent_id');
    }

    /**
     * Check if this is a root group
     */
    public function isRoot(): bool
    {
        return is_null($this->parent_id);
    }

    /**
     * Check if group has children
     */
    public function hasChildren(): bool
    {
        return $this->children()->exists();
    }

    /**
     * Get the depth level of this group in the hierarchy
     */
    public function getDepth(): int
    {
        $depth = 0;
        $current = $this;
        
        while ($current->parent_id !== null) {
            $depth++;
            $current = $current->parent;
        }
        
        return $depth;
    }

    /**
     * Get all ancestors (parent hierarchy)
     */
    public function getAncestors()
    {
        $ancestors = collect();
        $current = $this->parent;
        
        while ($current) {
            $ancestors->push($current);
            $current = $current->parent;
        }
        
        return $ancestors;
    }

    /**
     * Get all descendants (child hierarchy)
     */
    public function getDescendants()
    {
        $descendants = collect();
        
        // Load children explicitly to avoid lazy loading issues in tests
        $children = $this->children()->get();
        
        foreach ($children as $child) {
            $descendants->push($child);
            $descendants = $descendants->merge($child->getDescendants());
        }
        
        return $descendants;
    }

    /**
     * Check if inheritance is enabled
     */
    public function hasInheritanceEnabled(): bool
    {
        return $this->settings['inheritance_enabled'] ?? false;
    }

    /**
     * Check if auto-assign is enabled
     */
    public function hasAutoAssignEnabled(): bool
    {
        return $this->settings['auto_assign_users'] ?? false;
    }

    /**
     * Get default permissions from settings
     */
    public function getDefaultPermissions(): array
    {
        return $this->settings['default_permissions'] ?? [];
    }

    /**
     * Add an application to this group
     */
    public function addApplication(int $applicationId): bool
    {
        // Verify the application belongs to the same organization
        $application = Application::where('id', $applicationId)
            ->where('organization_id', $this->organization_id)
            ->first();

        if (!$application) {
            return false;
        }

        // Attach if not already attached
        if (!$this->applications()->where('application_id', $applicationId)->exists()) {
            $this->applications()->attach($applicationId);
        }

        return true;
    }

    /**
     * Remove an application from this group
     */
    public function removeApplication(int $applicationId): bool
    {
        $this->applications()->detach($applicationId);
        return true;
    }

    /**
     * Move this group to a new parent
     */
    public function moveToParent(int $parentId): bool
    {
        // Verify the parent belongs to the same organization
        $parent = ApplicationGroup::where('id', $parentId)
            ->where('organization_id', $this->organization_id)
            ->first();

        if (!$parent) {
            return false;
        }

        $this->parent_id = $parentId;
        return $this->save();
    }

    /**
     * Get the full hierarchical path
     */
    public function getFullPath(string $separator = ' > '): string
    {
        $path = [$this->name];
        $current = $this->parent;
        
        while ($current) {
            $path[] = $current->name;
            $current = $current->parent;
        }
        
        return implode($separator, array_reverse($path));
    }

    /**
     * Get direct application count
     */
    public function getApplicationCount(): int
    {
        return $this->applications()->count();
    }

    /**
     * Get total application count including descendants
     */
    public function getTotalApplicationCount(): int
    {
        $count = $this->getApplicationCount();
        
        foreach ($this->children as $child) {
            $count += $child->getTotalApplicationCount();
        }
        
        return $count;
    }
}