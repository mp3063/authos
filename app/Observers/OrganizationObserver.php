<?php

namespace App\Observers;

use App\Events\OrganizationUpdatedEvent;
use App\Models\Organization;
use App\Services\CacheInvalidationService;

class OrganizationObserver
{
    protected CacheInvalidationService $cacheInvalidationService;

    public function __construct(CacheInvalidationService $cacheInvalidationService)
    {
        $this->cacheInvalidationService = $cacheInvalidationService;
    }

    /**
     * Handle the Organization "created" event.
     */
    public function created(Organization $organization): void
    {
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/organizations');
    }

    /**
     * Handle the Organization "updated" event.
     */
    public function updated(Organization $organization): void
    {
        $this->cacheInvalidationService->invalidateOrganizationCaches($organization->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/organizations');

        OrganizationUpdatedEvent::dispatch($organization);
    }

    /**
     * Handle the Organization "deleted" event.
     */
    public function deleted(Organization $organization): void
    {
        $this->cacheInvalidationService->invalidateOrganizationCaches($organization->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/organizations');
    }

    /**
     * Handle the Organization "force deleted" event.
     */
    public function forceDeleted(Organization $organization): void
    {
        $this->cacheInvalidationService->invalidateOrganizationCaches($organization->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/organizations');
    }
}
