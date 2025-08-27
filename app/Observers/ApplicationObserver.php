<?php

namespace App\Observers;

use App\Models\Application;
use App\Services\CacheInvalidationService;

class ApplicationObserver
{
    protected CacheInvalidationService $cacheInvalidationService;

    public function __construct(CacheInvalidationService $cacheInvalidationService)
    {
        $this->cacheInvalidationService = $cacheInvalidationService;
    }

    /**
     * Handle the Application "created" event.
     */
    public function created(Application $application): void
    {
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/applications');
        
        if ($application->organization_id) {
            $this->cacheInvalidationService->invalidateOrganizationCaches($application->organization_id);
        }
    }

    /**
     * Handle the Application "updated" event.
     */
    public function updated(Application $application): void
    {
        $this->cacheInvalidationService->invalidateApplicationCaches(
            $application->id,
            $application->organization_id
        );
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/applications');
        
        // If organization changed, invalidate both organizations
        if ($application->wasChanged('organization_id')) {
            if ($application->getOriginal('organization_id')) {
                $this->cacheInvalidationService->invalidateOrganizationCaches(
                    $application->getOriginal('organization_id')
                );
            }
        }
    }

    /**
     * Handle the Application "deleted" event.
     */
    public function deleted(Application $application): void
    {
        $this->cacheInvalidationService->invalidateApplicationCaches(
            $application->id,
            $application->organization_id
        );
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/applications');
        
        if ($application->organization_id) {
            $this->cacheInvalidationService->invalidateOrganizationCaches($application->organization_id);
        }
    }
}