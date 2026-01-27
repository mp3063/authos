<?php

namespace App\Observers;

use App\Events\UserCreatedEvent;
use App\Events\UserDeletedEvent;
use App\Events\UserUpdatedEvent;
use App\Models\User;
use App\Services\CacheInvalidationService;

class UserObserver
{
    protected CacheInvalidationService $cacheInvalidationService;

    public function __construct(CacheInvalidationService $cacheInvalidationService)
    {
        $this->cacheInvalidationService = $cacheInvalidationService;
    }

    /**
     * Handle the User "created" event.
     */
    public function created(User $user): void
    {
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/users');

        if ($user->organization_id) {
            $this->cacheInvalidationService->invalidateOrganizationCaches($user->organization_id);
        }

        UserCreatedEvent::dispatch($user);
    }

    /**
     * Handle the User "updated" event.
     */
    public function updated(User $user): void
    {
        $this->cacheInvalidationService->invalidateUserCaches($user->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/users');

        // If organization changed, invalidate both organizations
        if ($user->wasChanged('organization_id')) {
            if ($user->getOriginal('organization_id')) {
                $this->cacheInvalidationService->invalidateOrganizationCaches(
                    $user->getOriginal('organization_id')
                );
            }
            if ($user->organization_id) {
                $this->cacheInvalidationService->invalidateOrganizationCaches($user->organization_id);
            }
        }

        // If permissions-related fields changed, invalidate permission caches
        if ($user->wasChanged(['mfa_methods', 'is_active'])) {
            $this->cacheInvalidationService->invalidateUserPermissionCaches($user->id);
        }

        UserUpdatedEvent::dispatch($user);
    }

    /**
     * Handle the User "deleted" event.
     */
    public function deleted(User $user): void
    {
        $this->cacheInvalidationService->invalidateUserCaches($user->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/users');

        if ($user->organization_id) {
            $this->cacheInvalidationService->invalidateOrganizationCaches($user->organization_id);
        }

        UserDeletedEvent::dispatch($user);
    }

    /**
     * Handle the User "force deleted" event.
     */
    public function forceDeleted(User $user): void
    {
        $this->cacheInvalidationService->invalidateUserCaches($user->id);
        $this->cacheInvalidationService->invalidateEndpointCaches('/api/users');

        if ($user->organization_id) {
            $this->cacheInvalidationService->invalidateOrganizationCaches($user->organization_id);
        }
    }
}
