<?php

namespace App\Services\Contracts;

use App\Models\Organization;
use App\Models\User;

/**
 * Interface for bulk operation service
 */
interface BulkOperationServiceInterface extends BaseServiceInterface
{
    /**
     * Send bulk invitations
     */
    public function bulkInviteUsers(array $invitations, Organization $organization, string $roleId, User $caller): array;

    /**
     * Revoke application access from multiple users
     */
    public function bulkRevokeAccess(array $userIds, int $applicationId, Organization $organization, User $caller): array;

    /**
     * Perform bulk user operations (activate, deactivate, delete)
     */
    public function bulkUserOperations(array $userIds, string $operation, Organization $organization): array;
}
