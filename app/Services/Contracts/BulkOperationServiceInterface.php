<?php

namespace App\Services\Contracts;

use App\Models\Organization;
use Illuminate\Http\UploadedFile;

/**
 * Interface for bulk operation service
 */
interface BulkOperationServiceInterface extends BaseServiceInterface
{
    /**
     * Send bulk invitations
     */
    public function bulkInviteUsers(array $invitations, Organization $organization, string $roleId): array;

    /**
     * Assign roles to multiple users
     */
    public function bulkAssignRoles(array $userIds, string $roleId, Organization $organization): array;

    /**
     * Revoke roles from multiple users
     */
    public function bulkRevokeRoles(array $userIds, string $roleId, Organization $organization): array;

    /**
     * Revoke application access from multiple users
     */
    public function bulkRevokeAccess(array $userIds, int $applicationId, Organization $organization): array;

    /**
     * Export users to specified format
     */
    public function exportUsers(Organization $organization, string $format = 'csv', array $filters = []): string;

    /**
     * Import users from uploaded file
     */
    public function importUsers(UploadedFile $file, Organization $organization, string $defaultRole): array;

    /**
     * Perform bulk user operations (activate, deactivate, delete)
     */
    public function bulkUserOperations(array $userIds, string $operation, Organization $organization): array;
}
