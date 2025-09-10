<?php

namespace App\Repositories\Contracts;

use App\Models\Application;
use App\Models\Organization;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

/**
 * Application repository interface
 */
interface ApplicationRepositoryInterface extends BaseRepositoryInterface
{
    /**
     * Find application by client ID
     */
    public function findByClientId(string $clientId): ?Application;

    /**
     * Get applications for organization with pagination
     */
    public function getOrganizationApplications(Organization $organization, array $filters = [], int $perPage = 15): LengthAwarePaginator;

    /**
     * Get applications with user counts
     */
    public function getWithUserCounts(Organization $organization): Collection;

    /**
     * Get active applications for organization
     */
    public function getActiveApplications(Organization $organization): Collection;

    /**
     * Find application with relationships
     */
    public function findWithRelationships(int $id): ?Application;

    /**
     * Get applications with SSO configurations
     */
    public function getWithSSOConfigurations(Organization $organization): Collection;

    /**
     * Search applications by name
     */
    public function searchApplications(string $query, Organization $organization, int $limit = 10): Collection;

    /**
     * Get application analytics
     */
    public function getApplicationAnalytics(Application $application, string $startDate, string $endDate): array;

    /**
     * Get applications created in date range
     */
    public function getApplicationsCreatedBetween(string $startDate, string $endDate, Organization $organization): Collection;

    /**
     * Check if client ID is available
     */
    public function isClientIdAvailable(string $clientId, ?int $excludeId = null): bool;

    /**
     * Get applications by grant type
     */
    public function getByGrantType(string $grantType, Organization $organization): Collection;

    /**
     * Get application usage statistics
     */
    public function getUsageStatistics(Application $application): array;
}
