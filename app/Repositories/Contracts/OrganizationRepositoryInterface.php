<?php

namespace App\Repositories\Contracts;

use App\Models\Organization;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Collection;

/**
 * Organization repository interface
 */
interface OrganizationRepositoryInterface extends BaseRepositoryInterface
{
    /**
     * Find organization by slug
     */
    public function findBySlug(string $slug): ?Organization;

    /**
     * Get organizations with user counts
     */
    public function getWithUserCounts(array $filters = [], int $perPage = 15): LengthAwarePaginator;

    /**
     * Get organizations with application counts
     */
    public function getWithApplicationCounts(): Collection;

    /**
     * Get active organizations
     */
    public function getActiveOrganizations(): Collection;

    /**
     * Get organizations created in date range
     */
    public function getOrganizationsCreatedBetween(string $startDate, string $endDate): Collection;

    /**
     * Search organizations by name or domain
     */
    public function searchOrganizations(string $query, int $limit = 10): Collection;

    /**
     * Get organization analytics data
     */
    public function getAnalyticsData(Organization $organization, string $startDate, string $endDate): array;

    /**
     * Get organization settings
     */
    public function getSettings(Organization $organization): array;

    /**
     * Update organization settings
     */
    public function updateSettings(Organization $organization, array $settings): Organization;

    /**
     * Get organizations by domain
     */
    public function getByDomain(string $domain): Collection;

    /**
     * Check if slug is available
     */
    public function isSlugAvailable(string $slug, ?int $excludeId = null): bool;
}
