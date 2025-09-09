<?php

namespace App\Services\Contracts;

use App\Models\Organization;

/**
 * Interface for organization analytics service operations
 */
interface OrganizationAnalyticsServiceInterface extends BaseServiceInterface
{
    /**
     * Get comprehensive analytics for an organization
     */
    public function getAnalytics(Organization $organization, string $period = '30d'): array;

    /**
     * Get user activity metrics
     */
    public function getUserActivityMetrics(Organization $organization, string $startDate, string $endDate): array;

    /**
     * Get application usage metrics
     */
    public function getApplicationUsageMetrics(Organization $organization, string $startDate, string $endDate): array;

    /**
     * Get authentication metrics
     */
    public function getAuthenticationMetrics(Organization $organization, string $startDate, string $endDate): array;

    /**
     * Get top applications by usage
     */
    public function getTopApplications(Organization $organization, int $limit = 10): array;

    /**
     * Get user growth metrics
     */
    public function getUserGrowthMetrics(Organization $organization, string $period = '30d'): array;

    /**
     * Get security metrics
     */
    public function getSecurityMetrics(Organization $organization, string $period = '30d'): array;
}
