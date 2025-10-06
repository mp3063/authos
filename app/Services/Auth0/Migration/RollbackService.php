<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

use App\Models\Application;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\DB;

class RollbackService
{
    /**
     * Rollback migration
     *
     * @throws \Throwable
     */
    public function rollback(MigrationResult $result): void
    {
        if ($result->dryRun) {
            throw new \RuntimeException('Cannot rollback a dry run migration');
        }

        DB::transaction(function () use ($result) {
            // Rollback in reverse order of creation

            // 4. Delete users
            $this->rollbackUsers($result);

            // 3. Delete applications
            $this->rollbackApplications($result);

            // 2. Delete roles
            $this->rollbackRoles($result);

            // 1. Delete organizations
            $this->rollbackOrganizations($result);
        });
    }

    /**
     * Rollback users
     */
    private function rollbackUsers(MigrationResult $result): void
    {
        $userIds = $result->users->getSuccessfulIds();

        if (empty($userIds)) {
            return;
        }

        // Delete users imported from Auth0
        User::whereIn('id', $userIds)
            ->whereJsonContains('metadata->imported_from_auth0', true)
            ->delete();
    }

    /**
     * Rollback applications
     */
    private function rollbackApplications(MigrationResult $result): void
    {
        $applicationIds = $result->applications->getSuccessfulIds();

        if (empty($applicationIds)) {
            return;
        }

        // Delete applications imported from Auth0
        Application::whereIn('id', $applicationIds)
            ->whereJsonContains('metadata->imported_from_auth0', true)
            ->delete();
    }

    /**
     * Rollback roles
     */
    private function rollbackRoles(MigrationResult $result): void
    {
        $roleIds = $result->roles->getSuccessfulIds();

        if (empty($roleIds)) {
            return;
        }

        // Delete roles imported from Auth0
        CustomRole::whereIn('id', $roleIds)
            ->whereJsonContains('metadata->imported_from_auth0', true)
            ->delete();
    }

    /**
     * Rollback organizations
     */
    private function rollbackOrganizations(MigrationResult $result): void
    {
        $organizationIds = $result->organizations->getSuccessfulIds();

        if (empty($organizationIds)) {
            return;
        }

        // Delete organizations imported from Auth0
        Organization::whereIn('id', $organizationIds)
            ->whereJsonContains('metadata->imported_from_auth0', true)
            ->delete();
    }

    /**
     * Partial rollback - only rollback specific category
     */
    public function partialRollback(MigrationResult $result, string $category): void
    {
        if ($result->dryRun) {
            throw new \RuntimeException('Cannot rollback a dry run migration');
        }

        DB::transaction(function () use ($result, $category) {
            match ($category) {
                'users' => $this->rollbackUsers($result),
                'applications' => $this->rollbackApplications($result),
                'roles' => $this->rollbackRoles($result),
                'organizations' => $this->rollbackOrganizations($result),
                default => throw new \InvalidArgumentException("Invalid category: {$category}"),
            };
        });
    }
}
