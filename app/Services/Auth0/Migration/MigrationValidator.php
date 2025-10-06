<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;

class MigrationValidator
{
    /**
     * Validate migration result
     */
    public function validate(MigrationResult $result): ValidationReport
    {
        $report = new ValidationReport;

        // Validate organizations
        $this->validateOrganizations($result, $report);

        // Validate users
        $this->validateUsers($result, $report);

        // Validate applications
        $this->validateApplications($result, $report);

        return $report;
    }

    /**
     * Validate organizations
     */
    private function validateOrganizations(MigrationResult $result, ValidationReport $report): void
    {
        foreach ($result->organizations->getSuccessfulIds() as $organizationId) {
            try {
                $organization = Organization::findOrFail($organizationId);

                // Check required fields
                if (empty($organization->name)) {
                    $report->addError('organizations', $organizationId, 'Organization name is empty');
                }
            } catch (\Throwable $e) {
                $report->addError('organizations', $organizationId, "Organization not found: {$e->getMessage()}");
            }
        }
    }

    /**
     * Validate users
     */
    private function validateUsers(MigrationResult $result, ValidationReport $report): void
    {
        foreach ($result->users->getSuccessfulIds() as $userId) {
            try {
                $user = User::findOrFail($userId);

                // Check required fields
                if (empty($user->email)) {
                    $report->addError('users', $userId, 'User email is empty');
                }

                // Check email format
                if (! filter_var($user->email, FILTER_VALIDATE_EMAIL)) {
                    $report->addError('users', $userId, 'Invalid email format');
                }

                // Check for duplicate emails
                $duplicateCount = User::where('email', $user->email)->count();
                if ($duplicateCount > 1) {
                    $report->addError('users', $userId, 'Duplicate email found');
                }

                // Check organization relationship
                if ($user->organization_id && ! Organization::find($user->organization_id)) {
                    $report->addError('users', $userId, 'Organization relationship is broken');
                }
            } catch (\Throwable $e) {
                $report->addError('users', $userId, "User not found: {$e->getMessage()}");
            }
        }
    }

    /**
     * Validate applications
     */
    private function validateApplications(MigrationResult $result, ValidationReport $report): void
    {
        foreach ($result->applications->getSuccessfulIds() as $applicationId) {
            try {
                $application = Application::findOrFail($applicationId);

                // Check required fields
                if (empty($application->name)) {
                    $report->addError('applications', $applicationId, 'Application name is empty');
                }

                // Check organization relationship
                if ($application->organization_id && ! Organization::find($application->organization_id)) {
                    $report->addError('applications', $applicationId, 'Organization relationship is broken');
                }

                // Validate redirect URIs
                if (! empty($application->redirect_uris)) {
                    foreach ($application->redirect_uris as $uri) {
                        if (! filter_var($uri, FILTER_VALIDATE_URL)) {
                            $report->addError('applications', $applicationId, "Invalid redirect URI: {$uri}");
                        }
                    }
                }
            } catch (\Throwable $e) {
                $report->addError('applications', $applicationId, "Application not found: {$e->getMessage()}");
            }
        }
    }
}
