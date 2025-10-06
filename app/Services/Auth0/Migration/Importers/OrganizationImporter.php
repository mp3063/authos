<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration\Importers;

use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\Migration\ImportResult;
use Illuminate\Support\Facades\DB;

class OrganizationImporter
{
    /**
     * Import organizations from Auth0
     *
     * @param  array<int, Auth0OrganizationDTO>  $auth0Organizations
     */
    public function import(array $auth0Organizations, bool $dryRun = false): ImportResult
    {
        $result = new ImportResult;

        foreach ($auth0Organizations as $auth0Org) {
            try {
                // Check if organization already exists
                if (Organization::where('name', $auth0Org->name)->exists()) {
                    $result->addSkipped("Organization with name {$auth0Org->name} already exists");

                    continue;
                }

                if ($dryRun) {
                    $result->addSuccess($auth0Org, null);

                    continue;
                }

                // Import organization
                $organization = $this->importOrganization($auth0Org);

                $result->addSuccess($auth0Org, $organization->id);
            } catch (\Throwable $e) {
                $result->addFailure($auth0Org, $e);
            }
        }

        return $result;
    }

    /**
     * Import a single organization
     */
    private function importOrganization(Auth0OrganizationDTO $auth0Org): Organization
    {
        return DB::transaction(function () use ($auth0Org) {
            // Create organization
            $organization = Organization::create([
                'name' => $auth0Org->name,
                'display_name' => $auth0Org->displayName,
                'is_active' => true,
            ]);

            // Import metadata
            $this->importMetadata($organization, $auth0Org);

            // Import branding if available
            if ($auth0Org->hasCustomBranding()) {
                $this->importBranding($organization, $auth0Org);
            }

            return $organization;
        });
    }

    /**
     * Import organization metadata
     */
    private function importMetadata(Organization $organization, Auth0OrganizationDTO $auth0Org): void
    {
        $organization->update([
            'metadata' => [
                'auth0_organization_id' => $auth0Org->id,
                'auth0_metadata' => $auth0Org->metadata,
                'imported_from_auth0' => true,
                'imported_at' => now()->toIso8601String(),
            ],
        ]);
    }

    /**
     * Import organization branding
     */
    private function importBranding(Organization $organization, Auth0OrganizationDTO $auth0Org): void
    {
        try {
            // Check if branding already exists
            $branding = OrganizationBranding::firstOrNew([
                'organization_id' => $organization->id,
            ]);

            // Import branding data
            $branding->fill([
                'logo_url' => $auth0Org->getLogoUrl(),
                'primary_color' => $auth0Org->getPrimaryColor(),
                'background_color' => $auth0Org->getPageBackgroundColor(),
            ]);

            $branding->save();
        } catch (\Throwable $e) {
            // Log error but don't fail the import
            logger()->error('Failed to import branding for organization', [
                'organization_id' => $organization->id,
                'error' => $e->getMessage(),
            ]);
        }
    }
}
