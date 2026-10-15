<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\Organization;
use App\Models\Role;
use Illuminate\Console\Command;

class SetupOrganizationDefaultRolesCommand extends Command
{
    protected $signature = 'organizations:setup-default-roles';

    protected $description = 'Create the default roles and permissions for organizations that are missing them';

    public function handle(): int
    {
        $repaired = 0;

        Organization::query()->chunkById(100, function ($organizations) use (&$repaired): void {
            foreach ($organizations as $organization) {
                $roleNames = array_keys($organization->getDefaultRoles());
                $existing = Role::where('organization_id', $organization->id)->whereIn('name', $roleNames)->count();

                if ($existing < count($roleNames) * 2) {
                    $organization->setupDefaultRoles();
                    $repaired++;
                }
            }
        });

        $this->info("Set up default roles for {$repaired} organization(s).");

        return self::SUCCESS;
    }
}
