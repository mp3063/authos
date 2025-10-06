<?php

declare(strict_types=1);

namespace App\Services\Auth0\Migration;

use App\Models\Organization;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use App\Services\Auth0\Exceptions\Auth0ApiException;
use App\Services\Auth0\Migration\Importers\ApplicationImporter;
use App\Services\Auth0\Migration\Importers\OrganizationImporter;
use App\Services\Auth0\Migration\Importers\RoleImporter;
use App\Services\Auth0\Migration\Importers\UserImporter;
use Illuminate\Support\Facades\DB;

class Auth0MigrationService
{
    public function __construct(
        private Auth0Client $client,
        private ?Organization $targetOrganization = null,
    ) {}

    /**
     * Discover all resources from Auth0
     *
     * @throws Auth0ApiException
     */
    public function discover(): MigrationPlan
    {
        $plan = new MigrationPlan;

        // Discover organizations
        foreach ($this->discoverOrganizations() as $organization) {
            $plan->addOrganization($organization);
        }

        // Discover roles
        foreach ($this->discoverRoles() as $role) {
            $plan->addRole($role);
        }

        // Discover applications
        foreach ($this->discoverApplications() as $application) {
            $plan->addApplication($application);
        }

        // Discover users
        foreach ($this->discoverUsers() as $user) {
            $plan->addUser($user);
        }

        // Discover connections
        foreach ($this->discoverConnections() as $connection) {
            $plan->addConnection($connection);
        }

        return $plan;
    }

    /**
     * Execute migration
     *
     * @throws \Throwable
     */
    public function migrate(MigrationPlan $plan, bool $dryRun = false, string $passwordStrategy = UserImporter::STRATEGY_LAZY): MigrationResult
    {
        // Create result object
        $result = new MigrationResult(
            organizations: new ImportResult,
            roles: new ImportResult,
            applications: new ImportResult,
            users: new ImportResult,
            dryRun: $dryRun,
        );

        if (! $dryRun) {
            DB::beginTransaction();
        }

        try {
            // Phase 1: Import organizations
            $result->organizations = $this->migrateOrganizations($plan, $dryRun);

            // Phase 2: Import roles
            $result->roles = $this->migrateRoles($plan, $dryRun);

            // Phase 3: Import applications
            $result->applications = $this->migrateApplications($plan, $dryRun);

            // Phase 4: Import users
            $result->users = $this->migrateUsers($plan, $dryRun, $passwordStrategy);

            if (! $dryRun) {
                DB::commit();
            }

            $result->markCompleted();

            return $result;
        } catch (\Throwable $e) {
            if (! $dryRun) {
                DB::rollBack();
            }

            throw $e;
        }
    }

    /**
     * Validate migration result
     */
    public function validate(MigrationResult $result): ValidationReport
    {
        $validator = new MigrationValidator;

        return $validator->validate($result);
    }

    /**
     * Rollback migration
     */
    public function rollback(MigrationResult $result): void
    {
        $rollbackService = new RollbackService;
        $rollbackService->rollback($result);
    }

    /**
     * Discover organizations from Auth0
     *
     * @return \Generator<Auth0OrganizationDTO>
     *
     * @throws Auth0ApiException
     */
    private function discoverOrganizations(): \Generator
    {
        foreach ($this->client->organizations()->getAll() as $orgData) {
            yield Auth0OrganizationDTO::fromArray($orgData);
        }
    }

    /**
     * Discover roles from Auth0
     *
     * @return \Generator<Auth0RoleDTO>
     *
     * @throws Auth0ApiException
     */
    private function discoverRoles(): \Generator
    {
        foreach ($this->client->roles()->getAll() as $roleData) {
            $role = Auth0RoleDTO::fromArray($roleData);

            // Fetch permissions for this role
            try {
                $permissions = $this->client->roles()->getPermissions($role->id);
                $role->permissions = $permissions;
            } catch (\Throwable $e) {
                // Continue without permissions
                logger()->warning('Failed to fetch permissions for role', [
                    'role_id' => $role->id,
                    'error' => $e->getMessage(),
                ]);
            }

            yield $role;
        }
    }

    /**
     * Discover applications from Auth0
     *
     * @return \Generator<Auth0ClientDTO>
     *
     * @throws Auth0ApiException
     */
    private function discoverApplications(): \Generator
    {
        foreach ($this->client->clients()->getAll() as $clientData) {
            yield Auth0ClientDTO::fromArray($clientData);
        }
    }

    /**
     * Discover users from Auth0
     *
     * @return \Generator<Auth0UserDTO>
     *
     * @throws Auth0ApiException
     */
    private function discoverUsers(): \Generator
    {
        foreach ($this->client->users()->getAll() as $userData) {
            yield Auth0UserDTO::fromArray($userData);
        }
    }

    /**
     * Discover connections from Auth0
     *
     * @return \Generator<array<string, mixed>>
     *
     * @throws Auth0ApiException
     */
    private function discoverConnections(): \Generator
    {
        foreach ($this->client->connections()->getAll() as $connection) {
            yield $connection;
        }
    }

    /**
     * Migrate organizations
     */
    private function migrateOrganizations(MigrationPlan $plan, bool $dryRun): ImportResult
    {
        $importer = new OrganizationImporter;

        return $importer->import($plan->organizations, $dryRun);
    }

    /**
     * Migrate roles
     */
    private function migrateRoles(MigrationPlan $plan, bool $dryRun): ImportResult
    {
        $importer = new RoleImporter($this->targetOrganization);

        return $importer->import($plan->roles, $dryRun);
    }

    /**
     * Migrate applications
     */
    private function migrateApplications(MigrationPlan $plan, bool $dryRun): ImportResult
    {
        $importer = new ApplicationImporter($this->targetOrganization);

        return $importer->import($plan->applications, $dryRun);
    }

    /**
     * Migrate users
     */
    private function migrateUsers(MigrationPlan $plan, bool $dryRun, string $passwordStrategy): ImportResult
    {
        $importer = new UserImporter($passwordStrategy, $this->targetOrganization);

        return $importer->import($plan->users, $dryRun);
    }

    /**
     * Set target organization for migration
     */
    public function setTargetOrganization(Organization $organization): void
    {
        $this->targetOrganization = $organization;
    }
}
