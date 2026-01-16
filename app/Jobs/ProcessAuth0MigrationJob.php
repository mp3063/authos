<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Models\MigrationJob;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use App\Services\Auth0\Migration\Auth0MigrationService;
use App\Services\Auth0\Migration\Importers\UserImporter;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Throwable;

class ProcessAuth0MigrationJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /**
     * Create a new job instance.
     */
    public function __construct(
        public MigrationJob $migrationJob
    ) {}

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        try {
            // Update job status to running
            $this->migrationJob->update([
                'status' => 'running',
                'started_at' => now(),
            ]);

            // Get configuration
            $config = $this->migrationJob->config ?? [];
            $tenantDomain = $config['tenant_domain'] ?? null;
            $apiToken = $config['api_token'] ?? null;

            if (! $tenantDomain || ! $apiToken) {
                throw new \RuntimeException('Missing Auth0 tenant domain or API token in migration configuration');
            }

            // Initialize Auth0 client (via container for testability)
            $auth0Client = $this->makeAuth0Client($tenantDomain, $apiToken);

            // Initialize migration service (via container for testability)
            $migrationService = $this->makeMigrationService($auth0Client);

            // Discover resources
            $plan = $migrationService->discover();

            // Store migrated data count
            $totalItems = 0;
            if ($config['migrate_users'] ?? false) {
                $totalItems += count($plan->users);
            }
            if ($config['migrate_applications'] ?? false) {
                $totalItems += count($plan->applications);
            }
            if ($config['migrate_roles'] ?? false) {
                $totalItems += count($plan->roles);
            }

            $this->migrationJob->update(['total_items' => $totalItems]);

            // Execute migration
            $result = $migrationService->migrate($plan, false, $config['password_strategy'] ?? UserImporter::STRATEGY_LAZY);

            // Store migration results
            $stats = [
                'users' => [
                    'total' => $result->users->total,
                    'successful' => $result->users->successful,
                    'failed' => $result->users->failed,
                    'skipped' => $result->users->skipped,
                ],
                'applications' => [
                    'total' => $result->applications->total,
                    'successful' => $result->applications->successful,
                    'failed' => $result->applications->failed,
                    'skipped' => $result->applications->skipped,
                ],
                'roles' => [
                    'total' => $result->roles->total,
                    'successful' => $result->roles->successful,
                    'failed' => $result->roles->failed,
                    'skipped' => $result->roles->skipped,
                ],
            ];

            // Store migrated data for auditing
            $migratedData = [
                'users' => array_map(fn (Auth0UserDTO $user) => [
                    'user_id' => $user->userId,
                    'email' => $user->email,
                    'name' => $user->name,
                ], $plan->users),
                'applications' => array_map(fn (Auth0ClientDTO $client) => [
                    'client_id' => $client->clientId,
                    'name' => $client->name,
                ], $plan->applications),
                'roles' => array_map(fn (Auth0RoleDTO $role) => [
                    'id' => $role->id,
                    'name' => $role->name,
                ], $plan->roles),
            ];

            // Update job with success
            $this->migrationJob->update([
                'status' => 'completed',
                'stats' => $stats,
                'migrated_data' => $migratedData,
                'completed_at' => now(),
            ]);

            Log::info('Auth0 migration completed successfully', [
                'migration_job_id' => $this->migrationJob->id,
                'stats' => $stats,
            ]);
        } catch (Throwable $e) {
            // Log error
            Log::error('Auth0 migration failed', [
                'migration_job_id' => $this->migrationJob->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            // Update job with failure
            $errorLog = $this->migrationJob->error_log ?? [];
            $errorLog[] = [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'timestamp' => now()->toDateTimeString(),
            ];

            $this->migrationJob->update([
                'status' => 'failed',
                'error_log' => $errorLog,
                'completed_at' => now(),
            ]);

            // Don't re-throw - job should complete gracefully with failed status
            // The error is already logged and stored in the migration job
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(Throwable $exception): void
    {
        Log::error('ProcessAuth0MigrationJob failed completely', [
            'migration_job_id' => $this->migrationJob->id,
            'error' => $exception->getMessage(),
        ]);

        // Ensure job is marked as failed
        $this->migrationJob->update([
            'status' => 'failed',
            'completed_at' => now(),
        ]);
    }

    /**
     * Create Auth0Client instance via container for testability.
     */
    protected function makeAuth0Client(string $domain, string $token): Auth0Client
    {
        return app()->make(Auth0Client::class, [
            'domain' => $domain,
            'token' => $token,
        ]);
    }

    /**
     * Create Auth0MigrationService instance via container for testability.
     */
    protected function makeMigrationService(Auth0Client $client): Auth0MigrationService
    {
        return app()->make(Auth0MigrationService::class, [
            'client' => $client,
            'targetOrganization' => $this->migrationJob->organization,
        ]);
    }
}
