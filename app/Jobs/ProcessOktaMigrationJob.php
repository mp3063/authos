<?php

declare(strict_types=1);

namespace App\Jobs;

use App\Models\MigrationJob;
use App\Models\User;
use App\Services\Okta\OktaClient;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class ProcessOktaMigrationJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public function __construct(
        public MigrationJob $migrationJob
    ) {}

    public function handle(): void
    {
        try {
            $this->migrationJob->update([
                'status' => 'running',
                'started_at' => now(),
            ]);

            $config = $this->migrationJob->config ?? [];
            $domain = $config['okta_domain'] ?? null;
            $token = $config['okta_api_token'] ?? null;

            if (! $domain || ! $token) {
                throw new \RuntimeException('Missing Okta domain or API token');
            }

            $client = $this->makeOktaClient($domain, $token);

            $stats = [
                'users' => ['total' => 0, 'successful' => 0, 'failed' => 0, 'skipped' => 0],
                'applications' => ['total' => 0, 'successful' => 0, 'failed' => 0, 'skipped' => 0],
                'roles' => ['total' => 0, 'successful' => 0, 'failed' => 0, 'skipped' => 0],
            ];

            // Migrate users
            if ($config['migrate_users'] ?? false) {
                $oktaUsers = $client->getUsers();
                $stats['users']['total'] = count($oktaUsers);
                $this->migrationJob->update(['total_items' => count($oktaUsers)]);

                foreach ($oktaUsers as $oktaUser) {
                    try {
                        $email = $oktaUser['profile']['email'] ?? null;
                        if (! $email) {
                            $stats['users']['skipped']++;

                            continue;
                        }

                        if (User::where('email', $email)->exists()) {
                            $stats['users']['skipped']++;

                            continue;
                        }

                        $name = trim(($oktaUser['profile']['firstName'] ?? '').' '.($oktaUser['profile']['lastName'] ?? ''));
                        if (! $name) {
                            $name = explode('@', $email)[0];
                        }

                        User::create([
                            'name' => $name,
                            'email' => $email,
                            'password' => Hash::make(Str::random(32)),
                            'email_verified_at' => ($oktaUser['status'] === 'ACTIVE') ? now() : null,
                            'organization_id' => $this->migrationJob->organization_id,
                            'profile' => [
                                'okta_user_id' => $oktaUser['id'],
                                'imported_from_okta' => true,
                                'imported_at' => now()->toIso8601String(),
                            ],
                            'metadata' => [
                                'okta_user_id' => $oktaUser['id'],
                                'okta_status' => $oktaUser['status'] ?? null,
                                'okta_created' => $oktaUser['created'] ?? null,
                                'okta_last_login' => $oktaUser['lastLogin'] ?? null,
                            ],
                        ]);

                        $stats['users']['successful']++;
                    } catch (Throwable $e) {
                        $stats['users']['failed']++;
                        Log::warning('Failed to import Okta user', [
                            'error' => $e->getMessage(),
                            'okta_user_id' => $oktaUser['id'] ?? 'unknown',
                        ]);
                    }
                }
            }

            $this->migrationJob->update([
                'status' => 'completed',
                'stats' => $stats,
                'completed_at' => now(),
            ]);

            Log::info('Okta migration completed', [
                'migration_job_id' => $this->migrationJob->id,
                'stats' => $stats,
            ]);
        } catch (Throwable $e) {
            Log::error('Okta migration failed', [
                'migration_job_id' => $this->migrationJob->id,
                'error' => $e->getMessage(),
            ]);

            $errorLog = $this->migrationJob->error_log ?? [];
            $errorLog[] = [
                'message' => $e->getMessage(),
                'timestamp' => now()->toDateTimeString(),
            ];

            $this->migrationJob->update([
                'status' => 'failed',
                'error_log' => $errorLog,
                'completed_at' => now(),
            ]);
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(Throwable $exception): void
    {
        Log::error('ProcessOktaMigrationJob failed completely', [
            'migration_job_id' => $this->migrationJob->id,
            'error' => $exception->getMessage(),
        ]);

        $this->migrationJob->update([
            'status' => 'failed',
            'completed_at' => now(),
        ]);
    }

    /**
     * Create OktaClient instance via container for testability.
     */
    protected function makeOktaClient(string $domain, string $token): OktaClient
    {
        return app()->make(OktaClient::class, [
            'domain' => $domain,
            'apiToken' => $token,
        ]);
    }
}
