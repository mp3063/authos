<?php

namespace App\Jobs;

use App\Models\LdapConfiguration;
use App\Services\LdapAuthService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

class SyncLdapUsersJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $timeout = 300; // 5 minutes

    public int $tries = 3;

    public int $backoff = 60; // Retry after 60 seconds

    public function __construct(
        public LdapConfiguration $ldapConfig
    ) {}

    public function handle(LdapAuthService $service): void
    {
        Log::info("Starting LDAP sync for config: {$this->ldapConfig->id}");

        try {
            $results = $service->syncUsers($this->ldapConfig, $this->ldapConfig->organization);

            // Update last_sync_at and status
            $this->ldapConfig->update([
                'last_sync_at' => now(),
                'sync_status' => 'completed',
                'last_sync_result' => $results,
            ]);

            Log::info('LDAP sync completed', $results);

        } catch (\Exception $e) {
            Log::error("LDAP sync failed: {$e->getMessage()}");

            $this->ldapConfig->update([
                'sync_status' => 'failed',
                'last_sync_error' => $e->getMessage(),
            ]);

            throw $e; // Re-throw to trigger retry
        }
    }

    public function failed(\Throwable $exception): void
    {
        Log::error("LDAP sync job failed permanently: {$exception->getMessage()}");

        $this->ldapConfig->update([
            'sync_status' => 'failed',
            'last_sync_error' => $exception->getMessage(),
        ]);
    }
}
