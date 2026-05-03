<?php

namespace App\Console\Commands;

use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\SecurityIncident;
use Carbon\CarbonImmutable;
use Illuminate\Console\Command;

class EnforceRetentionPolicy extends Command
{
    protected $signature = 'compliance:enforce-retention
                            {--organization= : Restrict to a single organization id}
                            {--dry-run : Report what would be deleted without writing}';

    protected $description = 'Delete authentication logs and resolved security incidents older than each organization\'s retention policy';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $orgId = $this->option('organization');

        $query = Organization::query();
        if ($orgId !== null) {
            $query->whereKey((int) $orgId);
        }

        $totalLogsDeleted = 0;
        $totalIncidentsDeleted = 0;
        $orgsProcessed = 0;
        $orgsSkipped = 0;

        $query->select(['id', 'name', 'settings'])->chunkById(50, function ($organizations) use (
            &$totalLogsDeleted,
            &$totalIncidentsDeleted,
            &$orgsProcessed,
            &$orgsSkipped,
            $dryRun,
        ): void {
            foreach ($organizations as $organization) {
                $settings = (array) ($organization->settings['security'] ?? []);
                $autoPruning = (bool) ($settings['auto_pruning_enabled'] ?? false);

                if (! $autoPruning) {
                    $orgsSkipped++;

                    continue;
                }

                $retentionDays = (int) ($settings['retention_period_days']
                    ?? config('compliance.default_retention_days', 365));
                $cutoff = CarbonImmutable::now()->subDays($retentionDays);

                $userIds = $organization->organizationUsers()->pluck('id');

                $logsCount = AuthenticationLog::query()
                    ->whereIn('user_id', $userIds)
                    ->where('created_at', '<', $cutoff);
                $incidentsCount = SecurityIncident::query()
                    ->forOrganization($organization->id)
                    ->whereNotNull('resolved_at')
                    ->where('detected_at', '<', $cutoff);

                if ($dryRun) {
                    $totalLogsDeleted += $logsCount->count();
                    $totalIncidentsDeleted += $incidentsCount->count();
                } else {
                    $totalLogsDeleted += $logsCount->delete();
                    $totalIncidentsDeleted += $incidentsCount->delete();

                    // Persist last_pruned_at into the org settings so the next
                    // compliance report can show when retention was last enforced.
                    $newSettings = (array) $organization->settings;
                    $newSettings['security'] = array_merge($settings, [
                        'last_pruned_at' => CarbonImmutable::now()->toIso8601String(),
                    ]);
                    $organization->forceFill(['settings' => $newSettings])->save();
                }

                $orgsProcessed++;
            }
        });

        $verb = $dryRun ? 'Would delete' : 'Deleted';
        $this->info("Processed {$orgsProcessed} orgs (skipped {$orgsSkipped} with auto_pruning disabled)");
        $this->info("{$verb} {$totalLogsDeleted} authentication logs, {$totalIncidentsDeleted} resolved security incidents");

        return self::SUCCESS;
    }
}
