<?php

namespace App\Console\Commands;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\ScheduledComplianceReport;
use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class DispatchScheduledComplianceReports extends Command
{
    protected $signature = 'compliance:dispatch-scheduled
                            {--dry-run : Report what would be dispatched without queueing jobs}';

    protected $description = 'Dispatch all scheduled compliance reports whose next_run_at has elapsed';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $now = CarbonImmutable::now();
        $dispatched = 0;
        $skipped = 0;

        // Wrap in a transaction so lockForUpdate releases even if dispatch throws.
        // We process each schedule individually rather than locking all rows at once
        // to keep lock duration short on large fleets.
        DB::transaction(function () use ($now, $dryRun, &$dispatched, &$skipped): void {
            $schedules = ScheduledComplianceReport::query()
                ->due()
                ->lockForUpdate()
                ->get();

            foreach ($schedules as $schedule) {
                if ($schedule->organization === null) {
                    $this->warn("Schedule #{$schedule->id} has no organization; deactivating.");
                    $schedule->update(['is_active' => false]);
                    $skipped++;

                    continue;
                }

                if ($dryRun) {
                    $this->info("Would dispatch {$schedule->report_type} for org #{$schedule->organization_id} (schedule #{$schedule->id})");
                    $dispatched++;

                    continue;
                }

                try {
                    GenerateComplianceReportJob::dispatch(
                        $schedule->organization,
                        $schedule->report_type,
                        $schedule->recipients,
                    );

                    // Compute next run from NOW (not from previous next_run_at) to avoid
                    // catch-up storms after worker downtime.
                    $schedule->update([
                        'last_run_at' => $now,
                        'next_run_at' => $schedule->computeNextRunAt($now),
                    ]);

                    $dispatched++;
                } catch (\Throwable $e) {
                    Log::error('Failed to dispatch scheduled compliance report', [
                        'schedule_id' => $schedule->id,
                        'organization_id' => $schedule->organization_id,
                        'error' => $e->getMessage(),
                    ]);
                    $skipped++;
                }
            }
        });

        $this->info("Dispatched: {$dispatched}, Skipped: {$skipped}".($dryRun ? ' (dry run)' : ''));

        return self::SUCCESS;
    }
}
