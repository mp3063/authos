<?php

namespace App\Console\Commands;

use App\Models\ComplianceReport;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class CleanupExpiredComplianceReports extends Command
{
    protected $signature = 'compliance:cleanup-expired-reports
                            {--dry-run : Report what would be deleted without writing}';

    protected $description = 'Delete ComplianceReport rows whose expires_at has passed, plus their PDF/JSON files';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $disk = Storage::disk('local');
        $deleted = 0;
        $filesRemoved = 0;

        ComplianceReport::query()
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->chunkById(100, function ($reports) use ($disk, $dryRun, &$deleted, &$filesRemoved): void {
                foreach ($reports as $report) {
                    foreach ([$report->file_path_pdf, $report->file_path_json] as $path) {
                        if ($path !== null && $disk->exists($path)) {
                            if (! $dryRun) {
                                $disk->delete($path);
                            }
                            $filesRemoved++;
                        }
                    }

                    if (! $dryRun) {
                        $report->delete();
                    }
                    $deleted++;
                }
            });

        $verb = $dryRun ? 'Would delete' : 'Deleted';
        $this->info("{$verb} {$deleted} expired compliance reports, {$filesRemoved} storage files");

        return self::SUCCESS;
    }
}
