<?php

namespace App\Console\Commands;

use App\Models\AuditExport;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class MovePublicExports extends Command
{
    protected $signature = 'exports:move-public
                            {--dry-run : Report what would be moved or deleted without writing}';

    protected $description = 'Move referenced exports from the public disk to the local disk and delete unreferenced public exports';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $public = Storage::disk('public');
        $local = Storage::disk('local');
        $moved = 0;
        $deleted = 0;

        $referenced = AuditExport::query()
            ->where('file_path', 'like', 'exports/%')
            ->pluck('file_path')
            ->flip();

        foreach ($public->allFiles('exports') as $path) {
            if ($referenced->has($path) && ! $local->exists($path)) {
                if (! $dryRun) {
                    $local->writeStream($path, $public->readStream($path));
                }
                $moved++;
            } else {
                $deleted++;
            }

            if (! $dryRun) {
                $public->delete($path);
            }
        }

        $prefix = $dryRun ? '[dry run] ' : '';
        $this->info("{$prefix}Moved {$moved} exports to the local disk, deleted {$deleted} public exports");

        return self::SUCCESS;
    }
}
