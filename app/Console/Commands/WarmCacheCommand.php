<?php

namespace App\Console\Commands;

use App\Services\CacheWarmingService;
use Illuminate\Console\Command;

class WarmCacheCommand extends Command
{
    protected $signature = 'cache:warm
                          {--all : Warm all caches}
                          {--organizations : Warm organization caches}
                          {--permissions : Warm permission caches}
                          {--applications : Warm application caches}
                          {--statistics : Warm statistics caches}';

    protected $description = 'Warm up application caches for better performance';

    public function handle(CacheWarmingService $warmingService): int
    {
        $this->info('Starting cache warming...');

        if ($this->option('all') || ! $this->hasOptions()) {
            $results = $warmingService->warmAll();
            $this->displayResults($results);

            return self::SUCCESS;
        }

        $results = [];

        if ($this->option('organizations')) {
            $this->info('Warming organization caches...');
            $results['organizations'] = $warmingService->warmOrganizationCaches();
        }

        if ($this->option('permissions')) {
            $this->info('Warming permission caches...');
            $results['permissions'] = $warmingService->warmPermissionCaches();
        }

        if ($this->option('applications')) {
            $this->info('Warming application caches...');
            $results['applications'] = $warmingService->warmApplicationCaches();
        }

        if ($this->option('statistics')) {
            $this->info('Warming statistics caches...');
            $results['statistics'] = $warmingService->warmStatisticsCaches();
        }

        $this->displayResults($results);

        return self::SUCCESS;
    }

    private function hasOptions(): bool
    {
        return $this->option('organizations')
            || $this->option('permissions')
            || $this->option('applications')
            || $this->option('statistics');
    }

    private function displayResults(array $results): void
    {
        $this->newLine();
        $this->info('Cache warming completed:');

        foreach ($results as $type => $count) {
            $this->line("  - {$type}: {$count} items cached");
        }

        $this->newLine();
        $this->info('✓ Cache warming successful');
    }
}
