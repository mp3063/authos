<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\Organization;
use App\Services\Auth0\Auth0Client;
use App\Services\Auth0\Exceptions\Auth0ApiException;
use App\Services\Auth0\Migration\Auth0MigrationService;
use App\Services\Auth0\Migration\Importers\UserImporter;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class MigrateFromAuth0Command extends Command
{
    protected $signature = 'migrate:auth0
                            {--domain= : Auth0 domain (e.g., example.auth0.com)}
                            {--token= : Auth0 Management API token}
                            {--organization= : Target organization ID for imported data}
                            {--dry-run : Perform a dry run without making changes}
                            {--strategy=lazy : Password migration strategy (reset, lazy, hash)}
                            {--export= : Export migration plan to JSON file}
                            {--skip-validation : Skip validation after migration}';

    protected $description = 'Migrate data from Auth0 tenant to AuthOS';

    public function handle(): int
    {
        $this->info('Auth0 Migration Tool');
        $this->newLine();

        // Get Auth0 credentials
        $domain = $this->option('domain') ?? $this->ask('Auth0 Domain (e.g., example.auth0.com)');
        $token = $this->option('token') ?? $this->secret('Auth0 Management API Token');

        if (! $domain || ! $token) {
            $this->error('Auth0 domain and token are required');

            return self::FAILURE;
        }

        // Get target organization
        $targetOrganization = null;
        if ($organizationId = $this->option('organization')) {
            $targetOrganization = Organization::find($organizationId);

            if (! $targetOrganization) {
                $this->error("Organization with ID {$organizationId} not found");

                return self::FAILURE;
            }
        }

        $dryRun = $this->option('dry-run');
        $strategy = $this->option('strategy') ?? UserImporter::STRATEGY_LAZY;

        // Validate strategy
        if (! in_array($strategy, [UserImporter::STRATEGY_RESET, UserImporter::STRATEGY_LAZY, UserImporter::STRATEGY_HASH], true)) {
            $this->error("Invalid password strategy: {$strategy}");

            return self::FAILURE;
        }

        try {
            // Test connection
            $this->info('Testing Auth0 connection...');
            $client = new Auth0Client($domain, $token);

            if (! $client->testConnection()) {
                $this->error('Failed to connect to Auth0 API');

                return self::FAILURE;
            }

            $this->info('Connection successful!');
            $this->newLine();

            // Create migration service
            $migrationService = new Auth0MigrationService($client, $targetOrganization);

            // Phase 1: Discovery
            $this->info('Discovering Auth0 resources...');
            $plan = $migrationService->discover();

            // Display summary
            $this->displayMigrationPlan($plan);

            // Export plan if requested
            if ($exportPath = $this->option('export')) {
                $this->info("Exporting migration plan to {$exportPath}...");
                File::put($exportPath, $plan->exportToJson());
                $this->info('Plan exported successfully!');
                $this->newLine();
            }

            // Confirm before proceeding
            if (! $dryRun) {
                if (! $this->confirm('Do you want to proceed with the migration?')) {
                    $this->info('Migration cancelled');

                    return self::SUCCESS;
                }
            }

            // Phase 2: Migration
            $this->newLine();
            $this->info($dryRun ? 'Performing dry run...' : 'Starting migration...');
            $this->newLine();

            $result = $this->createProgressBar($plan->getTotalItems(), function ($bar) use ($migrationService, $plan, $dryRun, $strategy) {
                return $migrationService->migrate($plan, $dryRun, $strategy);
            });

            $this->newLine(2);

            // Display results
            $this->displayMigrationResult($result);

            // Phase 3: Validation
            if (! $this->option('skip-validation') && ! $dryRun && $result->getSuccessCount() > 0) {
                $this->newLine();
                $this->info('Validating migration...');

                $validationReport = $migrationService->validate($result);

                if ($validationReport->isValid()) {
                    $this->info('Validation passed!');
                } else {
                    $this->warn('Validation found issues:');
                    $this->displayValidationReport($validationReport);

                    if ($this->confirm('Do you want to rollback the migration?')) {
                        $this->info('Rolling back migration...');
                        $migrationService->rollback($result);
                        $this->info('Rollback completed!');

                        return self::FAILURE;
                    }
                }
            }

            return $result->hasFailures() ? self::FAILURE : self::SUCCESS;
        } catch (Auth0ApiException $e) {
            $this->error("Auth0 API Error: {$e->getMessage()}");

            return self::FAILURE;
        } catch (\Throwable $e) {
            $this->error("Migration failed: {$e->getMessage()}");
            $this->error($e->getTraceAsString());

            return self::FAILURE;
        }
    }

    /**
     * Display migration plan summary
     */
    private function displayMigrationPlan($plan): void
    {
        $summary = $plan->getSummary();

        $this->table(
            ['Resource', 'Count'],
            [
                ['Organizations', $summary['organizations']],
                ['Roles', $summary['roles']],
                ['Applications', $summary['applications']],
                ['Users', $summary['users']],
                ['Connections', $summary['connections']],
                ['<fg=cyan>TOTAL</>', "<fg=cyan>{$summary['total']}</>"],
            ]
        );

        $this->newLine();
    }

    /**
     * Display migration result
     */
    private function displayMigrationResult($result): void
    {
        $report = $result->getReport();

        $this->info('Migration Result:');
        $this->newLine();

        $this->table(
            ['Resource', 'Total', 'Success', 'Failed', 'Skipped', 'Success Rate'],
            [
                [
                    'Organizations',
                    $report['organizations']['total'],
                    "<fg=green>{$report['organizations']['successful']}</>",
                    $report['organizations']['failed'] > 0 ? "<fg=red>{$report['organizations']['failed']}</>" : $report['organizations']['failed'],
                    $report['organizations']['skipped'],
                    number_format($report['organizations']['success_rate'], 1).'%',
                ],
                [
                    'Roles',
                    $report['roles']['total'],
                    "<fg=green>{$report['roles']['successful']}</>",
                    $report['roles']['failed'] > 0 ? "<fg=red>{$report['roles']['failed']}</>" : $report['roles']['failed'],
                    $report['roles']['skipped'],
                    number_format($report['roles']['success_rate'], 1).'%',
                ],
                [
                    'Applications',
                    $report['applications']['total'],
                    "<fg=green>{$report['applications']['successful']}</>",
                    $report['applications']['failed'] > 0 ? "<fg=red>{$report['applications']['failed']}</>" : $report['applications']['failed'],
                    $report['applications']['skipped'],
                    number_format($report['applications']['success_rate'], 1).'%',
                ],
                [
                    'Users',
                    $report['users']['total'],
                    "<fg=green>{$report['users']['successful']}</>",
                    $report['users']['failed'] > 0 ? "<fg=red>{$report['users']['failed']}</>" : $report['users']['failed'],
                    $report['users']['skipped'],
                    number_format($report['users']['success_rate'], 1).'%',
                ],
                [
                    '<fg=cyan>TOTAL</>',
                    $report['total'],
                    "<fg=cyan;options=bold>{$report['successful']}</>",
                    $report['failed'] > 0 ? "<fg=red;options=bold>{$report['failed']}</>" : $report['failed'],
                    "<fg=yellow>{$report['skipped']}</>",
                    '<fg=cyan>'.number_format($report['success_rate'], 1).'%</>',
                ],
            ]
        );

        $this->newLine();

        // Display errors if any
        if ($result->hasFailures()) {
            $this->warn('Errors occurred during migration:');
            $errors = $result->getAllErrors();

            foreach ($errors as $category => $categoryErrors) {
                if (! empty($categoryErrors)) {
                    $this->warn(ucfirst($category).':');

                    foreach (array_slice($categoryErrors, 0, 5) as $error) {
                        $this->line("  - {$error}");
                    }

                    if (count($categoryErrors) > 5) {
                        $this->line('  ... and '.(count($categoryErrors) - 5).' more');
                    }
                }
            }
        }

        $this->info("Duration: {$report['duration_seconds']} seconds");
    }

    /**
     * Display validation report
     */
    private function displayValidationReport($report): void
    {
        $errors = $report->getErrors();

        foreach ($errors as $category => $categoryErrors) {
            if (! empty($categoryErrors)) {
                $this->warn(ucfirst($category).' errors:');

                foreach (array_slice($categoryErrors, 0, 5) as $error) {
                    $this->line("  - ID {$error['id']}: {$error['message']}");
                }

                if (count($categoryErrors) > 5) {
                    $this->line('  ... and '.(count($categoryErrors) - 5).' more');
                }
            }
        }
    }

    /**
     * Create a progress bar for migration
     */
    private function createProgressBar(int $total, callable $callback): mixed
    {
        $bar = $this->output->createProgressBar($total);
        $bar->start();

        $result = $callback($bar);

        $bar->finish();

        return $result;
    }
}
