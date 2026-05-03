<?php

namespace Tests\Feature\Console;

use App\Models\AuthenticationLog;
use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class EnforceRetentionPolicyTest extends IntegrationTestCase
{
    private function makeOrgWithUser(array $securitySettings = []): array
    {
        $org = Organization::factory()->create([
            'settings' => ['security' => $securitySettings],
        ]);
        $user = User::factory()->create(['organization_id' => $org->id]);

        return [$org, $user];
    }

    #[Test]
    public function command_skips_orgs_without_auto_pruning_enabled(): void
    {
        [$org, $user] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => false,
        ]);

        AuthenticationLog::factory()->forUser($user)->create([
            'created_at' => now()->subDays(60),
        ]);

        Artisan::call('compliance:enforce-retention');

        $this->assertSame(1, AuthenticationLog::query()->count(), 'Logs should be untouched');
    }

    #[Test]
    public function command_deletes_old_logs_only_when_pruning_opted_in(): void
    {
        [$optedIn, $u1] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);
        [$optedOut, $u2] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => false,
        ]);

        // Old + new logs in both orgs
        AuthenticationLog::factory()->forUser($u1)->create(['created_at' => now()->subDays(60)]);
        AuthenticationLog::factory()->forUser($u1)->create(['created_at' => now()->subDays(5)]);
        AuthenticationLog::factory()->forUser($u2)->create(['created_at' => now()->subDays(60)]);
        AuthenticationLog::factory()->forUser($u2)->create(['created_at' => now()->subDays(5)]);

        Artisan::call('compliance:enforce-retention');

        $this->assertSame(1, AuthenticationLog::query()->whereIn('user_id', [$u1->id])->count());
        $this->assertSame(2, AuthenticationLog::query()->whereIn('user_id', [$u2->id])->count());
    }

    #[Test]
    public function command_deletes_resolved_incidents_but_not_open(): void
    {
        [$org, $user] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);

        SecurityIncident::factory()->forOrganization($org)->resolved()->create([
            'detected_at' => now()->subDays(60),
            'resolved_at' => now()->subDays(59),
        ]);
        SecurityIncident::factory()->forOrganization($org)->open()->create([
            'detected_at' => now()->subDays(60),
        ]);
        SecurityIncident::factory()->forOrganization($org)->resolved()->create([
            'detected_at' => now()->subDays(5),
            'resolved_at' => now()->subDays(4),
        ]);

        Artisan::call('compliance:enforce-retention');

        // Only the OLD RESOLVED row gets deleted
        $remaining = SecurityIncident::query()->forOrganization($org->id)->get();
        $this->assertCount(2, $remaining);
        $this->assertContains('open', $remaining->pluck('status')->all());
    }

    #[Test]
    public function command_records_last_pruned_at_in_settings(): void
    {
        [$org] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);

        Artisan::call('compliance:enforce-retention');

        $org->refresh();
        $this->assertNotNull($org->settings['security']['last_pruned_at'] ?? null);
    }

    #[Test]
    public function dry_run_does_not_delete_anything(): void
    {
        [$org, $user] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);

        AuthenticationLog::factory()->forUser($user)->create(['created_at' => now()->subDays(60)]);

        Artisan::call('compliance:enforce-retention', ['--dry-run' => true]);

        $this->assertSame(1, AuthenticationLog::query()->count());
        $org->refresh();
        $this->assertNull($org->settings['security']['last_pruned_at'] ?? null);
    }

    #[Test]
    public function organization_filter_restricts_to_one_org(): void
    {
        [$orgA, $userA] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);
        [$orgB, $userB] = $this->makeOrgWithUser([
            'retention_period_days' => 30,
            'auto_pruning_enabled' => true,
        ]);

        AuthenticationLog::factory()->forUser($userA)->create(['created_at' => now()->subDays(60)]);
        AuthenticationLog::factory()->forUser($userB)->create(['created_at' => now()->subDays(60)]);

        Artisan::call('compliance:enforce-retention', ['--organization' => $orgA->id]);

        $this->assertSame(0, AuthenticationLog::query()->where('user_id', $userA->id)->count());
        $this->assertSame(1, AuthenticationLog::query()->where('user_id', $userB->id)->count());
    }

    #[Test]
    public function cleanup_command_removes_expired_reports_and_files(): void
    {
        Storage::fake('local');

        $expiredPdf = 'compliance_reports/1/soc2_old.pdf';
        $expiredJson = 'compliance_reports/1/soc2_old.json';
        Storage::disk('local')->put($expiredPdf, 'fake pdf');
        Storage::disk('local')->put($expiredJson, '{}');

        $expired = ComplianceReport::factory()->completed()->create([
            'expires_at' => now()->subDay(),
            'file_path_pdf' => $expiredPdf,
            'file_path_json' => $expiredJson,
        ]);
        $current = ComplianceReport::factory()->completed()->create([
            'expires_at' => now()->addDay(),
        ]);

        Artisan::call('compliance:cleanup-expired-reports');

        $this->assertNull(ComplianceReport::query()->find($expired->id));
        $this->assertNotNull(ComplianceReport::query()->find($current->id));
        $this->assertFalse(Storage::disk('local')->exists($expiredPdf));
        $this->assertFalse(Storage::disk('local')->exists($expiredJson));
    }
}
