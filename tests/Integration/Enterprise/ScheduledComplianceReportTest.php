<?php

namespace Tests\Integration\Enterprise;

use App\Jobs\GenerateComplianceReportJob;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ScheduledComplianceReportTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();
        $this->organization = Organization::factory()->create();
        $this->admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
    }

    #[Test]
    public function schedule_endpoint_persists_a_row(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);

        $response = $this->withToken($token)->postJson('/api/v1/enterprise/compliance/schedule', [
            'report_type' => 'soc2',
            'frequency' => 'weekly',
            'recipients' => ['compliance@example.com', 'audit@example.com'],
        ]);

        $response->assertCreated();
        $response->assertJsonPath('data.schedule.report_type', 'soc2');
        $response->assertJsonPath('data.schedule.frequency', 'weekly');

        $this->assertDatabaseHas('scheduled_compliance_reports', [
            'organization_id' => $this->organization->id,
            'created_by_user_id' => $this->admin->id,
            'report_type' => 'soc2',
            'frequency' => 'weekly',
            'is_active' => true,
        ]);
    }

    #[Test]
    public function schedule_endpoint_rejects_invalid_payload(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->postJson('/api/v1/enterprise/compliance/schedule', [
                'report_type' => 'pci',  // not allowed
                'frequency' => 'hourly', // not allowed
                'recipients' => [],      // empty
            ])
            ->assertStatus(422)
            ->assertJsonValidationErrors(['report_type', 'frequency', 'recipients']);
    }

    #[Test]
    public function list_endpoint_returns_only_own_organizations_schedules(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);
        $other = Organization::factory()->create();

        ScheduledComplianceReport::factory()->count(2)->create(['organization_id' => $this->organization->id]);
        ScheduledComplianceReport::factory()->count(3)->create(['organization_id' => $other->id]);

        $response = $this->withToken($token)->getJson('/api/v1/enterprise/compliance/schedules');

        $response->assertOk();
        $this->assertCount(2, $response->json('data.schedules'));
    }

    #[Test]
    public function update_endpoint_recomputes_next_run_when_frequency_changes(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);
        $schedule = ScheduledComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
            'frequency' => 'monthly',
            'next_run_at' => now()->addMonth(),
        ]);

        $previousNextRun = $schedule->next_run_at;

        $this->withToken($token)
            ->patchJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}", [
                'frequency' => 'daily',
            ])
            ->assertOk();

        $schedule->refresh();
        $this->assertSame('daily', $schedule->frequency);
        $this->assertTrue($schedule->next_run_at->lessThan($previousNextRun));
    }

    #[Test]
    public function cancel_endpoint_deactivates_without_deleting(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);
        $schedule = ScheduledComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
            'is_active' => true,
        ]);

        $this->withToken($token)
            ->deleteJson("/api/v1/enterprise/compliance/schedules/{$schedule->id}")
            ->assertOk();

        $schedule->refresh();
        $this->assertFalse($schedule->is_active);
        $this->assertDatabaseHas('scheduled_compliance_reports', ['id' => $schedule->id]);
    }

    #[Test]
    public function update_and_cancel_cannot_reach_other_org_schedules(): void
    {
        $token = $this->createAccessToken($this->admin, ['*']);
        $foreign = ScheduledComplianceReport::factory()->create();

        $this->withToken($token)
            ->patchJson("/api/v1/enterprise/compliance/schedules/{$foreign->id}", ['frequency' => 'daily'])
            ->assertNotFound();

        $this->withToken($token)
            ->deleteJson("/api/v1/enterprise/compliance/schedules/{$foreign->id}")
            ->assertNotFound();
    }

    #[Test]
    public function dispatch_command_queues_jobs_and_advances_next_run(): void
    {
        Queue::fake();

        $due = ScheduledComplianceReport::factory()->due()->create([
            'organization_id' => $this->organization->id,
            'recipients' => ['ops@example.com'],
        ]);
        $futureSchedule = ScheduledComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
            'next_run_at' => now()->addDay(),
        ]);
        $inactive = ScheduledComplianceReport::factory()->due()->inactive()->create([
            'organization_id' => $this->organization->id,
        ]);

        $beforeNextRun = $due->next_run_at;

        Artisan::call('compliance:dispatch-scheduled');

        Queue::assertPushed(GenerateComplianceReportJob::class, 1);

        $due->refresh();
        $this->assertNotNull($due->last_run_at);
        $this->assertTrue($due->next_run_at->greaterThan($beforeNextRun));

        $futureSchedule->refresh();
        $this->assertNull($futureSchedule->last_run_at);

        $inactive->refresh();
        $this->assertNull($inactive->last_run_at);
    }

    #[Test]
    public function dispatch_command_dry_run_does_not_dispatch(): void
    {
        Queue::fake();

        ScheduledComplianceReport::factory()->due()->create([
            'organization_id' => $this->organization->id,
        ]);

        Artisan::call('compliance:dispatch-scheduled', ['--dry-run' => true]);

        Queue::assertNothingPushed();
    }
}
