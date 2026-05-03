<?php

namespace Tests\Unit\Models;

use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use Carbon\Carbon;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ScheduledComplianceReportTest extends TestCase
{
    #[Test]
    public function it_casts_recipients_and_dates_correctly(): void
    {
        $schedule = ScheduledComplianceReport::factory()->create([
            'recipients' => ['a@example.com', 'b@example.com'],
            'is_active' => true,
        ]);

        $schedule->refresh();

        $this->assertIsArray($schedule->recipients);
        $this->assertCount(2, $schedule->recipients);
        $this->assertInstanceOf(Carbon::class, $schedule->next_run_at);
        $this->assertTrue($schedule->is_active);
    }

    #[Test]
    public function it_has_organization_relation(): void
    {
        $org = Organization::factory()->create();
        $schedule = ScheduledComplianceReport::factory()->create(['organization_id' => $org->id]);

        $this->assertTrue($schedule->organization->is($org));
    }

    #[Test]
    public function it_has_created_by_relation(): void
    {
        $user = User::factory()->create();
        $schedule = ScheduledComplianceReport::factory()->create(['created_by_user_id' => $user->id]);

        $this->assertTrue($schedule->createdBy->is($user));
    }

    public static function frequencyProvider(): array
    {
        return [
            'daily' => [ScheduledComplianceReport::FREQUENCY_DAILY, 'addDay'],
            'weekly' => [ScheduledComplianceReport::FREQUENCY_WEEKLY, 'addWeek'],
            'monthly' => [ScheduledComplianceReport::FREQUENCY_MONTHLY, 'addMonth'],
            'quarterly' => [ScheduledComplianceReport::FREQUENCY_QUARTERLY, 'addMonths3'],
        ];
    }

    #[Test]
    #[DataProvider('frequencyProvider')]
    public function compute_next_run_at_advances_by_frequency(string $frequency, string $methodHint): void
    {
        $schedule = ScheduledComplianceReport::factory()->frequency($frequency)->make();
        $from = Carbon::create(2026, 5, 3, 12);

        $next = $schedule->computeNextRunAt($from);

        $expected = match ($frequency) {
            'daily' => $from->copy()->addDay(),
            'weekly' => $from->copy()->addWeek(),
            'monthly' => $from->copy()->addMonth(),
            'quarterly' => $from->copy()->addMonths(3),
        };

        $this->assertTrue($expected->equalTo($next), "Expected {$expected} got {$next} for {$frequency}");
    }

    #[Test]
    public function compute_next_run_at_defaults_to_now_when_no_argument(): void
    {
        $schedule = ScheduledComplianceReport::factory()->frequency('daily')->make();

        $before = now();
        $next = $schedule->computeNextRunAt();
        $after = now();

        $this->assertTrue($next->between($before->copy()->addDay(), $after->copy()->addDay()->addSecond()));
    }

    #[Test]
    public function compute_next_run_at_throws_for_unknown_frequency(): void
    {
        $schedule = ScheduledComplianceReport::factory()->make(['frequency' => 'biweekly']);

        $this->expectException(InvalidArgumentException::class);
        $schedule->computeNextRunAt();
    }

    #[Test]
    public function due_scope_returns_only_active_and_past_due(): void
    {
        ScheduledComplianceReport::factory()->due()->create();
        ScheduledComplianceReport::factory()->due()->create();
        ScheduledComplianceReport::factory()->create(['next_run_at' => now()->addDay()]);
        ScheduledComplianceReport::factory()->due()->inactive()->create();

        $this->assertSame(2, ScheduledComplianceReport::query()->due()->count());
    }

    #[Test]
    public function for_organization_scope_filters_correctly(): void
    {
        $orgA = Organization::factory()->create();
        $orgB = Organization::factory()->create();
        ScheduledComplianceReport::factory()->count(2)->create(['organization_id' => $orgA->id]);
        ScheduledComplianceReport::factory()->count(3)->create(['organization_id' => $orgB->id]);

        $this->assertSame(2, ScheduledComplianceReport::query()->forOrganization($orgA->id)->count());
        $this->assertSame(3, ScheduledComplianceReport::query()->forOrganization($orgB->id)->count());
    }
}
