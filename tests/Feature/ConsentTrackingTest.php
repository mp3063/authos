<?php

namespace Tests\Feature;

use App\Models\DataSubjectRequest;
use App\Models\Organization;
use App\Models\User;
use App\Models\UserConsent;
use App\Services\Compliance\ConsentTrackingService;
use App\Services\ComplianceReportService;
use Database\Seeders\BackfillUserConsentsSeeder;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ConsentTrackingTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();
        $this->organization = Organization::factory()->create();
        $this->user = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
    }

    #[Test]
    public function record_consent_creates_or_updates_active_consent(): void
    {
        $service = app(ConsentTrackingService::class);

        $first = $service->recordConsent($this->user, UserConsent::TYPE_TERMS, 'v1.0', '127.0.0.1');
        $this->assertTrue($first->isActive());
        $this->assertSame('v1.0', $first->terms_version);

        // Re-recording the same type should update the existing row, not create another
        $second = $service->recordConsent($this->user, UserConsent::TYPE_TERMS, 'v1.1');
        $this->assertSame($first->id, $second->id);
        $this->assertSame('v1.1', $second->terms_version);
        $this->assertSame(1, UserConsent::query()->where('user_id', $this->user->id)->count());
    }

    #[Test]
    public function withdraw_consent_marks_existing_active_row(): void
    {
        $service = app(ConsentTrackingService::class);
        $service->recordConsent($this->user, UserConsent::TYPE_MARKETING);
        $service->withdrawConsent($this->user, UserConsent::TYPE_MARKETING);

        $consent = UserConsent::query()->where('user_id', $this->user->id)->first();
        $this->assertNotNull($consent->withdrawn_at);
        $this->assertFalse($service->hasActiveConsent($this->user, UserConsent::TYPE_MARKETING));
    }

    #[Test]
    public function recording_after_withdrawal_reactivates(): void
    {
        $service = app(ConsentTrackingService::class);
        $service->recordConsent($this->user, UserConsent::TYPE_MARKETING);
        $service->withdrawConsent($this->user, UserConsent::TYPE_MARKETING);
        $service->recordConsent($this->user, UserConsent::TYPE_MARKETING);

        $this->assertTrue($service->hasActiveConsent($this->user, UserConsent::TYPE_MARKETING));
        $this->assertSame(1, UserConsent::query()->where('user_id', $this->user->id)->count());
    }

    #[Test]
    public function consent_endpoint_persists_record(): void
    {
        $token = $this->createAccessToken($this->user, ['*']);

        $this->withToken($token)
            ->postJson('/api/v1/profile/consents', [
                'consent_type' => 'privacy',
                'terms_version' => 'v2.0',
            ])
            ->assertCreated()
            ->assertJsonPath('data.consent.consent_type', 'privacy');

        $this->assertDatabaseHas('user_consents', [
            'user_id' => $this->user->id,
            'consent_type' => 'privacy',
            'terms_version' => 'v2.0',
        ]);
    }

    #[Test]
    public function withdraw_endpoint_marks_consent_withdrawn(): void
    {
        $token = $this->createAccessToken($this->user, ['*']);
        UserConsent::factory()->create([
            'user_id' => $this->user->id,
            'organization_id' => $this->organization->id,
            'consent_type' => 'marketing',
        ]);

        $this->withToken($token)
            ->deleteJson('/api/v1/profile/consents/marketing')
            ->assertOk();

        $consent = UserConsent::query()->where('user_id', $this->user->id)->first();
        $this->assertNotNull($consent->withdrawn_at);
    }

    #[Test]
    public function withdraw_endpoint_rejects_unknown_type(): void
    {
        $token = $this->createAccessToken($this->user, ['*']);

        $this->withToken($token)
            ->deleteJson('/api/v1/profile/consents/zombie')
            ->assertStatus(400);
    }

    #[Test]
    public function data_request_endpoint_creates_pending_dsr(): void
    {
        $token = $this->createAccessToken($this->user, ['*']);

        $this->withToken($token)
            ->postJson('/api/v1/profile/data-requests', [
                'request_type' => 'access',
                'notes' => 'Please send all data',
            ])
            ->assertCreated()
            ->assertJsonPath('data.request.request_type', 'access')
            ->assertJsonPath('data.request.status', 'pending');

        $this->assertDatabaseHas('data_subject_requests', [
            'user_id' => $this->user->id,
            'organization_id' => $this->organization->id,
            'request_type' => 'access',
            'status' => 'pending',
        ]);
    }

    #[Test]
    public function consent_metrics_in_gdpr_report_reflect_real_counts(): void
    {
        // 5 active consents, 2 withdrawn, 1 DSR
        UserConsent::factory()->count(5)->create([
            'organization_id' => $this->organization->id,
            'user_id' => User::factory()->create(['organization_id' => $this->organization->id])->id,
        ]);
        UserConsent::factory()->withdrawn()->count(2)->create([
            'organization_id' => $this->organization->id,
        ]);
        DataSubjectRequest::factory()->ofType('access')->create([
            'organization_id' => $this->organization->id,
            'user_id' => $this->user->id,
        ]);

        $report = app(ComplianceReportService::class)->generateGDPRReport($this->organization);
        $consent = $report['consent_tracking'];

        $this->assertSame(5, $consent['total_consents_active']);
        $this->assertSame(2, $consent['total_consents_withdrawn']);
        $this->assertSame(1, $consent['data_subject_requests']['access']);
    }

    #[Test]
    public function backfill_seeder_creates_terms_consent_for_existing_users(): void
    {
        // Five users in the org, no consents yet
        User::factory()->count(5)->create(['organization_id' => $this->organization->id]);
        $this->assertSame(0, UserConsent::query()->count());

        $this->seed(BackfillUserConsentsSeeder::class);

        // 1 admin + 5 fresh users = 6 expected backfilled rows in this org
        $count = UserConsent::query()->where('organization_id', $this->organization->id)->count();
        $this->assertGreaterThanOrEqual(6, $count);
    }
}
