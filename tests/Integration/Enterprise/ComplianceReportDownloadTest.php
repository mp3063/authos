<?php

namespace Tests\Integration\Enterprise;

use App\Models\ComplianceReport;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Storage;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ComplianceReportDownloadTest extends IntegrationTestCase
{
    private Organization $organization;

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();
        Storage::fake('local');
        $this->organization = Organization::factory()->create();
        $this->admin = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
    }

    private function makeCompletedReport(array $overrides = []): ComplianceReport
    {
        $orgId = $overrides['organization_id'] ?? $this->organization->id;
        $type = $overrides['report_type'] ?? 'soc2';
        $pdfPath = "compliance_reports/{$orgId}/{$type}_20260503_test.pdf";
        $jsonPath = "compliance_reports/{$orgId}/{$type}_20260503_test.json";

        Storage::disk('local')->put($pdfPath, '%PDF-1.4 fake bytes for test');
        Storage::disk('local')->put($jsonPath, json_encode(['report_type' => strtoupper($type)]));

        return ComplianceReport::factory()->create(array_merge([
            'organization_id' => $orgId,
            'report_type' => $type,
            'status' => ComplianceReport::STATUS_COMPLETED,
            'file_path_pdf' => $pdfPath,
            'file_path_json' => $jsonPath,
            'generated_at' => now(),
            'expires_at' => now()->addDays(180),
        ], $overrides));
    }

    #[Test]
    public function list_endpoint_returns_paginated_org_scoped_reports(): void
    {
        ComplianceReport::factory()->count(3)->completed()->create(['organization_id' => $this->organization->id]);
        ComplianceReport::factory()->count(2)->completed()->create();

        $token = $this->createAccessToken($this->admin, ['*']);

        $response = $this->withToken($token)->getJson('/api/v1/enterprise/compliance/reports');

        $response->assertOk();
        $this->assertCount(3, $response->json('data.reports'));
        $this->assertSame(3, $response->json('data.pagination.total'));
    }

    #[Test]
    public function list_endpoint_supports_type_and_status_filters(): void
    {
        ComplianceReport::factory()->count(2)->completed()->create([
            'organization_id' => $this->organization->id,
            'report_type' => 'soc2',
        ]);
        ComplianceReport::factory()->failed()->create([
            'organization_id' => $this->organization->id,
            'report_type' => 'gdpr',
        ]);

        $token = $this->createAccessToken($this->admin, ['*']);

        $soc2Only = $this->withToken($token)->getJson('/api/v1/enterprise/compliance/reports?report_type=soc2');
        $this->assertCount(2, $soc2Only->json('data.reports'));

        $failedOnly = $this->withToken($token)->getJson('/api/v1/enterprise/compliance/reports?status=failed');
        $this->assertCount(1, $failedOnly->json('data.reports'));
    }

    #[Test]
    public function download_serves_pdf_with_correct_content_type(): void
    {
        $report = $this->makeCompletedReport();
        $token = $this->createAccessToken($this->admin, ['*']);

        $response = $this->withToken($token)->get("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=pdf");

        $response->assertOk();
        $response->assertHeader('Content-Type', 'application/pdf');
        $this->assertStringStartsWith('%PDF-', $response->streamedContent());
    }

    #[Test]
    public function download_serves_json_format(): void
    {
        $report = $this->makeCompletedReport();
        $token = $this->createAccessToken($this->admin, ['*']);

        $response = $this->withToken($token)->get("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=json");

        $response->assertOk();
        $response->assertHeader('Content-Type', 'application/json');
        $decoded = json_decode($response->streamedContent(), true);
        $this->assertSame('SOC2', $decoded['report_type']);
    }

    #[Test]
    public function download_rejects_invalid_format(): void
    {
        $report = $this->makeCompletedReport();
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=docx")
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_format');
    }

    #[Test]
    public function download_returns_410_for_expired_reports(): void
    {
        $report = $this->makeCompletedReport(['expires_at' => now()->subDay()]);
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download")
            ->assertStatus(410)
            ->assertJsonPath('error', 'report_expired');
    }

    #[Test]
    public function download_returns_400_when_report_not_completed(): void
    {
        $report = ComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => ComplianceReport::STATUS_GENERATING,
        ]);
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download")
            ->assertStatus(400)
            ->assertJsonPath('error', 'report_not_ready');
    }

    #[Test]
    public function cross_org_download_returns_404(): void
    {
        $foreignReport = $this->makeCompletedReport(['organization_id' => Organization::factory()->create()->id]);
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$foreignReport->id}/download")
            ->assertStatus(404);
    }

    #[Test]
    public function download_returns_404_when_storage_file_missing(): void
    {
        // Create report row but never put the file on storage.
        $report = ComplianceReport::factory()->create([
            'organization_id' => $this->organization->id,
            'status' => ComplianceReport::STATUS_COMPLETED,
            'file_path_pdf' => "compliance_reports/{$this->organization->id}/missing.pdf",
            'file_path_json' => "compliance_reports/{$this->organization->id}/missing.json",
            'generated_at' => now(),
            'expires_at' => now()->addDay(),
        ]);
        $token = $this->createAccessToken($this->admin, ['*']);

        $this->withToken($token)
            ->getJson("/api/v1/enterprise/compliance/reports/{$report->id}/download?format=pdf")
            ->assertStatus(404)
            ->assertJsonPath('error', 'file_not_found');
    }
}
