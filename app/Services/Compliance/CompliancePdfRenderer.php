<?php

namespace App\Services\Compliance;

use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Services\BrandingService;
use Barryvdh\DomPDF\Facade\Pdf;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;
use RuntimeException;

class CompliancePdfRenderer
{
    private const TEMPLATE_MAP = [
        'soc2' => 'compliance.soc2',
        'iso27001' => 'compliance.iso27001',
        'gdpr' => 'compliance.gdpr',
    ];

    public function __construct(
        private readonly BrandingService $branding,
    ) {}

    /**
     * Render a compliance report to PDF and save it to storage.
     * Returns the relative storage path (relative to disk('local')).
     */
    public function render(string $reportType, array $reportData, Organization $organization): string
    {
        $template = self::TEMPLATE_MAP[$reportType]
            ?? throw new InvalidArgumentException("Unknown compliance report type: {$reportType}");

        $branding = $this->branding->getBranding($organization);
        $logoFsPath = $this->resolveLogoPath($branding);

        $pdfBytes = Pdf::loadView($template, [
            'report' => $reportData,
            'organization' => $organization,
            'branding' => $branding,
            'logoPath' => $logoFsPath,
            'redactPii' => (bool) config('compliance.pdf.redact_pii', false),
            'generatedAt' => now(),
        ])->setPaper('a4')->output();

        $relativePath = sprintf(
            'compliance_reports/%d/%s_%s_%s.pdf',
            $organization->id,
            $reportType,
            now()->format('Ymd'),
            (string) Str::uuid(),
        );

        Storage::disk('local')->put($relativePath, $pdfBytes);

        if (! Storage::disk('local')->exists($relativePath)) {
            throw new RuntimeException("Failed to write PDF to storage: {$relativePath}");
        }

        return $relativePath;
    }

    /**
     * Convert the branding logo to an absolute filesystem path.
     * DomPDF cannot reliably fetch HTTPS URLs (and remote-fetching is an
     * SSRF risk we explicitly do not enable), so we always read from disk.
     */
    private function resolveLogoPath(?OrganizationBranding $branding): ?string
    {
        if ($branding?->logo_path === null) {
            return null;
        }

        $publicDisk = Storage::disk('public');
        $candidate = $publicDisk->path($branding->logo_path);

        return file_exists($candidate) ? $candidate : null;
    }
}
