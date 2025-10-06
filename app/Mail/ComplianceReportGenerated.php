<?php

namespace App\Mail;

use App\Models\Organization;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class ComplianceReportGenerated extends Mailable
{
    use Queueable;
    use SerializesModels;

    public function __construct(
        public Organization $organization,
        public string $reportType,
        public array $reportData,
        public string $downloadUrl
    ) {}

    public function build(): self
    {
        return $this->subject("Compliance Report Generated - {$this->reportType}")
            ->markdown('emails.compliance-report')
            ->with([
                'organization' => $this->organization,
                'reportType' => strtoupper($this->reportType),
                'reportData' => $this->reportData,
                'downloadUrl' => $this->downloadUrl,
                'generatedAt' => now()->format('M d, Y H:i'),
            ]);
    }
}
