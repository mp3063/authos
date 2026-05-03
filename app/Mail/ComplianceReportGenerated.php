<?php

namespace App\Mail;

use App\Models\Organization;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Attachment;
use Illuminate\Queue\SerializesModels;

class ComplianceReportGenerated extends Mailable
{
    use Queueable;
    use SerializesModels;

    public function __construct(
        public Organization $organization,
        public string $reportType,
        public array $reportData,
        public string $downloadUrl,
        public ?string $pdfFilesystemPath = null,
        public ?string $jsonFilesystemPath = null,
    ) {}

    public function build(): self
    {
        $mail = $this->subject("Compliance Report Generated - {$this->reportType}")
            ->markdown('emails.compliance-report')
            ->with([
                'organization' => $this->organization,
                'reportType' => strtoupper($this->reportType),
                'reportData' => $this->reportData,
                'downloadUrl' => $this->downloadUrl,
                'generatedAt' => now()->format('M d, Y H:i'),
            ]);

        if ($this->pdfFilesystemPath !== null && is_file($this->pdfFilesystemPath)) {
            $mail->attach(Attachment::fromPath($this->pdfFilesystemPath)
                ->as("{$this->reportType}_report.pdf")
                ->withMime('application/pdf'));
        }

        if ($this->jsonFilesystemPath !== null && is_file($this->jsonFilesystemPath)) {
            $mail->attach(Attachment::fromPath($this->jsonFilesystemPath)
                ->as("{$this->reportType}_report.json")
                ->withMime('application/json'));
        }

        return $mail;
    }
}
