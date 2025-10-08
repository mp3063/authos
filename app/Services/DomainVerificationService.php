<?php

namespace App\Services;

use App\Models\CustomDomain;
use App\Models\Organization;
use Exception;
use Illuminate\Support\Facades\Log;

class DomainVerificationService
{
    /**
     * Add domain and generate verification code
     * Returns array format for API compatibility
     */
    public function addDomain(int|Organization $organizationId, string $domain): CustomDomain
    {
        // Accept both int and Organization object for flexibility
        $orgId = $organizationId instanceof Organization ? $organizationId->id : $organizationId;

        // Check for duplicates
        $existing = CustomDomain::where('organization_id', $orgId)
            ->where('domain', strtolower($domain))
            ->first();

        if ($existing) {
            throw new Exception('Domain already exists');
        }

        return CustomDomain::create([
            'organization_id' => $orgId,
            'domain' => strtolower($domain),
            'status' => 'pending',
            'verification_code' => CustomDomain::generateVerificationCode(),
            'verification_method' => 'dns',
            'is_active' => false,
        ]);
    }

    /**
     * Create a new custom domain
     */
    public function createDomain(Organization $organization, string $domain): CustomDomain
    {
        return CustomDomain::create([
            'organization_id' => $organization->id,
            'domain' => strtolower($domain),
            'status' => 'pending',
            'verification_code' => CustomDomain::generateVerificationCode(),
            'verification_method' => 'dns',
            'is_active' => false,
        ]);
    }

    /**
     * Get DNS records for domain (TXT and A/CNAME)
     */
    public function getDnsRecords(CustomDomain $domain): array
    {
        return $domain->getVerificationDnsRecords();
    }

    /**
     * Generate a verification code (32-char hex)
     */
    public function generateVerificationCode(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Check DNS TXT record for verification code
     */
    public function checkDnsTxtRecord(string $domain, string $expectedValue): bool
    {
        try {
            $txtRecords = $this->getDnsTxtRecords($domain);

            foreach ($txtRecords as $record) {
                if (str_contains($record, $expectedValue)) {
                    return true;
                }
            }

            return false;
        } catch (Exception $e) {
            Log::error('DNS TXT record check failed', [
                'domain' => $domain,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Verify domain ownership via DNS TXT record
     * Accepts domain ID or CustomDomain model for flexibility
     */
    public function verifyDomain(int|CustomDomain $domainId): array
    {
        try {
            $domain = $domainId instanceof CustomDomain ? $domainId : CustomDomain::findOrFail($domainId);
            $verified = $this->checkDnsTxtRecord($domain->domain, $domain->verification_code);

            if ($verified) {
                $domain->update([
                    'status' => 'verified',
                    'verified_at' => now(),
                    'is_active' => true,
                    'dns_records' => [
                        'txt_records' => $this->getDnsTxtRecords($domain->domain),
                        'verified_at' => now()->toISOString(),
                    ],
                ]);

                Log::info('Domain verified successfully', [
                    'domain' => $domain->domain,
                    'organization_id' => $domain->organization_id,
                ]);

                return [
                    'success' => true,
                    'verified' => true,
                    'message' => 'Domain verified successfully',
                ];
            }

            Log::warning('Domain verification failed - code not found', [
                'domain' => $domain->domain,
                'expected_code' => $domain->verification_code,
            ]);

            return [
                'success' => false,
                'verified' => false,
                'message' => 'DNS TXT record not found',
            ];
        } catch (Exception $e) {
            Log::error('Domain verification failed', [
                'domain_id' => $domainId,
                'error' => $e->getMessage(),
            ]);

            return [
                'success' => false,
                'verified' => false,
                'message' => 'Verification failed: '.$e->getMessage(),
            ];
        }
    }

    /**
     * Get DNS TXT records for a domain
     */
    private function getDnsTxtRecords(string $domain): array
    {
        // Try to get DNS records using dns_get_record
        $records = @dns_get_record("_authos-verify.$domain", DNS_TXT);

        if ($records === false) {
            // Fallback: try without subdomain prefix
            $records = @dns_get_record($domain, DNS_TXT);
        }

        if ($records === false || empty($records)) {
            return [];
        }

        $txtRecords = [];
        foreach ($records as $record) {
            if (isset($record['txt'])) {
                $txtRecords[] = $record['txt'];
            }
        }

        return $txtRecords;
    }

    /**
     * Get verification instructions for domain
     */
    public function getVerificationInstructions(CustomDomain $domain): array
    {
        $dnsRecords = $domain->getVerificationDnsRecords();

        return [
            'domain' => $domain->domain,
            'verification_code' => $domain->verification_code,
            'dns_records' => $dnsRecords,
            'instructions' => [
                'step_1' => 'Log in to your DNS provider',
                'step_2' => 'Add the following TXT record:',
                'txt_record' => [
                    'type' => 'TXT',
                    'name' => '_authos-verify',
                    'value' => $domain->verification_code,
                    'ttl' => 3600,
                ],
                'step_3' => 'Wait for DNS propagation (usually 5-30 minutes)',
                'step_4' => 'Click "Verify Domain" to complete verification',
            ],
            'verification_check_url' => route('api.enterprise.domains.verify', $domain->id),
        ];
    }

    /**
     * Check SSL certificate for domain
     */
    public function checkSslCertificate(CustomDomain $domain): array
    {
        try {
            $url = "https://{$domain->domain}";
            $stream = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                ],
            ]);

            $client = @stream_socket_client(
                "ssl://{$domain->domain}:443",
                $errno,
                $errstr,
                30,
                STREAM_CLIENT_CONNECT,
                $stream
            );

            if ($client === false) {
                return [
                    'success' => false,
                    'message' => "SSL connection failed: $errstr",
                ];
            }

            $params = stream_context_get_params($client);
            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);

            fclose($client);

            $domain->update([
                'ssl_certificate' => [
                    'issuer' => $cert['issuer']['CN'] ?? 'Unknown',
                    'subject' => $cert['subject']['CN'] ?? 'Unknown',
                    'valid_from' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
                    'valid_to' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
                    'checked_at' => now()->toISOString(),
                ],
            ]);

            return [
                'success' => true,
                'certificate' => $domain->ssl_certificate,
            ];
        } catch (Exception $e) {
            Log::error('SSL certificate check failed', [
                'domain' => $domain->domain,
                'error' => $e->getMessage(),
            ]);

            return [
                'success' => false,
                'message' => 'Certificate check failed: '.$e->getMessage(),
            ];
        }
    }

    /**
     * Remove domain and cleanup
     */
    public function removeDomain(CustomDomain $domain): bool
    {
        // Log domain removal
        Log::info('Custom domain removed', [
            'domain' => $domain->domain,
            'organization_id' => $domain->organization_id,
        ]);

        return $domain->delete();
    }

    /**
     * Configure SSL certificate for domain
     */
    public function configureSsl(CustomDomain $domain, array $certificate): CustomDomain
    {
        $domain->update([
            'ssl_certificate' => $certificate,
        ]);

        Log::info('SSL certificate configured', [
            'domain' => $domain->domain,
            'organization_id' => $domain->organization_id,
        ]);

        return $domain->fresh();
    }

    /**
     * Regenerate verification code
     */
    public function regenerateVerificationCode(CustomDomain $domain): CustomDomain
    {
        $domain->update([
            'verification_code' => CustomDomain::generateVerificationCode(),
            'status' => 'pending',
            'verified_at' => null,
            'is_active' => false,
        ]);

        return $domain->fresh();
    }
}
