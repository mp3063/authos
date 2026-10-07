<?php

namespace App\Http\Controllers\Api\SSO;

use App\Http\Controllers\Controller;
use App\Models\SSOConfiguration;
use App\Services\Saml\SamlCertificate;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class SamlCertificateController extends Controller
{
    /**
     * Upload/update SAML certificate for an SSO configuration
     */
    public function updateSamlCertificate(Request $request, int $configId): JsonResponse
    {
        $request->validate([
            'x509_cert' => 'required|string',
            'cert_type' => 'sometimes|string|in:idp,sp',
        ]);

        try {
            $ssoConfig = SSOConfiguration::findOrFail($configId);
            $certType = $request->input('cert_type', 'idp');

            $configuration = $ssoConfig->configuration ?? [];
            $certKey = $certType === 'sp' ? 'sp_x509_cert' : 'x509_cert';
            $configuration[$certKey] = $request->x509_cert;
            $configuration[$certKey.'_uploaded_at'] = now()->toISOString();

            $ssoConfig->update(['configuration' => $configuration]);

            return response()->json([
                'success' => true,
                'message' => strtoupper($certType).' certificate updated successfully',
                'cert_type' => $certType,
                'uploaded_at' => $configuration[$certKey.'_uploaded_at'],
            ]);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * View SAML certificate info for an SSO configuration
     */
    public function viewSamlCertificate(int $configId): JsonResponse
    {
        try {
            $ssoConfig = SSOConfiguration::findOrFail($configId);
            $configuration = $ssoConfig->configuration ?? [];

            $certs = [];
            foreach (['x509_cert' => 'idp', 'sp_x509_cert' => 'sp'] as $key => $type) {
                if (! empty($configuration[$key])) {
                    $certInfo = ['type' => $type, 'present' => true];
                    $certInfo['uploaded_at'] = $configuration[$key.'_uploaded_at'] ?? null;

                    // Try to parse certificate for details
                    $certData = openssl_x509_parse(SamlCertificate::toPem($configuration[$key]));
                    if ($certData) {
                        $certInfo['subject'] = $certData['subject']['CN'] ?? 'Unknown';
                        $certInfo['issuer'] = $certData['issuer']['CN'] ?? 'Unknown';
                        $certInfo['valid_from'] = date('Y-m-d H:i:s', $certData['validFrom_time_t']);
                        $certInfo['valid_to'] = date('Y-m-d H:i:s', $certData['validTo_time_t']);
                        $certInfo['expired'] = $certData['validTo_time_t'] < time();
                    }

                    $certs[] = $certInfo;
                }
            }

            return response()->json([
                'success' => true,
                'certificates' => $certs,
            ]);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Rotate SAML certificate (replace with new one)
     */
    public function rotateSamlCertificate(Request $request, int $configId): JsonResponse
    {
        $request->validate([
            'new_x509_cert' => 'required|string',
            'cert_type' => 'sometimes|string|in:idp,sp',
        ]);

        try {
            $ssoConfig = SSOConfiguration::findOrFail($configId);
            $certType = $request->input('cert_type', 'idp');

            $configuration = $ssoConfig->configuration ?? [];
            $certKey = $certType === 'sp' ? 'sp_x509_cert' : 'x509_cert';

            // Store previous cert for rollback
            $configuration[$certKey.'_previous'] = $configuration[$certKey] ?? null;
            $configuration[$certKey] = $request->new_x509_cert;
            $configuration[$certKey.'_rotated_at'] = now()->toISOString();
            $configuration[$certKey.'_uploaded_at'] = now()->toISOString();

            $ssoConfig->update(['configuration' => $configuration]);

            return response()->json([
                'success' => true,
                'message' => strtoupper($certType).' certificate rotated successfully',
                'cert_type' => $certType,
                'rotated_at' => $configuration[$certKey.'_rotated_at'],
                'has_previous' => ! empty($configuration[$certKey.'_previous']),
            ]);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }
}
