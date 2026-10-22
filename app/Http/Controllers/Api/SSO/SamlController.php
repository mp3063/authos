<?php

namespace App\Http\Controllers\Api\SSO;

use App\Http\Controllers\Controller;
use App\Models\SSOConfiguration;
use App\Models\User;
use App\Services\Saml\SamlMessageBuilder;
use App\Services\Saml\SamlSignatureValidator;
use App\Services\SamlService;
use App\Services\SSO\SsoSessionIssuer;
use App\Services\SSO\SsoSessionManager;
use App\Services\SSOService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;

class SamlController extends Controller
{
    public function __construct(
        protected SSOService $ssoService,
        protected SamlService $samlService,
        protected SamlSignatureValidator $signatureValidator,
        protected SamlMessageBuilder $messageBuilder,
        protected SsoSessionManager $sessions,
        protected SsoSessionIssuer $sessionIssuer,
    ) {}

    /**
     * Handle SAML callback
     */
    public function samlCallback(Request $request): JsonResponse
    {
        $request->validate([
            'SAMLResponse' => 'required|string',
            'RelayState' => 'sometimes|string',
        ]);

        try {
            $result = $this->ssoService->processSamlCallback(
                $request->SAMLResponse,
                $request->RelayState,
                $request->url()
            );

            $challengeResponse = $this->sessionIssuer->challengeResponse($result);
            if ($challengeResponse) {
                return $challengeResponse;
            }

            return response()->json([
                'success' => true,
                'user' => $result['user'],
                'session' => $result['session'],
                'application' => $result['application'],
                'tokens' => $result['tokens'],
            ]);

        } catch (Exception $e) {
            Log::warning('SAML authentication rejected', ['reason' => $e->getMessage()]);

            return response()->json([
                'success' => false,
                'message' => 'SAML authentication failed',
            ], 400);
        }
    }

    /**
     * Get SP metadata XML for SAML configuration
     */
    public function spMetadata(string $organizationSlug): Response
    {
        try {
            $metadata = $this->ssoService->getOrganizationMetadata($organizationSlug);
            $organization = $metadata['organization'];

            // Find SAML SSO configuration for this organization
            $ssoConfig = SSOConfiguration::whereHas('application', function ($query) use ($organization) {
                $query->where('organization_id', $organization->id);
            })->where('is_active', true)
                ->where(function ($providerQuery) {
                    $providerQuery->where('provider', 'saml2')->orWhere('provider', 'saml');
                })
                ->first();

            if (! $ssoConfig) {
                return response('No active SAML configuration found', 404);
            }

            $baseUrl = config('app.url', url('/'));
            $metadataXml = $this->messageBuilder->generateSpMetadataFromConfig($ssoConfig, $baseUrl);

            return response($metadataXml, 200, [
                'Content-Type' => 'application/xml',
                'Cache-Control' => 'public, max-age=3600',
            ]);
        } catch (Exception $e) {
            return response('<Error>SAML metadata not found</Error>', 404, [
                'Content-Type' => 'application/xml',
            ]);
        }
    }

    /**
     * Handle SAML Single Logout (SLO) request
     */
    public function sloEndpoint(Request $request): JsonResponse|Response
    {
        try {
            $samlRequest = $request->input('SAMLRequest');
            $samlResponse = $request->input('SAMLResponse');
            $relayState = $request->input('RelayState');

            if ($samlRequest) {
                // IdP-initiated logout - parse LogoutRequest and revoke sessions
                $logoutData = $this->samlService->parseLogoutRequest($samlRequest);

                $ssoConfig = $this->findSamlConfigurationForIssuer(
                    $logoutData['issuer'],
                    fn (?string $x509Cert) => $this->signatureValidator->validateLogoutRequest($samlRequest, $x509Cert)
                );
                if (! $ssoConfig) {
                    Log::warning('SAML single logout rejected', ['reason' => 'No SAML configuration found for IdP', 'issuer' => $logoutData['issuer'] ?? null]);

                    return response()->json([
                        'success' => false,
                        'message' => 'No SAML configuration found for IdP',
                    ], 400);
                }

                $this->samlService->validateLogoutRequest($logoutData, $request->url());

                $user = User::where('organization_id', $ssoConfig->application->organization_id)
                    ->where('email', $logoutData['name_id'])
                    ->first();

                if ($user) {
                    $this->sessions->revokeUserSessions($user->id, $ssoConfig->application_id);
                }

                $spEntityId = $ssoConfig->configuration['sp_entity_id'] ?? config('app.url');
                $destination = $ssoConfig->configuration['idp_slo_url']
                    ?? $ssoConfig->settings['saml_sls_url']
                    ?? $logoutData['issuer'].'/slo';

                // Generate LogoutResponse
                $logoutResponseXml = $this->messageBuilder->generateLogoutResponse(
                    $logoutData['request_id'],
                    $spEntityId,
                    $destination
                );

                return response()->json([
                    'success' => true,
                    'message' => 'Logout processed',
                    'SAMLResponse' => base64_encode($logoutResponseXml),
                    'RelayState' => $relayState,
                    'destination' => $destination,
                ]);
            }

            if ($samlResponse) {
                // Response to our LogoutRequest (SP-initiated logout completed)
                return response()->json([
                    'success' => true,
                    'message' => 'Single logout completed',
                ]);
            }

            return response()->json([
                'success' => false,
                'message' => 'Missing SAMLRequest or SAMLResponse parameter',
            ], 400);
        } catch (Exception $e) {
            Log::warning('SAML single logout rejected', ['reason' => $e->getMessage()]);

            return response()->json([
                'success' => false,
                'message' => 'Single logout failed',
            ], 400);
        }
    }

    /**
     * Handle IdP-initiated SAML SSO (Assertion Consumer Service)
     */
    public function idpInitiatedSso(Request $request): JsonResponse
    {
        $request->validate([
            'SAMLResponse' => 'required|string',
            'RelayState' => 'sometimes|string',
        ]);

        try {
            $samlResponse = $request->SAMLResponse;

            // Parse the assertion to get user info and issuer
            $userInfo = $this->samlService->parseAssertion($samlResponse);

            $ssoConfig = $this->findSamlConfigurationForIssuer(
                $userInfo['issuer'],
                fn (?string $x509Cert) => $this->signatureValidator->validate($samlResponse, $x509Cert)
            );

            if (! $ssoConfig) {
                Log::warning('SAML authentication rejected', ['reason' => 'No SAML configuration found for IdP', 'issuer' => $userInfo['issuer'] ?? null]);

                return response()->json([
                    'success' => false,
                    'message' => 'No SAML configuration found for IdP',
                ], 400);
            }

            $this->samlService->validateAssertion($userInfo, $ssoConfig, $request->url());

            // Apply attribute mapping
            $userInfo = $this->samlService->applyAttributeMapping($userInfo, $ssoConfig);

            $application = $ssoConfig->application;

            // Find or match user
            $user = User::where('organization_id', $application->organization_id)
                ->where('email', $userInfo['email'])
                ->first();
            if (! $user) {
                Log::warning('SAML authentication rejected', ['reason' => 'User not found for SAML assertion', 'email' => $userInfo['email']]);

                return response()->json([
                    'success' => false,
                    'message' => 'User not found for SAML assertion',
                ], 404);
            }

            $attributes = [
                'ip_address' => $request->ip() ?? '127.0.0.1',
                'user_agent' => $request->userAgent() ?? 'SAML IdP-Initiated',
                'new_session' => true,
                'metadata' => [
                    'flow' => 'idp_initiated',
                    'issuer' => $userInfo['issuer'],
                    'session_index' => $userInfo['session_index'],
                    'name_id' => $userInfo['name_id'],
                ],
            ];

            $result = $user->requiresMfa()
                ? $this->sessionIssuer->challenge($user, $ssoConfig, $attributes)
                : $this->sessionIssuer->issue($user, $ssoConfig, $attributes);

            return $this->sessionIssuer->challengeResponse($result) ?? response()->json($result);
        } catch (Exception $e) {
            Log::warning('SAML authentication rejected', ['reason' => $e->getMessage()]);

            return response()->json([
                'success' => false,
                'message' => 'SAML authentication failed',
            ], 400);
        }
    }

    /**
     * Find the active SAML configuration for the issuer whose IdP certificate verifies the message's signature.
     *
     * @param  callable(?string): mixed  $verifySignature
     *
     * @throws Exception when configurations match the issuer but none of their certificates verifies the signature
     */
    private function findSamlConfigurationForIssuer(?string $issuer, callable $verifySignature): ?SSOConfiguration
    {
        if (! $issuer) {
            return null;
        }

        $candidates = SSOConfiguration::with('application')
            ->where('is_active', true)
            ->where(function ($providerQuery) {
                $providerQuery->where('provider', 'saml2')->orWhere('provider', 'saml');
            })
            ->get()
            ->filter(function ($config) use ($issuer) {
                $idpEntityId = $config->configuration['idp_entity_id']
                    ?? $config->settings['saml_entity_id']
                    ?? null;

                return $idpEntityId === $issuer;
            });

        $lastFailure = null;
        foreach ($candidates as $config) {
            try {
                $verifySignature($config->configuration['x509_cert'] ?? $config->settings['x509_cert'] ?? null);

                return $config;
            } catch (Exception $e) {
                $lastFailure = $e;
            }
        }

        if ($lastFailure) {
            throw $lastFailure;
        }

        return null;
    }
}
