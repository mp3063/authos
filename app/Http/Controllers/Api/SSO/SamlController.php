<?php

namespace App\Http\Controllers\Api\SSO;

use App\Http\Controllers\Controller;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use App\Services\Saml\SamlMessageBuilder;
use App\Services\Saml\SamlSignatureValidator;
use App\Services\SamlService;
use App\Services\SSO\SsoSessionManager;
use App\Services\SSOService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class SamlController extends Controller
{
    public function __construct(
        protected SSOService $ssoService,
        protected SamlService $samlService,
        protected SamlSignatureValidator $signatureValidator,
        protected SamlMessageBuilder $messageBuilder,
        protected SsoSessionManager $sessions,
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
                $request->RelayState
            );

            return response()->json([
                'success' => true,
                'user' => $result['user'],
                'session' => $result['session'],
                'application' => $result['application'] ?? [
                    'id' => $result['session']['application_id'] ?? null,
                    'name' => $result['session']['application_name'] ?? 'Unknown Application',
                ],
                'tokens' => $result['tokens'] ?? [],
            ]);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
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
            return response('<Error>'.$e->getMessage().'</Error>', 404, [
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

                // Find user by NameID and revoke sessions
                $user = User::where('email', $logoutData['name_id'])->first();

                if ($user) {
                    $this->sessions->revokeUserSessions($user->id);
                }

                // Find the SSO config to get SP entity ID for the response
                $ssoConfig = null;
                if ($logoutData['issuer']) {
                    $ssoConfig = SSOConfiguration::where('is_active', true)
                        ->whereJsonContains('configuration->idp_entity_id', $logoutData['issuer'])
                        ->first();
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
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
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

            // Find the SSO configuration by IdP issuer
            $ssoConfig = null;
            if ($userInfo['issuer']) {
                $ssoConfig = SSOConfiguration::where('is_active', true)
                    ->where(function ($providerQuery) {
                        $providerQuery->where('provider', 'saml2')->orWhere('provider', 'saml');
                    })
                    ->get()
                    ->first(function ($config) use ($userInfo) {
                        $idpEntityId = $config->configuration['idp_entity_id']
                            ?? $config->settings['saml_entity_id']
                            ?? null;

                        return $idpEntityId === $userInfo['issuer'];
                    });
            }

            if (! $ssoConfig) {
                // Fall back to finding by application in RelayState
                return response()->json([
                    'success' => false,
                    'message' => 'No SAML configuration found for IdP: '.($userInfo['issuer'] ?? 'unknown'),
                ], 400);
            }

            $x509Cert = $ssoConfig->configuration['x509_cert']
                ?? $ssoConfig->settings['x509_cert']
                ?? null;

            $this->signatureValidator->validate($samlResponse, $x509Cert);

            // Validate time conditions
            if (! empty($userInfo['conditions'])) {
                $this->samlService->validateConditions($userInfo['conditions']);
            }

            // Apply attribute mapping
            $userInfo = $this->samlService->applyAttributeMapping($userInfo, $ssoConfig);

            // Find or match user
            $user = User::where('email', $userInfo['email'])->first();
            if (! $user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found for SAML assertion email: '.$userInfo['email'],
                ], 404);
            }

            $application = $ssoConfig->application;

            // Create SSO session
            $session = SSOSession::create([
                'user_id' => $user->id,
                'application_id' => $application->id,
                'ip_address' => $request->ip() ?? '127.0.0.1',
                'user_agent' => $request->userAgent() ?? 'SAML IdP-Initiated',
                'expires_at' => now()->addSeconds($ssoConfig->getSessionLifetimeInSeconds()),
                'metadata' => [
                    'flow' => 'idp_initiated',
                    'issuer' => $userInfo['issuer'],
                    'session_index' => $userInfo['session_index'],
                    'name_id' => $userInfo['name_id'],
                ],
            ]);

            return response()->json([
                'success' => true,
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'session' => [
                    'id' => $session->id,
                    'session_token' => $session->session_token,
                    'expires_at' => $session->expires_at->toISOString(),
                ],
                'application' => [
                    'id' => $application->id,
                    'name' => $application->name,
                ],
                'tokens' => [
                    'access_token' => $session->session_token,
                    'token_type' => 'Bearer',
                    'expires_in' => $session->expires_at->timestamp - now()->timestamp,
                ],
            ]);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => $e->getMessage(),
            ], 400);
        }
    }
}
