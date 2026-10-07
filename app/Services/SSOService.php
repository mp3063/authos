<?php

namespace App\Services;

use App\Models\Application;
use App\Models\Organization;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use App\Services\Saml\SamlSignatureValidator;
use App\Services\SSO\SsoAccessPolicy;
use App\Services\SSO\SsoSessionManager;
use Exception;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class SSOService
{
    public function __construct(
        protected SamlService $samlService,
        protected SamlSignatureValidator $signatureValidator,
        protected SsoSessionManager $sessions,
        protected SsoAccessPolicy $accessPolicy,
    ) {}

    /**
     * Initiate SSO flow for an application
     *
     * @throws Exception
     */
    public function initiateSSOFlow(int $userId, int $applicationId, int $ssoConfigId, ?string $redirectUri = null): array
    {
        $user = User::findOrFail($userId);
        /** @var User $user */
        $application = Application::findOrFail($applicationId);
        /** @var Application $application */
        $ssoConfig = SSOConfiguration::findOrFail($ssoConfigId);

        // Check if config is active first
        if (! $ssoConfig->is_active) {
            throw new Exception('SSO configuration is not active');
        }

        // Validate redirect URI if provided
        if ($redirectUri && ! $this->accessPolicy->isValidRedirectUri($redirectUri, $ssoConfig)) {
            throw ValidationException::withMessages([
                'redirect_uri' => ['Invalid redirect URI for this SSO configuration'],
            ]);
        }

        // Check organization match by comparing config's application's organization with user's organization
        $ssoConfigApplication = $ssoConfig->application;
        if ($user->organization_id !== $ssoConfigApplication->organization_id) {
            throw new Exception('SSO configuration does not belong to the same organization');
        }

        if ($ssoConfig->application_id !== $applicationId) {
            throw new Exception('SSO configuration does not belong to this application');
        }

        // Check user access
        if (! $this->accessPolicy->userCanAccessApplication($user, $application)) {
            throw new Exception('User does not have access to this application');
        }

        // Create or update session
        $session = $this->sessions->createOrUpdateSession($user, $application, request()->ip() ?? '127.0.0.1', request()->userAgent() ?? 'test');

        // Generate state parameter for CSRF protection
        $state = Str::random(32);

        // Get authorization endpoint from configuration
        $configuration = $ssoConfig->configuration ?? $ssoConfig->settings ?? [];
        $authEndpoint = $configuration['authorization_endpoint'] ?? $ssoConfig->callback_url;

        // Determine allowed scopes based on application configuration
        $allowedScopes = $this->accessPolicy->getAllowedScopes($application, $ssoConfig);

        // Generate redirect URL with filtered scopes
        $redirectUrl = $authEndpoint.'?'.http_build_query([
            'client_id' => $application->client_id ?? $application->id,
            'response_type' => 'code',
            'scope' => implode(' ', $allowedScopes),
            'redirect_uri' => $redirectUri ?? $ssoConfig->callback_url,
            'state' => $state,
        ]);

        // Store state in session metadata and external_session_id for callback lookup
        // Include MFA status if required by organization
        $metadata = [
            'state' => $state,
            'redirect_uri' => $redirectUri ?? $ssoConfig->callback_url,
            'scopes' => $allowedScopes,
        ];

        // Add MFA status if MFA is enabled for user/organization
        $orgMfaRequired = $user->organization && is_array($user->organization->settings) && (($user->organization->settings['mfa_required'] ?? false));

        if ($user->mfa_enabled || $orgMfaRequired) {
            $metadata['mfa_verified'] = $user->mfa_enabled;
        }

        // Update external_session_id and metadata separately to avoid guarded attribute issues
        $session->external_session_id = $state;
        $this->sessions->updateSessionMetadata($session, $metadata);

        return [
            'redirect_url' => $redirectUrl,
            'session_token' => $session->session_token,
            'state' => $state,
            'expires_at' => $session->expires_at->toISOString(),
        ];
    }

    /**
     * Initiate SSO flow for an application (legacy method)
     *
     * @throws Exception
     * @throws ValidationException
     */
    public function initiateSSO(
        int $applicationId,
        string $redirectUri,
        User $user,
        string $ipAddress,
        string $userAgent
    ): array {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);
        /** @var Application $application */
        if (! $application->hasSSOEnabled()) {
            throw new Exception('SSO is not enabled for this application');
        }

        $ssoConfig = $application->ssoConfiguration;

        // Validate redirect URI
        if (! $this->accessPolicy->isValidRedirectUri($redirectUri, $ssoConfig)) {
            throw ValidationException::withMessages([
                'redirect_uri' => 'Invalid redirect URI for this application',
            ]);
        }

        // Check if user has access to this application
        if (! $this->accessPolicy->userCanAccessApplication($user, $application)) {
            throw new Exception('User does not have access to this application');
        }

        // Create or update SSO session
        $session = $this->sessions->createOrUpdateSession($user, $application, $ipAddress, $userAgent);

        // Generate authorization code (temporary)
        $authCode = Str::random(32);

        // Store auth code in session metadata for validation
        $this->sessions->updateSessionMetadata($session, [
            'auth_code' => $authCode,
            'auth_code_expires' => now()->addMinutes(10)->timestamp,
            'redirect_uri' => $redirectUri,
        ]);

        return [
            'auth_code' => $authCode,
            'redirect_uri' => $redirectUri,
            'expires_in' => 600, // 10 minutes
            'state' => $session->session_token,
        ];
    }

    /**
     * Validate callback and exchange auth code for session token
     *
     * @throws Exception
     */
    public function validateCallback(
        string $authCode,
        int $applicationId,
        ?string $redirectUri = null
    ): array {
        Application::findOrFail($applicationId);

        // Find session with this auth code
        $session = SSOSession::where('application_id', $applicationId)
            ->whereJsonContains('metadata->auth_code', $authCode)
            ->active()
            ->first();

        if (! $session) {
            throw new Exception('Invalid or expired authorization code');
        }

        $metadata = $session->metadata ?? [];

        // Check auth code expiration
        if (! isset($metadata['auth_code_expires']) ||
          now()->timestamp > $metadata['auth_code_expires']) {
            throw new Exception('Authorization code has expired');
        }

        // Validate redirect URI if provided
        if ($redirectUri && isset($metadata['redirect_uri']) &&
          $metadata['redirect_uri'] !== $redirectUri) {
            throw new Exception('Redirect URI mismatch');
        }

        // Clear auth code from metadata
        unset($metadata['auth_code'], $metadata['auth_code_expires']);
        $session->metadata = $metadata;
        $session->save();

        return [
            'access_token' => $session->session_token,
            'refresh_token' => $session->refresh_token,
            'token_type' => 'Bearer',
            'expires_in' => $session->expires_at->timestamp - now()->timestamp,
            'user' => [
                'id' => $session->user->id,
                'name' => $session->user->name,
                'email' => $session->user->email,
            ],
        ];
    }

    /**
     * Get SSO configuration for an application
     *
     * @throws Exception
     */
    public function getConfiguration(int $applicationId): SSOConfiguration
    {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);

        if (! $application->ssoConfiguration) {
            throw new Exception('SSO is not configured for this application');
        }

        return $application->ssoConfiguration;
    }

    /**
     * Create SSO configuration for an application
     *
     * @throws Exception
     */
    public function createConfiguration(
        int $applicationId,
        string $logoutUrl,
        string $callbackUrl,
        array $allowedDomains,
        int $sessionLifetime = 3600,
        array $settings = []
    ): SSOConfiguration {
        $application = Application::findOrFail($applicationId);

        // Check if configuration already exists
        if ($application->ssoConfiguration) {
            throw new Exception('SSO configuration already exists for this application');
        }

        return SSOConfiguration::create([
            'application_id' => $applicationId,
            'logout_url' => $logoutUrl,
            'callback_url' => $callbackUrl,
            'allowed_domains' => $allowedDomains,
            'session_lifetime' => $sessionLifetime,
            'settings' => $settings,
        ]);
    }

    /**
     * Update SSO configuration
     *
     * @throws Exception
     */
    public function updateConfiguration(
        int $applicationId,
        array $updates
    ): SSOConfiguration {
        $application = Application::with('ssoConfiguration')->findOrFail($applicationId);

        if (! $application->ssoConfiguration) {
            throw new Exception('SSO configuration does not exist for this application');
        }

        $application->ssoConfiguration->update($updates);

        return $application->ssoConfiguration->fresh();
    }

    /**
     * Get SSO configuration for organization
     */
    public function getSSOConfiguration(int $organizationId): ?SSOConfiguration
    {
        return SSOConfiguration::whereHas('application', function ($query) use ($organizationId) {
            $query->where('organization_id', $organizationId);
        })->where('is_active', true)->first();
    }

    /**
     * Validate SAML response
     *
     * @throws Exception
     */
    public function validateSAMLResponse(string $samlResponse, string|int $requestId): array
    {
        // Find the SSO session by request ID in metadata or external_session_id if it's a string, otherwise treat as application ID
        if (is_string($requestId)) {
            $session = SSOSession::whereJsonContains('metadata->saml_request_id', $requestId)->first() ??
              SSOSession::where('external_session_id', $requestId)->first();
            if (! $session) {
                throw new Exception('SSO session not found');
            }
            $application = $session->application;
        } else {
            $application = Application::findOrFail($requestId);
        }

        if (! $application->ssoConfiguration) {
            throw new Exception('SSO configuration not found for application');
        }

        $ssoConfig = $application->ssoConfiguration;

        // Parse SAML assertion using proper XML parsing
        $userInfo = $this->samlService->parseAssertion($samlResponse);

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

        return [
            'user_info' => $userInfo,
            'application_id' => $application->id,
            'validated_at' => now(),
            'success' => true,
        ];
    }

    /**
     * Process SAML callback
     *
     * @throws Exception
     */
    public function processSamlCallback(string $samlResponse, ?string $relayState = null): array
    {
        // Use existing SAML validation method
        $validationResult = $this->validateSAMLResponse($samlResponse, $relayState ?? 'default-request');

        // Create or find user based on SAML response
        $userInfo = $validationResult['user_info'];

        // Try to find the session by relay state or default identifier
        $session = null;
        $lookupId = $relayState ?? 'default-request';
        $session = SSOSession::whereJsonContains('metadata->saml_request_id', $lookupId)->first() ??
                  SSOSession::where('external_session_id', $lookupId)->first();

        if ($session && $session->user) {
            $user = $session->user;
        } else {
            // Try NameID first (raw identifier before attribute mapping), then mapped email
            $user = User::where('email', $userInfo['name_id'] ?? $userInfo['email'])->first()
                ?? User::where('email', $userInfo['email'])->first();

            if (! $user) {
                throw new Exception('User not found: '.$userInfo['email']);
            }
        }

        // Find or create application
        $application = Application::find($validationResult['application_id']);
        if (! $application) {
            throw new Exception('Application not found');
        }

        // Create SSO session
        $session = $this->sessions->createOrUpdateSession($user, $application, request()->ip() ?? '127.0.0.1', request()->userAgent() ?? 'SAML Client');

        // Generate tokens for the response
        $tokens = [
            'access_token' => $session->session_token,
            'token_type' => 'Bearer',
            'expires_in' => $session->expires_at->timestamp - now()->timestamp,
        ];

        return [
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
            ],
            'session' => [
                'id' => $session->id,
                'expires_at' => $session->expires_at->toISOString(),
            ],
            'application' => [
                'id' => $application->id,
                'name' => $application->name,
            ],
            'tokens' => $tokens,
        ];
    }

    /**
     * Get organization metadata for SSO
     *
     * @throws Exception
     */
    public function getOrganizationMetadata(string $organizationSlug): array
    {
        $organization = Organization::where('slug', $organizationSlug)->first();

        if (! $organization) {
            throw new Exception('Organization not found');
        }

        // Get SSO configuration for this organization
        $ssoConfiguration = $this->getSSOConfiguration($organization->id);

        if (! $ssoConfiguration) {
            throw new Exception('No active SSO configuration found for this organization');
        }

        return [
            'organization' => $organization,
            'sso_configuration' => [
                'provider' => $ssoConfiguration->configuration['provider'] ?? 'oidc',
                'endpoints' => [
                    'callback_url' => $ssoConfiguration->callback_url,
                    'logout_url' => $ssoConfiguration->logout_url,
                ],
            ],
            'supported_flows' => ['authorization_code', 'saml2'],
            'security_requirements' => [
                'allowed_domains' => $ssoConfiguration->allowed_domains,
                'session_lifetime' => $ssoConfiguration->session_lifetime,
            ],
            'endpoints' => [
                'initiate' => url('/api/v1/sso/initiate'),
                'callback' => url('/api/v1/sso/callback'),
                'metadata' => url('/api/v1/sso/metadata/'.$organizationSlug),
                'logout' => url('/api/v1/sso/logout'),
            ],
        ];
    }
}
