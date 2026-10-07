<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SamlIdpInitiatedSsoTest extends IntegrationTestCase
{
    use SignsSamlResponses;

    private const IDP_ENTITY_ID = 'https://idp.example.com';

    #[Test]
    public function it_creates_a_session_for_an_assertion_signed_by_the_configured_idp(): void
    {
        $user = $this->createUser();
        $application = $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email)),
        ]);

        $response->assertOk()
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('application.id', $application->id);
        $this->assertDatabaseHas('sso_sessions', ['user_id' => $user->id, 'application_id' => $application->id]);
    }

    #[Test]
    public function it_rejects_an_unsigned_assertion_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => base64_encode($this->responseXml($user->email)),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML response is not signed');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_an_assertion_signed_by_another_key_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponseWithUntrustedKey($this->responseXml($user->email)),
        ]);

        $response->assertBadRequest();
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_any_assertion_when_the_idp_has_no_certificate_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, null);

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email)),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'No IdP certificate configured for SAML signature validation');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function sp_initiated_callback_rejects_an_unsigned_assertion_with_400(): void
    {
        $user = $this->createUser();
        $application = $this->createSamlApplication($user, $this->samlIdpCertificate());
        $pendingSession = SSOSession::factory()->forUser($user)->create([
            'application_id' => $application->id,
            'metadata' => ['saml_request_id' => 'request-1'],
        ]);

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => base64_encode($this->responseXml($user->email)),
            'RelayState' => 'request-1',
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML response is not signed');
        $this->assertDatabaseCount('sso_sessions', 1);
        $this->assertSame($pendingSession->session_token, $pendingSession->fresh()->session_token);
    }

    #[Test]
    public function it_does_not_log_in_a_user_from_another_organization_with_404(): void
    {
        $owner = $this->createUser();
        $this->createSamlApplication($owner, $this->samlIdpCertificate());
        $outsider = $this->createUser();

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($outsider->email)),
        ]);

        $response->assertNotFound();
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $outsider->id]);
    }

    #[Test]
    public function sp_initiated_callback_logs_in_the_asserted_user_not_the_pending_session_owner(): void
    {
        $initiator = $this->createUser();
        $assertedUser = $this->createUser(['organization_id' => $initiator->organization_id]);
        $application = $this->createSamlApplication($initiator, $this->samlIdpCertificate());
        SSOSession::factory()->forUser($initiator)->create([
            'application_id' => $application->id,
            'metadata' => ['saml_request_id' => 'request-1'],
        ]);

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($assertedUser->email)),
            'RelayState' => 'request-1',
        ]);

        $response->assertOk()->assertJsonPath('user.id', $assertedUser->id);
    }

    #[Test]
    public function sp_initiated_callback_rejects_a_user_from_another_organization_with_400(): void
    {
        $initiator = $this->createUser();
        $application = $this->createSamlApplication($initiator, $this->samlIdpCertificate());
        $outsider = $this->createUser();
        SSOSession::factory()->forUser($initiator)->create([
            'application_id' => $application->id,
            'metadata' => ['saml_request_id' => 'request-1'],
        ]);

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($outsider->email)),
            'RelayState' => 'request-1',
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'User not found: '.$outsider->email);
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $outsider->id]);
    }

    private function createSamlApplication(User $user, ?string $certificate): Application
    {
        $application = $this->createOAuthApplication(['organization_id' => $user->organization_id]);

        SSOConfiguration::create([
            'application_id' => $application->id,
            'name' => 'SAML IdP',
            'provider' => 'saml2',
            'callback_url' => 'https://app.example.com/saml/callback',
            'logout_url' => 'https://app.example.com/saml/logout',
            'allowed_domains' => ['example.com'],
            'session_lifetime' => 3600,
            'is_active' => true,
            'configuration' => [
                'idp_entity_id' => self::IDP_ENTITY_ID,
                'x509_cert' => $certificate,
            ],
        ]);

        return $application;
    }

    private function responseXml(string $email): string
    {
        return '<?xml version="1.0"?>'
            .'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" Version="2.0">'
            .'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0">'
            .'<saml:Issuer>'.self::IDP_ENTITY_ID.'</saml:Issuer>'
            .'<saml:Subject><saml:NameID>'.$email.'</saml:NameID></saml:Subject>'
            .'</saml:Assertion>'
            .'</samlp:Response>';
    }
}
