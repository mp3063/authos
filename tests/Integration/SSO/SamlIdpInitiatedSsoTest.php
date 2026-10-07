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

    private const SP_ENTITY_ID = 'https://authos.example.com/saml/sp';

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
            'SAMLResponse' => base64_encode($this->spInitiatedResponseXml($user->email)),
            'RelayState' => 'request-1',
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML response is not signed');
        $this->assertDatabaseCount('sso_sessions', 1);
        $this->assertSame($pendingSession->session_token, $pendingSession->fresh()->session_token);
    }

    #[Test]
    public function it_ignores_a_forged_subject_injected_into_the_unsigned_signature_key_info(): void
    {
        $signer = $this->createUser();
        $victim = $this->createUser(['organization_id' => $signer->organization_id]);
        $this->createSamlApplication($signer, $this->samlIdpCertificate());
        $signed = base64_decode($this->signSamlResponse($this->responseXml($signer->email)));
        $forgedSubject = '<ds:KeyInfo><saml:Subject><saml:NameID>'.$victim->email.'</saml:NameID></saml:Subject></ds:KeyInfo>';
        $injected = str_replace('</ds:SignatureValue>', '</ds:SignatureValue>'.$forgedSubject, $signed);

        $response = $this->postJson('/api/v1/sso/saml/acs', ['SAMLResponse' => base64_encode($injected)]);

        $response->assertOk()->assertJsonPath('user.id', $signer->id);
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $victim->id]);
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
            'SAMLResponse' => $this->signSamlResponse($this->spInitiatedResponseXml($assertedUser->email)),
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
            'SAMLResponse' => $this->signSamlResponse($this->spInitiatedResponseXml($outsider->email)),
            'RelayState' => 'request-1',
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'User not found: '.$outsider->email);
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $outsider->id]);
    }

    #[Test]
    public function it_uses_the_configuration_whose_certificate_verifies_when_organizations_share_an_issuer(): void
    {
        $shadowingOwner = $this->createUser();
        $this->createSamlApplication($shadowingOwner, $this->samlUntrustedCertificate());
        $user = $this->createUser();
        $application = $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email)),
        ]);

        $response->assertOk()
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('application.id', $application->id);
    }

    #[Test]
    public function it_rejects_an_assertion_for_another_audience_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email, ['audience' => 'https://other-sp.example.com'])),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML assertion audience does not match this service provider');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_an_assertion_without_conditions_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email, ['conditions' => false])),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML assertion has no validity period');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_an_assertion_issued_for_another_recipient_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());

        $response = $this->postJson('/api/v1/sso/saml/acs', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email, ['recipient' => 'https://other-sp.example.com/acs'])),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML assertion recipient does not match this endpoint');
        $this->assertDatabaseMissing('sso_sessions', ['user_id' => $user->id]);
    }

    #[Test]
    public function it_rejects_a_replayed_assertion_with_400(): void
    {
        $user = $this->createUser();
        $this->createSamlApplication($user, $this->samlIdpCertificate());
        $samlResponse = $this->signSamlResponse($this->responseXml($user->email));

        $this->postJson('/api/v1/sso/saml/acs', ['SAMLResponse' => $samlResponse])->assertOk();
        $replay = $this->postJson('/api/v1/sso/saml/acs', ['SAMLResponse' => $samlResponse]);

        $replay->assertBadRequest()->assertJsonPath('message', 'SAML assertion has already been used');
        $this->assertDatabaseCount('sso_sessions', 1);
    }

    #[Test]
    public function sp_initiated_callback_rejects_an_assertion_for_another_request_with_400(): void
    {
        $user = $this->createUser();
        $application = $this->createSamlApplication($user, $this->samlIdpCertificate());
        SSOSession::factory()->forUser($user)->create([
            'application_id' => $application->id,
            'metadata' => ['saml_request_id' => 'request-1'],
        ]);

        $response = $this->postJson('/api/v1/sso/saml/callback', [
            'SAMLResponse' => $this->signSamlResponse($this->responseXml($user->email, [
                'recipient' => url('/api/v1/sso/saml/callback'),
                'in_response_to' => 'request-2',
            ])),
            'RelayState' => 'request-1',
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML assertion does not answer the pending request');
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
                'sp_entity_id' => self::SP_ENTITY_ID,
                'x509_cert' => $certificate,
            ],
        ]);

        return $application;
    }

    /**
     * @param  array{audience?: string, recipient?: string, in_response_to?: ?string, conditions?: bool}  $options
     */
    private function responseXml(string $email, array $options = []): string
    {
        $options += [
            'audience' => self::SP_ENTITY_ID,
            'recipient' => url('/api/v1/sso/saml/acs'),
            'in_response_to' => null,
            'conditions' => true,
        ];
        $notOnOrAfter = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        $inResponseTo = $options['in_response_to'] ? ' InResponseTo="'.$options['in_response_to'].'"' : '';
        $conditions = $options['conditions']
            ? '<saml:Conditions NotOnOrAfter="'.$notOnOrAfter.'"><saml:AudienceRestriction><saml:Audience>'.$options['audience'].'</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            : '';

        return '<?xml version="1.0"?>'
            .'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" Version="2.0">'
            .'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0">'
            .'<saml:Issuer>'.self::IDP_ENTITY_ID.'</saml:Issuer>'
            .'<saml:Subject><saml:NameID>'.$email.'</saml:NameID>'
            .'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            .'<saml:SubjectConfirmationData Recipient="'.$options['recipient'].'" NotOnOrAfter="'.$notOnOrAfter.'"'.$inResponseTo.'/>'
            .'</saml:SubjectConfirmation></saml:Subject>'
            .$conditions
            .'</saml:Assertion>'
            .'</samlp:Response>';
    }

    private function spInitiatedResponseXml(string $email): string
    {
        return $this->responseXml($email, [
            'recipient' => url('/api/v1/sso/saml/callback'),
            'in_response_to' => 'request-1',
        ]);
    }
}
