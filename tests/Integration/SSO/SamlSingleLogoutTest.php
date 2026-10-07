<?php

namespace Tests\Integration\SSO;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SamlSingleLogoutTest extends IntegrationTestCase
{
    use SignsSamlResponses;

    private const IDP_ENTITY_ID = 'https://idp.example.com';

    #[Test]
    public function it_revokes_the_users_sessions_for_a_logout_request_signed_by_the_idp(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($user->email)),
        ]);

        $response->assertOk()->assertJsonPath('message', 'Logout processed');
        $this->assertNotNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_an_unsigned_logout_request_with_400(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => base64_encode($this->logoutRequestXml($user->email)),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML logout request is not signed');
        $this->assertNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_a_logout_request_signed_by_another_key_with_400(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequestWithUntrustedKey($this->logoutRequestXml($user->email)),
        ]);

        $response->assertBadRequest();
        $this->assertNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_a_logout_request_from_an_unknown_issuer_with_400(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($user->email, 'https://unknown-idp.example.com')),
        ]);

        $response->assertBadRequest()
            ->assertJsonPath('message', 'No SAML configuration found for IdP: https://unknown-idp.example.com');
        $this->assertNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_does_not_revoke_sessions_of_a_user_in_another_organization(): void
    {
        $idpOwner = $this->createUser();
        $this->createSamlApplication($idpOwner);
        $outsider = $this->createUser();
        $outsiderSession = $this->createActiveSession($outsider, $this->createOAuthApplication(['organization_id' => $outsider->organization_id]));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($outsider->email)),
        ]);

        $response->assertOk();
        $this->assertNull($outsiderSession->fresh()->logged_out_at);
    }

    #[Test]
    public function it_ignores_a_forged_name_id_injected_into_the_unsigned_signature_key_info(): void
    {
        $signer = $this->createUser();
        $victim = $this->createUser(['organization_id' => $signer->organization_id]);
        $application = $this->createSamlApplication($signer);
        $victimSession = $this->createActiveSession($victim, $application);
        $signed = base64_decode($this->signSamlLogoutRequest($this->logoutRequestXml($signer->email)));
        $forgedNameId = '<ds:KeyInfo><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'.$victim->email.'</saml:NameID></ds:KeyInfo>';
        $injected = str_replace('</ds:SignatureValue>', '</ds:SignatureValue>'.$forgedNameId, $signed);

        $response = $this->postJson('/api/v1/sso/saml/slo', ['SAMLRequest' => base64_encode($injected)]);

        $response->assertOk();
        $this->assertNull($victimSession->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_a_replayed_logout_request_with_400(): void
    {
        $user = $this->createUser();
        $application = $this->createSamlApplication($user);
        $samlRequest = $this->signSamlLogoutRequest($this->logoutRequestXml($user->email));
        $this->postJson('/api/v1/sso/saml/slo', ['SAMLRequest' => $samlRequest])->assertOk();
        $laterSession = $this->createActiveSession($user, $application);

        $replay = $this->postJson('/api/v1/sso/saml/slo', ['SAMLRequest' => $samlRequest]);

        $replay->assertBadRequest()->assertJsonPath('message', 'SAML logout request has already been used');
        $this->assertNull($laterSession->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_a_stale_logout_request_with_400(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($user->email, options: ['issue_instant' => time() - 3600])),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML logout request has expired');
        $this->assertNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_rejects_a_logout_request_for_another_destination_with_400(): void
    {
        $user = $this->createUser();
        $session = $this->createActiveSession($user, $this->createSamlApplication($user));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($user->email, options: ['destination' => 'https://other-sp.example.com/slo'])),
        ]);

        $response->assertBadRequest()->assertJsonPath('message', 'SAML logout request destination does not match this endpoint');
        $this->assertNull($session->fresh()->logged_out_at);
    }

    #[Test]
    public function it_keeps_the_users_sessions_in_other_applications_of_the_organization(): void
    {
        $user = $this->createUser();
        $samlSession = $this->createActiveSession($user, $this->createSamlApplication($user));
        $otherSession = $this->createActiveSession($user, $this->createOAuthApplication(['organization_id' => $user->organization_id]));

        $response = $this->postJson('/api/v1/sso/saml/slo', [
            'SAMLRequest' => $this->signSamlLogoutRequest($this->logoutRequestXml($user->email)),
        ]);

        $response->assertOk();
        $this->assertNotNull($samlSession->fresh()->logged_out_at);
        $this->assertNull($otherSession->fresh()->logged_out_at);
    }

    private function createSamlApplication(User $user): Application
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
                'idp_slo_url' => self::IDP_ENTITY_ID.'/slo',
                'x509_cert' => $this->samlIdpCertificate(),
            ],
        ]);

        return $application;
    }

    private function createActiveSession(User $user, Application $application): SSOSession
    {
        return SSOSession::factory()->forUser($user)->create([
            'application_id' => $application->id,
            'logged_out_at' => null,
        ]);
    }

    /**
     * @param  array{issue_instant?: int, destination?: string}  $options
     */
    private function logoutRequestXml(string $email, string $issuer = self::IDP_ENTITY_ID, array $options = []): string
    {
        $options += ['issue_instant' => time(), 'destination' => url('/api/v1/sso/saml/slo')];

        return '<?xml version="1.0"?>'
            .'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            .'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="logout-1" Version="2.0" '
            .'IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z', $options['issue_instant']).'" Destination="'.$options['destination'].'">'
            .'<saml:Issuer>'.$issuer.'</saml:Issuer>'
            .'<saml:NameID>'.$email.'</saml:NameID>'
            .'<samlp:SessionIndex>session-1</samlp:SessionIndex>'
            .'</samlp:LogoutRequest>';
    }
}
