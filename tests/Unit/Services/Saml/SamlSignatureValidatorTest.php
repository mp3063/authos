<?php

namespace Tests\Unit\Services\Saml;

use App\Services\Saml\SamlSignatureValidator;
use Exception;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\SSO\SignsSamlResponses;
use Tests\TestCase;

class SamlSignatureValidatorTest extends TestCase
{
    use SignsSamlResponses;

    private const RESPONSE_XML = <<<'XML'
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response-1" Version="2.0">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-1" Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
XML;

    #[Test]
    public function it_accepts_an_assertion_signed_by_the_configured_certificate(): void
    {
        $response = $this->signSamlResponse(self::RESPONSE_XML);

        $this->assertTrue((new SamlSignatureValidator)->validate($response, $this->samlIdpCertificate()));
    }

    #[Test]
    public function it_rejects_a_response_when_no_certificate_is_configured(): void
    {
        $response = $this->signSamlResponse(self::RESPONSE_XML);

        $this->expectExceptionMessage('No IdP certificate configured');

        (new SamlSignatureValidator)->validate($response, null);
    }

    #[Test]
    public function it_rejects_an_unsigned_response(): void
    {
        $this->expectExceptionMessage('SAML response is not signed');

        (new SamlSignatureValidator)->validate(base64_encode(self::RESPONSE_XML), $this->samlIdpCertificate());
    }

    #[Test]
    public function it_rejects_an_assertion_signed_by_another_key(): void
    {
        $response = $this->signSamlResponseWithUntrustedKey(self::RESPONSE_XML);

        $this->expectExceptionMessage('signature does not match');

        (new SamlSignatureValidator)->validate($response, $this->samlIdpCertificate());
    }

    #[Test]
    public function it_rejects_an_assertion_modified_after_signing(): void
    {
        $signed = base64_decode($this->signSamlResponse(self::RESPONSE_XML));
        $tampered = str_replace('alice@example.com', 'admin@example.com', $signed);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Reference validation failed');

        (new SamlSignatureValidator)->validate(base64_encode($tampered), $this->samlIdpCertificate());
    }

    #[Test]
    public function it_rejects_a_forged_assertion_wrapped_around_a_signed_one(): void
    {
        $signed = base64_decode($this->signSamlResponse(self::RESPONSE_XML));
        $forged = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="evil" Version="2.0">'
            .'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject></saml:Assertion>';
        $wrapped = preg_replace('/(<samlp:Response[^>]*>)/', '$1'.$forged, $signed, 1);

        $this->expectExceptionMessage('exactly one assertion');

        (new SamlSignatureValidator)->validate(base64_encode($wrapped), $this->samlIdpCertificate());
    }

    #[Test]
    public function it_rejects_a_signature_whose_reference_points_to_a_duplicate_id(): void
    {
        $signed = base64_decode($this->signSamlResponse(self::RESPONSE_XML));
        $decoy = '<samlp:Extensions><Decoy ID="assertion-1"/></samlp:Extensions>';
        $wrapped = preg_replace('/(<samlp:Response[^>]*>)/', '$1'.$decoy, $signed, 1);

        $this->expectException(Exception::class);

        (new SamlSignatureValidator)->validate(base64_encode($wrapped), $this->samlIdpCertificate());
    }
}
