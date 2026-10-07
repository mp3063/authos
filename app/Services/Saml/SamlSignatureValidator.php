<?php

namespace App\Services\Saml;

use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SamlSignatureValidator
{
    private const ALLOWED_ALGORITHMS = [
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
    ];

    /**
     * Validate that the response's single assertion is covered by a valid signature from the IdP certificate.
     *
     * @throws Exception
     */
    public function validate(string $samlResponse, ?string $x509Certificate): bool
    {
        $xpath = $this->load($samlResponse, $x509Certificate, 'SAML response');

        $assertions = $xpath->query('//saml:Assertion');
        if ($assertions->length !== 1) {
            throw new Exception('SAML response must contain exactly one assertion');
        }

        $this->verifySignature($this->locateSignature($xpath, $assertions->item(0)), $x509Certificate);

        return true;
    }

    /**
     * Validate that a LogoutRequest (HTTP-POST binding) carries an enveloped signature from the IdP certificate.
     *
     * @throws Exception
     */
    public function validateLogoutRequest(string $samlRequest, ?string $x509Certificate): bool
    {
        $xpath = $this->load($samlRequest, $x509Certificate, 'SAML logout request');

        $signatures = $xpath->query('/samlp:LogoutRequest/ds:Signature');
        if ($signatures->length !== 1) {
            throw new Exception('SAML logout request is not signed');
        }

        $this->verifySignature($signatures->item(0), $x509Certificate);

        return true;
    }

    /**
     * @throws Exception
     */
    private function load(string $encodedXml, ?string $x509Certificate, string $messageType): DOMXPath
    {
        if (! $x509Certificate) {
            throw new Exception('No IdP certificate configured for SAML signature validation');
        }

        $doc = SamlXml::load((string) base64_decode($encodedXml, true));
        if (! $doc) {
            throw new Exception("Could not parse {$messageType} XML");
        }

        return SamlXml::xpath($doc, [
            'ds' => SamlXml::DSIG_NS,
            'saml' => SamlXml::SAML_NS,
            'samlp' => SamlXml::SAMLP_NS,
        ]);
    }

    /**
     * @throws Exception
     */
    private function verifySignature(DOMElement $signature, string $x509Certificate): void
    {
        $expectedNode = $signature->parentNode;

        $dsig = new XMLSecurityDSig;
        $dsig->sigNode = $signature;
        $dsig->idKeys = ['ID'];
        $dsig->canonicalizeSignedInfo();
        $dsig->validateReference();

        if (! $this->nodeWasValidated($dsig, $expectedNode)) {
            throw new Exception('SAML signature does not cover the signed element');
        }

        $key = $dsig->locateKey();
        if (! $key || ! in_array($key->type, self::ALLOWED_ALGORITHMS, true)) {
            throw new Exception('Unsupported SAML signature algorithm');
        }

        $key->loadKey(SamlCertificate::toPem($x509Certificate), false, true);

        if ($dsig->verify($key) !== 1) {
            throw new Exception('SAML signature validation failed - signature does not match');
        }
    }

    /**
     * @throws Exception
     */
    private function locateSignature(DOMXPath $xpath, DOMElement $assertion): DOMElement
    {
        $signatures = $xpath->query('ds:Signature', $assertion);
        if ($signatures->length === 0) {
            $signatures = $xpath->query('/samlp:Response/ds:Signature');
        }

        if ($signatures->length !== 1) {
            throw new Exception('SAML response is not signed');
        }

        return $signatures->item(0);
    }

    private function nodeWasValidated(XMLSecurityDSig $dsig, DOMNode $expectedNode): bool
    {
        foreach ($dsig->getValidatedNodes() ?? [] as $validatedNode) {
            if ($validatedNode->isSameNode($expectedNode)) {
                return true;
            }
        }

        return false;
    }
}
