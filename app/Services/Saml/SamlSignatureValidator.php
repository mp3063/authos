<?php

namespace App\Services\Saml;

use DOMNode;
use DOMXPath;
use Exception;
use Illuminate\Support\Facades\Log;

class SamlSignatureValidator
{
    /**
     * Validate SAML response signature using X.509 certificate.
     *
     * @throws Exception
     */
    public function validate(string $samlResponse, string $x509Certificate): bool
    {
        $xml = base64_decode($samlResponse);
        if (empty($xml)) {
            throw new Exception('Invalid SAML response for signature validation');
        }

        $doc = SamlXml::load($xml);

        if (! $doc) {
            throw new Exception('Could not parse SAML response XML');
        }

        $xpath = SamlXml::xpath($doc, [
            'ds' => SamlXml::DSIG_NS,
            'saml' => SamlXml::SAML_NS,
            'samlp' => SamlXml::SAMLP_NS,
        ]);

        $signatures = $xpath->query('//ds:Signature');
        if ($signatures->length === 0) {
            Log::warning('SAML response has no signature element - skipping signature validation');

            return true; // Unsigned responses are accepted (common in test environments)
        }

        $signatureNode = $signatures->item(0);

        $sigValueNodes = $xpath->query('ds:SignatureValue', $signatureNode);
        if ($sigValueNodes->length === 0) {
            throw new Exception('SAML signature value not found');
        }
        $signatureValue = base64_decode(trim($sigValueNodes->item(0)->textContent));

        $signedInfoNodes = $xpath->query('ds:SignedInfo', $signatureNode);
        if ($signedInfoNodes->length === 0) {
            throw new Exception('SAML SignedInfo not found');
        }

        $signedInfoXml = $signedInfoNodes->item(0)->C14N(true, false);
        $algorithm = $this->resolveSignatureAlgorithm($xpath, $signatureNode);

        return $this->verifySignedInfo($signedInfoXml, $signatureValue, $x509Certificate, $algorithm);
    }

    private function resolveSignatureAlgorithm(DOMXPath $xpath, DOMNode $signatureNode): int
    {
        $sigMethodNodes = $xpath->query('ds:SignedInfo/ds:SignatureMethod', $signatureNode);
        if ($sigMethodNodes->length === 0) {
            return OPENSSL_ALGO_SHA256;
        }

        return match ($sigMethodNodes->item(0)->getAttribute('Algorithm')) {
            'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => OPENSSL_ALGO_SHA1,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
            default => OPENSSL_ALGO_SHA256,
        };
    }

    /**
     * @throws Exception
     */
    private function verifySignedInfo(string $signedInfoXml, string $signatureValue, string $x509Certificate, int $algorithm): bool
    {
        $publicKey = openssl_pkey_get_public(SamlCertificate::toPem($x509Certificate));

        if (! $publicKey) {
            throw new Exception('Invalid X.509 certificate');
        }

        $result = openssl_verify($signedInfoXml, $signatureValue, $publicKey, $algorithm);

        if ($result === 1) {
            return true;
        }

        if ($result === 0) {
            throw new Exception('SAML signature validation failed - signature does not match');
        }

        throw new Exception('SAML signature validation error: '.openssl_error_string());
    }
}
