<?php

namespace Tests\Integration\SSO;

use App\Services\Saml\SamlXml;
use DOMDocument;
use DOMElement;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

trait SignsSamlResponses
{
    /** @var array{key: string, cert: string}|null */
    private static ?array $samlIdpKeyPair = null;

    /** @var array{key: string, cert: string}|null */
    private static ?array $samlAttackerKeyPair = null;

    protected function samlIdpCertificate(): string
    {
        return self::idpKeyPair()['cert'];
    }

    protected function signSamlResponse(string $xml): string
    {
        return $this->signSamlResponseWith($xml, self::idpKeyPair());
    }

    protected function signSamlResponseWithUntrustedKey(string $xml): string
    {
        return $this->signSamlResponseWith($xml, self::attackerKeyPair());
    }

    protected function signSamlLogoutRequest(string $xml): string
    {
        return $this->signSamlXml($xml, self::idpKeyPair(), fn (DOMDocument $doc) => $doc->documentElement);
    }

    protected function signSamlLogoutRequestWithUntrustedKey(string $xml): string
    {
        return $this->signSamlXml($xml, self::attackerKeyPair(), fn (DOMDocument $doc) => $doc->documentElement);
    }

    /**
     * @param  array{key: string, cert: string}  $keyPair
     */
    private function signSamlResponseWith(string $xml, array $keyPair): string
    {
        return $this->signSamlXml(
            $xml,
            $keyPair,
            fn (DOMDocument $doc) => $doc->getElementsByTagNameNS(SamlXml::SAML_NS, 'Assertion')->item(0)
        );
    }

    /**
     * @param  array{key: string, cert: string}  $keyPair
     * @param  callable(DOMDocument): DOMElement  $selectSignedElement
     */
    private function signSamlXml(string $xml, array $keyPair, callable $selectSignedElement): string
    {
        $doc = new DOMDocument;
        $doc->loadXML($xml);
        $signedElement = $selectSignedElement($doc);

        $dsig = new XMLSecurityDSig;
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $signedElement,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N],
            ['id_name' => 'ID', 'overwrite' => false]
        );

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($keyPair['key']);
        $dsig->sign($key);
        $dsig->insertSignature($signedElement, $signedElement->firstChild);

        return base64_encode($doc->saveXML());
    }

    /**
     * @return array{key: string, cert: string}
     */
    private static function idpKeyPair(): array
    {
        return self::$samlIdpKeyPair ??= self::generateKeyPair();
    }

    /**
     * @return array{key: string, cert: string}
     */
    private static function attackerKeyPair(): array
    {
        return self::$samlAttackerKeyPair ??= self::generateKeyPair();
    }

    /**
     * @return array{key: string, cert: string}
     */
    private static function generateKeyPair(): array
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => 'idp.example.com'], $privateKey, ['digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($csr, null, $privateKey, 1, ['digest_alg' => 'sha256']);

        openssl_pkey_export($privateKey, $keyPem);
        openssl_x509_export($certificate, $certPem);

        return ['key' => $keyPem, 'cert' => $certPem];
    }
}
