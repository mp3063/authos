<?php

namespace App\Services\Saml;

use DOMDocument;
use DOMNode;
use DOMXPath;
use Exception;

class SamlAssertionDecryptor
{
    /**
     * Decrypt an encrypted SAML assertion.
     *
     * @throws Exception
     */
    public function decrypt(string $samlResponse, string $privateKey): string
    {
        $xml = base64_decode($samlResponse);
        if (empty($xml)) {
            throw new Exception('Invalid SAML response for decryption');
        }

        $doc = SamlXml::load($xml);

        if (! $doc) {
            throw new Exception('Could not parse SAML response XML for decryption');
        }

        $xpath = SamlXml::xpath($doc, [
            'saml' => SamlXml::SAML_NS,
            'samlp' => SamlXml::SAMLP_NS,
            'xenc' => SamlXml::XENC_NS,
        ]);

        $encryptedAssertions = $xpath->query('//saml:EncryptedAssertion');
        if ($encryptedAssertions->length === 0) {
            return $samlResponse;
        }

        $encAssertion = $encryptedAssertions->item(0);

        if ($xpath->query('xenc:EncryptedData', $encAssertion)->length === 0) {
            throw new Exception('EncryptedData element not found in EncryptedAssertion');
        }

        $symmetricKey = $this->decryptSymmetricKey($xpath, $encAssertion, $privateKey);
        $decryptedXml = $this->decryptCipherData($xpath, $encAssertion, $symmetricKey);

        $decryptedDoc = new DOMDocument;
        libxml_use_internal_errors(true);
        $decryptedDoc->loadXML($decryptedXml);
        libxml_clear_errors();

        $importedNode = $doc->importNode($decryptedDoc->documentElement, true);
        $encAssertion->parentNode->replaceChild($importedNode, $encAssertion);

        return base64_encode($doc->saveXML());
    }

    /**
     * @throws Exception
     */
    private function decryptSymmetricKey(DOMXPath $xpath, DOMNode $encAssertion, string $privateKey): string
    {
        $encKeyNodes = $xpath->query('.//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue', $encAssertion);
        if ($encKeyNodes->length === 0) {
            throw new Exception('Encrypted key not found');
        }

        $encryptedSymKey = base64_decode(trim($encKeyNodes->item(0)->textContent));

        $pkey = openssl_pkey_get_private($privateKey);
        if (! $pkey) {
            throw new Exception('Invalid private key for SAML decryption');
        }

        $decryptedSymKey = '';
        $decResult = openssl_private_decrypt($encryptedSymKey, $decryptedSymKey, $pkey, OPENSSL_PKCS1_OAEP_PADDING);
        if (! $decResult) {
            throw new Exception('Failed to decrypt symmetric key: '.openssl_error_string());
        }

        return $decryptedSymKey;
    }

    /**
     * @throws Exception
     */
    private function decryptCipherData(DOMXPath $xpath, DOMNode $encAssertion, string $symmetricKey): string
    {
        $cipherDataNodes = $xpath->query('xenc:EncryptedData/xenc:CipherData/xenc:CipherValue', $encAssertion);
        if ($cipherDataNodes->length === 0) {
            throw new Exception('Cipher data not found');
        }

        $cipherData = base64_decode(trim($cipherDataNodes->item(0)->textContent));
        $encAlgorithm = $this->resolveEncryptionAlgorithm($xpath, $encAssertion);

        $ivLen = openssl_cipher_iv_length($encAlgorithm);
        $iv = substr($cipherData, 0, $ivLen);
        $encryptedContent = substr($cipherData, $ivLen);

        $decryptedXml = openssl_decrypt($encryptedContent, $encAlgorithm, $symmetricKey, OPENSSL_RAW_DATA, $iv);
        if ($decryptedXml === false) {
            throw new Exception('Failed to decrypt SAML assertion');
        }

        return $decryptedXml;
    }

    private function resolveEncryptionAlgorithm(DOMXPath $xpath, DOMNode $encAssertion): string
    {
        $encMethodNodes = $xpath->query('xenc:EncryptedData/xenc:EncryptionMethod', $encAssertion);
        if ($encMethodNodes->length === 0) {
            return 'aes-256-cbc';
        }

        return match ($encMethodNodes->item(0)->getAttribute('Algorithm')) {
            'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => 'aes-128-cbc',
            'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => 'aes-256-cbc',
            'http://www.w3.org/2009/xmlenc11#aes128-gcm' => 'aes-128-gcm',
            'http://www.w3.org/2009/xmlenc11#aes256-gcm' => 'aes-256-gcm',
            default => 'aes-256-cbc',
        };
    }
}
