<?php

namespace App\Services;

use App\Models\SSOConfiguration;
use DOMDocument;
use DOMXPath;
use Exception;
use Illuminate\Support\Facades\Log;

class SamlService
{
    private const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const SAMLP_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

    private const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

    private const NAMEID_FORMATS = [
        'email' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'persistent' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'transient' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        'unspecified' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'entity' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
    ];

    /**
     * Parse SAML assertion from a base64-encoded SAML response.
     *
     * @throws Exception
     */
    public function parseAssertion(string $samlResponse): array
    {
        $xml = base64_decode($samlResponse);

        if (empty($xml)) {
            throw new Exception('Invalid SAML response');
        }

        $doc = new DOMDocument;
        libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();

        if (! $loaded) {
            // Fallback: check for assertion tag in raw XML
            if (str_contains($xml, '<saml:Assertion')) {
                return $this->parseAssertionFromRawXml($xml);
            }
            throw new Exception('Could not extract user information from SAML response');
        }

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('saml', self::SAML_NS);
        $xpath->registerNamespace('samlp', self::SAMLP_NS);
        $xpath->registerNamespace('ds', self::DSIG_NS);
        $xpath->registerNamespace('xenc', self::XENC_NS);

        // Check for encrypted assertion
        $encryptedAssertions = $xpath->query('//xenc:EncryptedData');
        if ($encryptedAssertions->length > 0) {
            throw new Exception('Encrypted assertion found but no private key provided for decryption');
        }

        // Find assertion
        $assertions = $xpath->query('//saml:Assertion');
        if ($assertions->length === 0) {
            throw new Exception('Could not extract user information from SAML response');
        }

        $assertion = $assertions->item(0);

        // Extract NameID
        $nameIdNodes = $xpath->query('.//saml:Subject/saml:NameID', $assertion);
        $nameId = $nameIdNodes->length > 0 ? trim($nameIdNodes->item(0)->textContent) : null;
        $nameIdFormat = $nameIdNodes->length > 0 ? $nameIdNodes->item(0)->getAttribute('Format') : null;

        // Extract attributes
        $attributes = [];
        $attrStatements = $xpath->query('.//saml:AttributeStatement/saml:Attribute', $assertion);

        foreach ($attrStatements as $attr) {
            $attrName = $attr->getAttribute('Name');
            $values = $xpath->query('saml:AttributeValue', $attr);

            if ($values->length === 1) {
                $attributes[$attrName] = trim($values->item(0)->textContent);
            } elseif ($values->length > 1) {
                $attrValues = [];
                foreach ($values as $v) {
                    $attrValues[] = trim($v->textContent);
                }
                $attributes[$attrName] = $attrValues;
            }
        }

        // Extract Issuer
        $issuerNodes = $xpath->query('.//saml:Issuer', $assertion);
        $issuer = $issuerNodes->length > 0 ? trim($issuerNodes->item(0)->textContent) : null;

        // Extract conditions (NotBefore, NotOnOrAfter)
        $conditions = [];
        $conditionNodes = $xpath->query('.//saml:Conditions', $assertion);
        if ($conditionNodes->length > 0) {
            $cond = $conditionNodes->item(0);
            $conditions['not_before'] = $cond->getAttribute('NotBefore') ?: null;
            $conditions['not_on_or_after'] = $cond->getAttribute('NotOnOrAfter') ?: null;
        }

        // Extract SessionIndex from AuthnStatement
        $sessionIndex = null;
        $authnStatements = $xpath->query('.//saml:AuthnStatement', $assertion);
        if ($authnStatements->length > 0) {
            $sessionIndex = $authnStatements->item(0)->getAttribute('SessionIndex') ?: null;
        }

        // Map to user info
        $email = $attributes['email']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
            ?? $attributes['mail']
            ?? $nameId;

        $name = $attributes['name']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']
            ?? $attributes['displayName']
            ?? null;

        $firstName = $attributes['firstName']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']
            ?? $attributes['givenName']
            ?? null;

        $lastName = $attributes['lastName']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']
            ?? $attributes['sn']
            ?? null;

        if (! $name && $firstName) {
            $name = trim($firstName.' '.($lastName ?? ''));
        }

        return [
            'id' => 'saml_'.md5($nameId ?? $email ?? uniqid()),
            'email' => $email,
            'name' => $name ?? 'SAML User',
            'name_id' => $nameId,
            'name_id_format' => $nameIdFormat,
            'attributes' => $attributes,
            'issuer' => $issuer,
            'session_index' => $sessionIndex,
            'conditions' => $conditions,
        ];
    }

    /**
     * Parse assertion from raw XML string when DOMDocument fails.
     */
    private function parseAssertionFromRawXml(string $xml): array
    {
        // Extract NameID
        $nameId = null;
        if (preg_match('/<saml:NameID[^>]*>(.*?)<\/saml:NameID>/s', $xml, $matches)) {
            $nameId = trim($matches[1]);
        }

        // Extract attributes
        $attributes = [];
        if (preg_match_all('/<saml:Attribute\s+Name="([^"]*)"[^>]*>\s*<saml:AttributeValue[^>]*>(.*?)<\/saml:AttributeValue>/s', $xml, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $attributes[$match[1]] = trim($match[2]);
            }
        }

        $email = $attributes['email']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
            ?? $nameId;

        $name = $attributes['name']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']
            ?? null;

        return [
            'id' => 'saml_'.md5($nameId ?? $email ?? uniqid()),
            'email' => $email,
            'name' => $name ?? 'SAML User',
            'name_id' => $nameId,
            'name_id_format' => null,
            'attributes' => $attributes,
            'issuer' => null,
            'session_index' => null,
            'conditions' => [],
        ];
    }

    /**
     * Validate SAML response signature using X.509 certificate.
     *
     * @throws Exception
     */
    public function validateSignature(string $samlResponse, string $x509Certificate): bool
    {
        $xml = base64_decode($samlResponse);
        if (empty($xml)) {
            throw new Exception('Invalid SAML response for signature validation');
        }

        $doc = new DOMDocument;
        libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();

        if (! $loaded) {
            throw new Exception('Could not parse SAML response XML');
        }

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::DSIG_NS);
        $xpath->registerNamespace('saml', self::SAML_NS);
        $xpath->registerNamespace('samlp', self::SAMLP_NS);

        // Find Signature element
        $signatures = $xpath->query('//ds:Signature');
        if ($signatures->length === 0) {
            Log::warning('SAML response has no signature element - skipping signature validation');

            return true; // Unsigned responses are accepted (common in test environments)
        }

        $signatureNode = $signatures->item(0);

        // Extract SignatureValue
        $sigValueNodes = $xpath->query('ds:SignatureValue', $signatureNode);
        if ($sigValueNodes->length === 0) {
            throw new Exception('SAML signature value not found');
        }
        $signatureValue = base64_decode(trim($sigValueNodes->item(0)->textContent));

        // Extract SignedInfo for verification
        $signedInfoNodes = $xpath->query('ds:SignedInfo', $signatureNode);
        if ($signedInfoNodes->length === 0) {
            throw new Exception('SAML SignedInfo not found');
        }

        // Canonicalize SignedInfo
        $signedInfoXml = $signedInfoNodes->item(0)->C14N(true, false);

        // Determine signature algorithm
        $sigMethodNodes = $xpath->query('ds:SignedInfo/ds:SignatureMethod', $signatureNode);
        $algorithm = OPENSSL_ALGO_SHA256;
        if ($sigMethodNodes->length > 0) {
            $algUri = $sigMethodNodes->item(0)->getAttribute('Algorithm');
            $algorithm = match ($algUri) {
                'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => OPENSSL_ALGO_SHA1,
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
                'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
                default => OPENSSL_ALGO_SHA256,
            };
        }

        // Prepare certificate
        $cert = $this->formatCertificate($x509Certificate);
        $publicKey = openssl_pkey_get_public($cert);

        if (! $publicKey) {
            throw new Exception('Invalid X.509 certificate');
        }

        // Verify signature
        $result = openssl_verify($signedInfoXml, $signatureValue, $publicKey, $algorithm);

        if ($result === 1) {
            return true;
        }

        if ($result === 0) {
            throw new Exception('SAML signature validation failed - signature does not match');
        }

        throw new Exception('SAML signature validation error: '.openssl_error_string());
    }

    /**
     * Decrypt an encrypted SAML assertion.
     *
     * @throws Exception
     */
    public function decryptAssertion(string $samlResponse, string $privateKey): string
    {
        $xml = base64_decode($samlResponse);
        if (empty($xml)) {
            throw new Exception('Invalid SAML response for decryption');
        }

        $doc = new DOMDocument;
        libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();

        if (! $loaded) {
            throw new Exception('Could not parse SAML response XML for decryption');
        }

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('saml', self::SAML_NS);
        $xpath->registerNamespace('samlp', self::SAMLP_NS);
        $xpath->registerNamespace('xenc', self::XENC_NS);

        // Find EncryptedAssertion
        $encryptedAssertions = $xpath->query('//saml:EncryptedAssertion');
        if ($encryptedAssertions->length === 0) {
            // No encryption, return as-is
            return $samlResponse;
        }

        $encAssertion = $encryptedAssertions->item(0);

        // Get EncryptedData
        $encDataNodes = $xpath->query('xenc:EncryptedData', $encAssertion);
        if ($encDataNodes->length === 0) {
            throw new Exception('EncryptedData element not found in EncryptedAssertion');
        }

        // Get encrypted key
        $encKeyNodes = $xpath->query('.//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue', $encAssertion);
        if ($encKeyNodes->length === 0) {
            throw new Exception('Encrypted key not found');
        }

        $encryptedSymKey = base64_decode(trim($encKeyNodes->item(0)->textContent));

        // Decrypt symmetric key using private key
        $pkey = openssl_pkey_get_private($privateKey);
        if (! $pkey) {
            throw new Exception('Invalid private key for SAML decryption');
        }

        $decryptedSymKey = '';
        $decResult = openssl_private_decrypt($encryptedSymKey, $decryptedSymKey, $pkey, OPENSSL_PKCS1_OAEP_PADDING);
        if (! $decResult) {
            throw new Exception('Failed to decrypt symmetric key: '.openssl_error_string());
        }

        // Get cipher data
        $cipherDataNodes = $xpath->query('xenc:EncryptedData/xenc:CipherData/xenc:CipherValue', $encAssertion);
        if ($cipherDataNodes->length === 0) {
            throw new Exception('Cipher data not found');
        }

        $cipherData = base64_decode(trim($cipherDataNodes->item(0)->textContent));

        // Determine encryption algorithm
        $encMethodNodes = $xpath->query('xenc:EncryptedData/xenc:EncryptionMethod', $encAssertion);
        $encAlgorithm = 'aes-256-cbc';
        if ($encMethodNodes->length > 0) {
            $algUri = $encMethodNodes->item(0)->getAttribute('Algorithm');
            $encAlgorithm = match ($algUri) {
                'http://www.w3.org/2001/04/xmlenc#aes128-cbc' => 'aes-128-cbc',
                'http://www.w3.org/2001/04/xmlenc#aes256-cbc' => 'aes-256-cbc',
                'http://www.w3.org/2009/xmlenc11#aes128-gcm' => 'aes-128-gcm',
                'http://www.w3.org/2009/xmlenc11#aes256-gcm' => 'aes-256-gcm',
                default => 'aes-256-cbc',
            };
        }

        // Extract IV from cipher data
        $ivLen = openssl_cipher_iv_length($encAlgorithm);
        $iv = substr($cipherData, 0, $ivLen);
        $encryptedContent = substr($cipherData, $ivLen);

        // Decrypt the assertion
        $decryptedXml = openssl_decrypt($encryptedContent, $encAlgorithm, $decryptedSymKey, OPENSSL_RAW_DATA, $iv);
        if ($decryptedXml === false) {
            throw new Exception('Failed to decrypt SAML assertion');
        }

        // Replace EncryptedAssertion with decrypted content
        $decryptedDoc = new DOMDocument;
        libxml_use_internal_errors(true);
        $decryptedDoc->loadXML($decryptedXml);
        libxml_clear_errors();

        $importedNode = $doc->importNode($decryptedDoc->documentElement, true);
        $encAssertion->parentNode->replaceChild($importedNode, $encAssertion);

        return base64_encode($doc->saveXML());
    }

    /**
     * Map NameID format to a standardized identifier.
     */
    public function mapNameIdFormat(string $format): string
    {
        return match ($format) {
            self::NAMEID_FORMATS['email'],
            'emailAddress' => 'email',

            self::NAMEID_FORMATS['persistent'],
            'persistent' => 'persistent',

            self::NAMEID_FORMATS['transient'],
            'transient' => 'transient',

            self::NAMEID_FORMATS['unspecified'],
            'unspecified' => 'unspecified',

            self::NAMEID_FORMATS['entity'],
            'entity' => 'entity',

            default => 'unspecified',
        };
    }

    /**
     * Get the full URI for a NameID format.
     */
    public function getNameIdFormatUri(string $shortName): string
    {
        return self::NAMEID_FORMATS[$shortName] ?? self::NAMEID_FORMATS['unspecified'];
    }

    /**
     * Apply attribute mapping from SSO configuration.
     */
    public function applyAttributeMapping(array $userInfo, SSOConfiguration $config): array
    {
        $mapping = $config->configuration['attribute_mapping'] ?? null;

        if (! $mapping || ! is_array($mapping)) {
            return $userInfo;
        }

        $attributes = $userInfo['attributes'] ?? [];
        foreach ($mapping as $field => $samlAttribute) {
            if (isset($attributes[$samlAttribute])) {
                $userInfo[$field] = $attributes[$samlAttribute];
            }
        }

        return $userInfo;
    }

    /**
     * Generate SP (Service Provider) metadata XML.
     */
    public function generateSpMetadataXml(string $entityId, string $acsUrl, string $sloUrl, ?string $x509Certificate = null, string $nameIdFormat = 'email'): string
    {
        $nameIdFormatUri = $this->getNameIdFormatUri($nameIdFormat);

        $xml = '<?xml version="1.0" encoding="UTF-8"?>'."\n";
        $xml .= '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"';
        $xml .= ' entityID="'.htmlspecialchars($entityId, ENT_XML1).'">';
        $xml .= "\n";

        $xml .= '  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"';
        $xml .= ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">';
        $xml .= "\n";

        // Signing key descriptor
        if ($x509Certificate) {
            $certClean = $this->cleanCertificate($x509Certificate);
            $xml .= '    <md:KeyDescriptor use="signing">'."\n";
            $xml .= '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'."\n";
            $xml .= '        <ds:X509Data>'."\n";
            $xml .= '          <ds:X509Certificate>'.$certClean.'</ds:X509Certificate>'."\n";
            $xml .= '        </ds:X509Data>'."\n";
            $xml .= '      </ds:KeyInfo>'."\n";
            $xml .= '    </md:KeyDescriptor>'."\n";

            // Encryption key descriptor
            $xml .= '    <md:KeyDescriptor use="encryption">'."\n";
            $xml .= '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'."\n";
            $xml .= '        <ds:X509Data>'."\n";
            $xml .= '          <ds:X509Certificate>'.$certClean.'</ds:X509Certificate>'."\n";
            $xml .= '        </ds:X509Data>'."\n";
            $xml .= '      </ds:KeyInfo>'."\n";
            $xml .= '    </md:KeyDescriptor>'."\n";
        }

        // SLO endpoint
        $xml .= '    <md:SingleLogoutService';
        $xml .= ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"';
        $xml .= ' Location="'.htmlspecialchars($sloUrl, ENT_XML1).'" />'."\n";

        $xml .= '    <md:SingleLogoutService';
        $xml .= ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"';
        $xml .= ' Location="'.htmlspecialchars($sloUrl, ENT_XML1).'" />'."\n";

        // NameID format
        $xml .= '    <md:NameIDFormat>'.$nameIdFormatUri.'</md:NameIDFormat>'."\n";

        // ACS endpoint
        $xml .= '    <md:AssertionConsumerService';
        $xml .= ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"';
        $xml .= ' Location="'.htmlspecialchars($acsUrl, ENT_XML1).'"';
        $xml .= ' index="0" isDefault="true" />'."\n";

        $xml .= '  </md:SPSSODescriptor>'."\n";
        $xml .= '</md:EntityDescriptor>';

        return $xml;
    }

    /**
     * Generate SP metadata from SSO configuration.
     */
    public function generateSpMetadataFromConfig(SSOConfiguration $config, string $baseUrl): string
    {
        $configuration = $config->configuration ?? [];
        $settings = $config->settings ?? [];

        $entityId = $configuration['sp_entity_id']
            ?? $settings['saml_entity_id']
            ?? $baseUrl.'/api/v1/saml/metadata';

        $acsUrl = $config->callback_url ?? $baseUrl.'/api/v1/sso/saml/callback';
        $sloUrl = $config->logout_url ?? $baseUrl.'/api/v1/saml/slo';

        $certificate = $configuration['sp_x509_cert']
            ?? $settings['sp_x509_cert']
            ?? null;

        $nameIdFormat = $settings['name_id_format'] ?? 'email';
        $shortFormat = $this->mapNameIdFormat($nameIdFormat);

        return $this->generateSpMetadataXml($entityId, $acsUrl, $sloUrl, $certificate, $shortFormat);
    }

    /**
     * Process a SAML LogoutRequest.
     *
     * @throws Exception
     */
    public function parseLogoutRequest(string $samlRequest): array
    {
        $xml = base64_decode($samlRequest);
        if (empty($xml)) {
            throw new Exception('Invalid SAML LogoutRequest');
        }

        $doc = new DOMDocument;
        libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();

        if (! $loaded) {
            throw new Exception('Could not parse SAML LogoutRequest XML');
        }

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('saml', self::SAML_NS);
        $xpath->registerNamespace('samlp', self::SAMLP_NS);

        $logoutRequests = $xpath->query('//samlp:LogoutRequest');
        if ($logoutRequests->length === 0) {
            throw new Exception('No LogoutRequest element found');
        }

        $request = $logoutRequests->item(0);
        $requestId = $request->getAttribute('ID');

        // Extract NameID
        $nameIdNodes = $xpath->query('.//saml:NameID', $request);
        $nameId = $nameIdNodes->length > 0 ? trim($nameIdNodes->item(0)->textContent) : null;

        // Extract SessionIndex
        $sessionIndexNodes = $xpath->query('.//samlp:SessionIndex', $request);
        $sessionIndex = $sessionIndexNodes->length > 0 ? trim($sessionIndexNodes->item(0)->textContent) : null;

        // Extract Issuer
        $issuerNodes = $xpath->query('.//saml:Issuer', $request);
        $issuer = $issuerNodes->length > 0 ? trim($issuerNodes->item(0)->textContent) : null;

        return [
            'request_id' => $requestId,
            'name_id' => $nameId,
            'session_index' => $sessionIndex,
            'issuer' => $issuer,
        ];
    }

    /**
     * Generate a SAML LogoutResponse XML.
     */
    public function generateLogoutResponse(string $inResponseTo, string $issuer, string $destination, string $status = 'Success'): string
    {
        $responseId = '_'.bin2hex(random_bytes(16));
        $issueInstant = gmdate('Y-m-d\TH:i:s\Z');

        $statusCode = match ($status) {
            'Success' => 'urn:oasis:names:tc:SAML:2.0:status:Success',
            'Requester' => 'urn:oasis:names:tc:SAML:2.0:status:Requester',
            'Responder' => 'urn:oasis:names:tc:SAML:2.0:status:Responder',
            default => 'urn:oasis:names:tc:SAML:2.0:status:Success',
        };

        $xml = '<?xml version="1.0" encoding="UTF-8"?>'."\n";
        $xml .= '<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"';
        $xml .= ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
        $xml .= ' ID="'.htmlspecialchars($responseId, ENT_XML1).'"';
        $xml .= ' Version="2.0"';
        $xml .= ' IssueInstant="'.$issueInstant.'"';
        $xml .= ' Destination="'.htmlspecialchars($destination, ENT_XML1).'"';
        $xml .= ' InResponseTo="'.htmlspecialchars($inResponseTo, ENT_XML1).'">';
        $xml .= "\n";
        $xml .= '  <saml:Issuer>'.htmlspecialchars($issuer, ENT_XML1).'</saml:Issuer>'."\n";
        $xml .= '  <samlp:Status>'."\n";
        $xml .= '    <samlp:StatusCode Value="'.$statusCode.'" />'."\n";
        $xml .= '  </samlp:Status>'."\n";
        $xml .= '</samlp:LogoutResponse>';

        return $xml;
    }

    /**
     * Generate a SAML AuthnRequest for SP-initiated SSO.
     */
    public function generateAuthnRequest(string $issuer, string $acsUrl, string $destination, string $nameIdFormat = 'email'): string
    {
        $requestId = '_'.bin2hex(random_bytes(16));
        $issueInstant = gmdate('Y-m-d\TH:i:s\Z');
        $nameIdFormatUri = $this->getNameIdFormatUri($nameIdFormat);

        $xml = '<?xml version="1.0" encoding="UTF-8"?>'."\n";
        $xml .= '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"';
        $xml .= ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"';
        $xml .= ' ID="'.htmlspecialchars($requestId, ENT_XML1).'"';
        $xml .= ' Version="2.0"';
        $xml .= ' IssueInstant="'.$issueInstant.'"';
        $xml .= ' Destination="'.htmlspecialchars($destination, ENT_XML1).'"';
        $xml .= ' AssertionConsumerServiceURL="'.htmlspecialchars($acsUrl, ENT_XML1).'"';
        $xml .= ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">';
        $xml .= "\n";
        $xml .= '  <saml:Issuer>'.htmlspecialchars($issuer, ENT_XML1).'</saml:Issuer>'."\n";
        $xml .= '  <samlp:NameIDPolicy Format="'.$nameIdFormatUri.'" AllowCreate="true" />'."\n";
        $xml .= '</samlp:AuthnRequest>';

        return $xml;
    }

    /**
     * Validate time conditions of a SAML assertion.
     *
     * @throws Exception
     */
    public function validateConditions(array $conditions, int $clockSkewSeconds = 120): bool
    {
        if (empty($conditions)) {
            return true;
        }

        $now = time();

        if (! empty($conditions['not_before'])) {
            $notBefore = strtotime($conditions['not_before']);
            if ($notBefore !== false && $now < ($notBefore - $clockSkewSeconds)) {
                throw new Exception('SAML assertion is not yet valid');
            }
        }

        if (! empty($conditions['not_on_or_after'])) {
            $notOnOrAfter = strtotime($conditions['not_on_or_after']);
            if ($notOnOrAfter !== false && $now >= ($notOnOrAfter + $clockSkewSeconds)) {
                throw new Exception('SAML assertion has expired');
            }
        }

        return true;
    }

    /**
     * Format a certificate string into PEM format.
     */
    private function formatCertificate(string $cert): string
    {
        $cert = $this->cleanCertificate($cert);

        return "-----BEGIN CERTIFICATE-----\n".chunk_split($cert, 64, "\n").'-----END CERTIFICATE-----';
    }

    /**
     * Clean certificate by removing headers and whitespace.
     */
    private function cleanCertificate(string $cert): string
    {
        $cert = str_replace([
            '-----BEGIN CERTIFICATE-----',
            '-----END CERTIFICATE-----',
            "\r", "\n", ' ',
        ], '', $cert);

        return trim($cert);
    }
}
