<?php

namespace App\Services;

use App\Models\SSOConfiguration;
use App\Services\Saml\SamlMessageBuilder;
use App\Services\Saml\SamlXml;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

class SamlService
{
    private const CLOCK_SKEW_SECONDS = 120;

    private const LOGOUT_REQUEST_MAX_AGE_SECONDS = 300;

    public function __construct(private SamlMessageBuilder $messageBuilder) {}

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

        $doc = SamlXml::load($xml);

        if (! $doc) {
            // Fallback: check for assertion tag in raw XML
            if (str_contains($xml, '<saml:Assertion')) {
                return $this->parseAssertionFromRawXml($xml);
            }
            throw new Exception('Could not extract user information from SAML response');
        }

        $xpath = SamlXml::xpath($doc, [
            'saml' => SamlXml::SAML_NS,
            'samlp' => SamlXml::SAMLP_NS,
            'ds' => SamlXml::DSIG_NS,
            'xenc' => SamlXml::XENC_NS,
        ]);

        $encryptedAssertions = $xpath->query('//xenc:EncryptedData');
        if ($encryptedAssertions->length > 0) {
            throw new Exception('Encrypted assertion found but no private key provided for decryption');
        }

        $assertions = $xpath->query('//saml:Assertion');
        if ($assertions->length === 0) {
            throw new Exception('Could not extract user information from SAML response');
        }

        return $this->extractAssertionData($xpath, $assertions->item(0));
    }

    private function extractAssertionData(DOMXPath $xpath, DOMNode $assertion): array
    {
        $nameIdNodes = $xpath->query('saml:Subject/saml:NameID', $assertion);
        $nameId = $nameIdNodes->length > 0 ? trim($nameIdNodes->item(0)->textContent) : null;
        $nameIdFormat = $nameIdNodes->length > 0 ? $nameIdNodes->item(0)->getAttribute('Format') : null;

        $attributes = $this->extractAttributes($xpath, $assertion);

        $email = $attributes['email']
            ?? $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']
            ?? $attributes['mail']
            ?? $nameId;

        $name = $this->resolveDisplayName($attributes);

        $root = $assertion->ownerDocument->documentElement;

        return [
            'id' => 'saml_'.md5($nameId ?? $email ?? uniqid()),
            'email' => $email,
            'name' => $name ?? 'SAML User',
            'name_id' => $nameId,
            'name_id_format' => $nameIdFormat,
            'attributes' => $attributes,
            'issuer' => SamlXml::firstText($xpath, 'saml:Issuer', $assertion),
            'session_index' => $this->extractSessionIndex($xpath, $assertion),
            'conditions' => $this->extractConditions($xpath, $assertion),
            'assertion_id' => $assertion instanceof DOMElement ? $assertion->getAttribute('ID') : null,
            'destination' => $root !== $assertion ? ($root->getAttribute('Destination') ?: null) : null,
            'subject_confirmation' => $this->extractSubjectConfirmation($xpath, $assertion),
        ];
    }

    private function extractSubjectConfirmation(DOMXPath $xpath, DOMNode $assertion): array
    {
        $data = $xpath->query(
            'saml:Subject/saml:SubjectConfirmation[@Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"]/saml:SubjectConfirmationData',
            $assertion
        )->item(0);

        if (! $data instanceof DOMElement) {
            return [];
        }

        return [
            'recipient' => $data->getAttribute('Recipient') ?: null,
            'not_on_or_after' => $data->getAttribute('NotOnOrAfter') ?: null,
            'in_response_to' => $data->getAttribute('InResponseTo') ?: null,
        ];
    }

    private function extractAttributes(DOMXPath $xpath, DOMNode $assertion): array
    {
        $attributes = [];
        $attrStatements = $xpath->query('saml:AttributeStatement/saml:Attribute', $assertion);

        foreach ($attrStatements as $attr) {
            $attrName = $attr->getAttribute('Name');
            $values = $xpath->query('saml:AttributeValue', $attr);

            if ($values->length === 1) {
                $attributes[$attrName] = trim($values->item(0)->textContent);
            } elseif ($values->length > 1) {
                $attrValues = [];
                foreach ($values as $valueNode) {
                    $attrValues[] = trim($valueNode->textContent);
                }
                $attributes[$attrName] = $attrValues;
            }
        }

        return $attributes;
    }

    private function resolveDisplayName(array $attributes): mixed
    {
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

        return $name;
    }

    private function extractConditions(DOMXPath $xpath, DOMNode $assertion): array
    {
        $conditions = [];
        $conditionNodes = $xpath->query('saml:Conditions', $assertion);
        if ($conditionNodes->length > 0) {
            $cond = $conditionNodes->item(0);
            $conditions['not_before'] = $cond->getAttribute('NotBefore') ?: null;
            $conditions['not_on_or_after'] = $cond->getAttribute('NotOnOrAfter') ?: null;
            $conditions['audience_restrictions'] = [];
            foreach ($xpath->query('saml:AudienceRestriction', $cond) as $restriction) {
                $audiences = [];
                foreach ($xpath->query('saml:Audience', $restriction) as $audience) {
                    $audiences[] = trim($audience->textContent);
                }
                $conditions['audience_restrictions'][] = $audiences;
            }
        }

        return $conditions;
    }

    private function extractSessionIndex(DOMXPath $xpath, DOMNode $assertion): ?string
    {
        $authnStatements = $xpath->query('saml:AuthnStatement', $assertion);
        if ($authnStatements->length === 0) {
            return null;
        }

        return $authnStatements->item(0)->getAttribute('SessionIndex') ?: null;
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

        $doc = SamlXml::load($xml);

        if (! $doc) {
            throw new Exception('Could not parse SAML LogoutRequest XML');
        }

        $xpath = SamlXml::xpath($doc, [
            'saml' => SamlXml::SAML_NS,
            'samlp' => SamlXml::SAMLP_NS,
        ]);

        $logoutRequests = $xpath->query('//samlp:LogoutRequest');
        if ($logoutRequests->length === 0) {
            throw new Exception('No LogoutRequest element found');
        }

        $request = $logoutRequests->item(0);

        return [
            'request_id' => $request->getAttribute('ID'),
            'name_id' => SamlXml::firstText($xpath, 'saml:NameID', $request),
            'session_index' => SamlXml::firstText($xpath, 'samlp:SessionIndex', $request),
            'issuer' => SamlXml::firstText($xpath, 'saml:Issuer', $request),
            'issue_instant' => $request->getAttribute('IssueInstant') ?: null,
            'not_on_or_after' => $request->getAttribute('NotOnOrAfter') ?: null,
            'destination' => $request->getAttribute('Destination') ?: null,
        ];
    }

    /**
     * Validate a parsed, signature-verified LogoutRequest for this endpoint, then mark it as consumed.
     *
     * @throws Exception
     */
    public function validateLogoutRequest(array $logoutData, string $sloUrl): void
    {
        $now = time();
        $issuedAt = strtotime($logoutData['issue_instant'] ?? '');
        if ($issuedAt === false
            || $issuedAt > $now + self::CLOCK_SKEW_SECONDS
            || $now >= $issuedAt + self::LOGOUT_REQUEST_MAX_AGE_SECONDS + self::CLOCK_SKEW_SECONDS) {
            throw new Exception('SAML logout request has expired');
        }

        if (! empty($logoutData['not_on_or_after'])) {
            $notOnOrAfter = strtotime($logoutData['not_on_or_after']);
            if ($notOnOrAfter === false || $now >= $notOnOrAfter + self::CLOCK_SKEW_SECONDS) {
                throw new Exception('SAML logout request has expired');
            }
        }

        if (($logoutData['destination'] ?? null) !== $sloUrl) {
            throw new Exception('SAML logout request destination does not match this endpoint');
        }

        if (empty($logoutData['request_id'])) {
            throw new Exception('SAML logout request has no ID');
        }

        $expiresAt = $issuedAt + self::LOGOUT_REQUEST_MAX_AGE_SECONDS + self::CLOCK_SKEW_SECONDS;
        $replayKey = 'saml_logout_request:'.hash('sha256', ($logoutData['issuer'] ?? '').'|'.$logoutData['request_id']);
        if (! Cache::add($replayKey, true, Carbon::createFromTimestamp($expiresAt))) {
            throw new Exception('SAML logout request has already been used');
        }
    }

    /**
     * Validate a parsed, signature-verified assertion for this SP and endpoint, then mark it as consumed.
     *
     * @throws Exception
     */
    public function validateAssertion(array $userInfo, SSOConfiguration $config, string $acsUrl, ?string $expectedInResponseTo = null): void
    {
        $conditions = $userInfo['conditions'] ?? [];
        $this->validateConditions($conditions);

        $spEntityId = $this->messageBuilder->spEntityId($config, config('app.url', url('/')));
        $restrictions = $conditions['audience_restrictions'] ?? [];
        if ($restrictions === [] || collect($restrictions)->contains(fn (array $audiences) => ! in_array($spEntityId, $audiences, true))) {
            throw new Exception('SAML assertion audience does not match this service provider');
        }

        $confirmation = $userInfo['subject_confirmation'] ?? [];
        if (($confirmation['recipient'] ?? null) !== $acsUrl) {
            throw new Exception('SAML assertion recipient does not match this endpoint');
        }

        $confirmationExpiry = strtotime($confirmation['not_on_or_after'] ?? '');
        if ($confirmationExpiry === false || time() >= $confirmationExpiry + self::CLOCK_SKEW_SECONDS) {
            throw new Exception('SAML subject confirmation has expired');
        }

        if (($userInfo['destination'] ?? null) !== null && $userInfo['destination'] !== $acsUrl) {
            throw new Exception('SAML response destination does not match this endpoint');
        }

        if ($expectedInResponseTo !== null && ($confirmation['in_response_to'] ?? null) !== $expectedInResponseTo) {
            throw new Exception('SAML assertion does not answer the pending request');
        }

        if (empty($userInfo['assertion_id'])) {
            throw new Exception('SAML assertion has no ID');
        }

        $expiresAt = max(strtotime($conditions['not_on_or_after']), $confirmationExpiry) + self::CLOCK_SKEW_SECONDS;
        $replayKey = 'saml_assertion:'.hash('sha256', ($userInfo['issuer'] ?? '').'|'.$userInfo['assertion_id']);
        if (! Cache::add($replayKey, true, Carbon::createFromTimestamp($expiresAt))) {
            throw new Exception('SAML assertion has already been used');
        }
    }

    /**
     * Validate time conditions of a SAML assertion.
     *
     * @throws Exception
     */
    public function validateConditions(array $conditions, int $clockSkewSeconds = self::CLOCK_SKEW_SECONDS): bool
    {
        if (empty($conditions['not_on_or_after'])) {
            throw new Exception('SAML assertion has no validity period');
        }

        $now = time();

        if (! empty($conditions['not_before'])) {
            $notBefore = strtotime($conditions['not_before']);
            if ($notBefore === false || $now < ($notBefore - $clockSkewSeconds)) {
                throw new Exception('SAML assertion is not yet valid');
            }
        }

        $notOnOrAfter = strtotime($conditions['not_on_or_after']);
        if ($notOnOrAfter === false || $now >= ($notOnOrAfter + $clockSkewSeconds)) {
            throw new Exception('SAML assertion has expired');
        }

        return true;
    }
}
