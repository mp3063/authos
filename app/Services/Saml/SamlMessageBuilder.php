<?php

namespace App\Services\Saml;

use App\Models\SSOConfiguration;

class SamlMessageBuilder
{
    private const NAMEID_FORMATS = [
        'email' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'persistent' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'transient' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        'unspecified' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'entity' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
    ];

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
            $certClean = SamlCertificate::clean($x509Certificate);
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
}
