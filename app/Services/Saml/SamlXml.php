<?php

namespace App\Services\Saml;

use DOMDocument;
use DOMNode;
use DOMXPath;

final class SamlXml
{
    public const SAML_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public const SAMLP_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

    public const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

    public static function load(string $xml): ?DOMDocument
    {
        $doc = new DOMDocument;
        libxml_use_internal_errors(true);
        $loaded = $doc->loadXML($xml);
        libxml_clear_errors();

        return $loaded ? $doc : null;
    }

    /**
     * @param  array<string, string>  $namespaces
     */
    public static function xpath(DOMDocument $doc, array $namespaces): DOMXPath
    {
        $xpath = new DOMXPath($doc);
        foreach ($namespaces as $prefix => $namespace) {
            $xpath->registerNamespace($prefix, $namespace);
        }

        return $xpath;
    }

    public static function firstText(DOMXPath $xpath, string $query, ?DOMNode $context = null): ?string
    {
        $nodes = $xpath->query($query, $context);

        return $nodes->length > 0 ? trim($nodes->item(0)->textContent) : null;
    }
}
