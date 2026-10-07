<?php

namespace App\Services\Saml;

final class SamlCertificate
{
    public static function clean(string $cert): string
    {
        $cert = str_replace([
            '-----BEGIN CERTIFICATE-----',
            '-----END CERTIFICATE-----',
            "\r", "\n", ' ',
        ], '', $cert);

        return trim($cert);
    }

    public static function toPem(string $cert): string
    {
        return "-----BEGIN CERTIFICATE-----\n".chunk_split(self::clean($cert), 64, "\n").'-----END CERTIFICATE-----';
    }
}
