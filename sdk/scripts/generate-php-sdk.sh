#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}AuthOS PHP SDK Generator${NC}"
echo "================================"

# Check if OpenAPI spec exists
if [ ! -f "public/openapi.json" ]; then
    echo -e "${YELLOW}OpenAPI spec not found. Generating...${NC}"
    herd php artisan openapi:generate
fi

# Check if OpenAPI Generator is installed
if ! command -v openapi-generator &> /dev/null; then
    echo -e "${YELLOW}Installing OpenAPI Generator...${NC}"
    echo "Please install OpenAPI Generator:"
    echo "  brew install openapi-generator"
    echo "  or"
    echo "  npm install @openapitools/openapi-generator-cli -g"
    exit 1
fi

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
rm -rf sdk/php/src sdk/php/docs sdk/php/test

# Generate PHP client from OpenAPI spec
echo -e "${YELLOW}Generating PHP client...${NC}"
openapi-generator generate \
    -i public/openapi.json \
    -g php \
    -o sdk/php \
    --additional-properties=\
invokerPackage=AuthOS\\Client,\
packageName=authos-client,\
artifactVersion=1.0.0,\
composerVendorName=authos,\
composerProjectName=client,\
phpVersion=8.2

# Create custom auth helpers
echo -e "${YELLOW}Creating custom auth helpers...${NC}"

mkdir -p sdk/php/src/Auth

cat > sdk/php/src/Auth/PKCEManager.php << 'EOF'
<?php

declare(strict_types=1);

namespace AuthOS\Client\Auth;

class PKCEManager
{
    /**
     * Generate PKCE code verifier
     */
    public static function generateCodeVerifier(): string
    {
        $bytes = random_bytes(32);
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Generate S256 code challenge from verifier
     */
    public static function generateCodeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Generate PKCE pair (verifier and challenge)
     */
    public static function generatePKCEPair(): array
    {
        $verifier = self::generateCodeVerifier();
        $challenge = self::generateCodeChallenge($verifier);

        return [
            'code_verifier' => $verifier,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ];
    }
}
EOF

cat > sdk/php/src/Auth/OAuthHelper.php << 'EOF'
<?php

declare(strict_types=1);

namespace AuthOS\Client\Auth;

class OAuthHelper
{
    public function __construct(
        private string $clientId,
        private string $redirectUri,
        private string $baseUrl
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Get OAuth authorization URL
     *
     * @param array<string> $scopes
     * @return array{url: string, state: string, code_verifier: string|null}
     */
    public function getAuthorizationUrl(
        array $scopes = ['openid', 'profile', 'email'],
        ?string $state = null,
        bool $usePKCE = true
    ): array {
        if ($state === null) {
            $state = bin2hex(random_bytes(16));
        }

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => $state,
        ];

        $codeVerifier = null;
        if ($usePKCE) {
            $pkce = PKCEManager::generatePKCEPair();
            $params['code_challenge'] = $pkce['code_challenge'];
            $params['code_challenge_method'] = $pkce['code_challenge_method'];
            $codeVerifier = $pkce['code_verifier'];
        }

        $url = $this->baseUrl . '/oauth/authorize?' . http_build_query($params);

        return [
            'url' => $url,
            'state' => $state,
            'code_verifier' => $codeVerifier,
        ];
    }

    /**
     * Exchange authorization code for tokens
     */
    public function exchangeCodeForToken(
        string $code,
        ?string $codeVerifier = null,
        ?string $clientSecret = null
    ): array {
        $params = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
        ];

        if ($clientSecret !== null) {
            $params['client_secret'] = $clientSecret;
        }

        if ($codeVerifier !== null) {
            $params['code_verifier'] = $codeVerifier;
        }

        $ch = curl_init($this->baseUrl . '/oauth/token');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new \RuntimeException('Token exchange failed: ' . $response);
        }

        return json_decode($response, true);
    }
}
EOF

# Update composer.json
echo -e "${YELLOW}Updating composer.json...${NC}"

cat > sdk/php/composer.json << 'EOF'
{
  "name": "authos/client",
  "description": "PHP SDK for AuthOS - Enterprise authentication service",
  "keywords": ["auth", "authentication", "oauth", "oauth2", "oidc", "sso", "authos"],
  "type": "library",
  "license": "MIT",
  "authors": [
    {
      "name": "AuthOS Team",
      "email": "support@authos.dev"
    }
  ],
  "require": {
    "php": "^8.2",
    "ext-curl": "*",
    "ext-json": "*",
    "ext-mbstring": "*",
    "guzzlehttp/guzzle": "^7.8",
    "guzzlehttp/psr7": "^2.6"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.5",
    "friendsofphp/php-cs-fixer": "^3.48"
  },
  "autoload": {
    "psr-4": {
      "AuthOS\\Client\\": "src/"
    }
  },
  "autoload-dev": {
    "psr-4": {
      "AuthOS\\Client\\Test\\": "test/"
    }
  },
  "scripts": {
    "test": "phpunit",
    "cs-fix": "php-cs-fixer fix"
  }
}
EOF

# Create README
echo -e "${YELLOW}Creating README.md...${NC}"

cat > sdk/php/README.md << 'EOF'
# AuthOS PHP SDK

Official PHP SDK for AuthOS - Enterprise authentication service.

## Requirements

- PHP 8.2 or higher
- Composer

## Installation

```bash
composer require authos/client
```

## Quick Start

```php
<?php

require_once 'vendor/autoload.php';

use AuthOS\Client\Configuration;
use AuthOS\Client\ApiClient;
use AuthOS\Client\Auth\OAuthHelper;

// Initialize configuration
$config = Configuration::getDefaultConfiguration();
$config->setHost('https://auth.example.com');

// Create API client
$apiClient = new ApiClient($config);

// OAuth flow helper
$oauth = new OAuthHelper(
    clientId: 'your-client-id',
    redirectUri: 'http://localhost:8000/callback',
    baseUrl: 'https://auth.example.com'
);

// Get authorization URL
$authData = $oauth->getAuthorizationUrl(
    scopes: ['openid', 'profile', 'email']
);

echo "Visit: " . $authData['url'] . "\n";
// Store $authData['state'] and $authData['code_verifier'] for callback
```

## Usage

### Authentication

```php
// After OAuth callback, exchange code for tokens
$tokens = $oauth->exchangeCodeForToken(
    code: $_GET['code'],
    codeVerifier: $_SESSION['code_verifier'] // stored from previous step
);

// Set access token
$config->setAccessToken($tokens['access_token']);
```

### User Management

```php
use AuthOS\Client\Api\UsersApi;

$usersApi = new UsersApi($apiClient);

// List users
$users = $usersApi->getV1Users();

// Get specific user
$user = $usersApi->getV1UsersId('user-id');
```

### Organization Management

```php
use AuthOS\Client\Api\OrganizationsApi;

$orgsApi = new OrganizationsApi($apiClient);

// List organizations
$orgs = $orgsApi->getV1Organizations();

// Create organization
$org = $orgsApi->postV1Organizations([
    'name' => 'Acme Corp',
    'slug' => 'acme-corp'
]);
```

## Laravel Integration

```php
// In a Laravel service provider or controller

use AuthOS\Client\Configuration;
use AuthOS\Client\ApiClient;

$config = Configuration::getDefaultConfiguration();
$config->setHost(config('services.authos.url'));
$config->setAccessToken(session('authos_token'));

$apiClient = new ApiClient($config);
```

## Documentation

Full documentation: https://docs.authos.dev/sdk/php

## License

MIT
EOF

echo -e "${GREEN}✓ PHP SDK generated successfully!${NC}"
echo -e "Location: ${YELLOW}sdk/php/${NC}"
echo ""
echo "Next steps:"
echo "  1. cd sdk/php"
echo "  2. composer install"
echo "  3. Run tests: composer test"
