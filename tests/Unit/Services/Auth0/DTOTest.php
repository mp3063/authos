<?php

declare(strict_types=1);

namespace Tests\Unit\Services\Auth0;

use App\Services\Auth0\DTOs\Auth0ClientDTO;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\DTOs\Auth0RoleDTO;
use App\Services\Auth0\DTOs\Auth0UserDTO;
use Tests\TestCase;

class DTOTest extends TestCase
{
    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_user_dto_from_array(): void
    {
        $data = [
            'user_id' => 'auth0|123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'email_verified' => true,
            'app_metadata' => ['role' => 'admin'],
            'user_metadata' => ['preferences' => []],
            'identities' => [
                ['provider' => 'auth0', 'user_id' => '123', 'isSocial' => false],
            ],
            'picture' => 'https://example.com/avatar.jpg',
        ];

        $dto = Auth0UserDTO::fromArray($data);

        $this->assertEquals('auth0|123', $dto->userId);
        $this->assertEquals('test@example.com', $dto->email);
        $this->assertEquals('Test User', $dto->name);
        $this->assertTrue($dto->emailVerified);
        $this->assertEquals(['role' => 'admin'], $dto->appMetadata);
        $this->assertEquals('https://example.com/avatar.jpg', $dto->picture);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_detects_mfa_enabled_user(): void
    {
        $dto = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: ['mfa_enabled' => true],
            userMetadata: [],
            identities: [],
        );

        $this->assertTrue($dto->hasMFA());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_extracts_social_connections(): void
    {
        $dto = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [
                ['provider' => 'google-oauth2', 'user_id' => 'google123', 'isSocial' => true, 'connection' => 'google'],
                ['provider' => 'auth0', 'user_id' => '123', 'isSocial' => false, 'connection' => 'Username-Password-Authentication'],
            ],
        );

        $social = $dto->getSocialConnections();

        $this->assertCount(1, $social);
        $this->assertEquals('google-oauth2', $social[0]['provider']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_identifies_database_user(): void
    {
        $dto = new Auth0UserDTO(
            userId: 'auth0|123',
            email: 'test@example.com',
            name: 'Test User',
            emailVerified: true,
            appMetadata: [],
            userMetadata: [],
            identities: [
                ['provider' => 'auth0', 'user_id' => '123', 'isSocial' => false],
            ],
        );

        $this->assertTrue($dto->isDatabaseUser());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_client_dto_from_array(): void
    {
        $data = [
            'client_id' => 'client123',
            'name' => 'Test App',
            'app_type' => 'spa',
            'callbacks' => ['https://example.com/callback'],
            'allowed_logout_urls' => ['https://example.com/logout'],
            'allowed_origins' => ['https://example.com'],
            'web_origins' => ['https://example.com'],
            'grant_types' => ['authorization_code'],
            'client_metadata' => [],
        ];

        $dto = Auth0ClientDTO::fromArray($data);

        $this->assertEquals('client123', $dto->clientId);
        $this->assertEquals('Test App', $dto->name);
        $this->assertEquals('spa', $dto->appType);
        $this->assertTrue($dto->isSPA());
        $this->assertTrue($dto->supportsPKCE());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_identifies_client_types(): void
    {
        $spa = new Auth0ClientDTO(
            clientId: 'spa123',
            name: 'SPA',
            appType: 'spa',
            callbacks: [],
            allowedLogoutUrls: [],
            allowedOrigins: [],
            webOrigins: [],
            grantTypes: [],
            clientMetadata: [],
        );

        $native = new Auth0ClientDTO(
            clientId: 'native123',
            name: 'Native',
            appType: 'native',
            callbacks: [],
            allowedLogoutUrls: [],
            allowedOrigins: [],
            webOrigins: [],
            grantTypes: [],
            clientMetadata: [],
        );

        $this->assertTrue($spa->isSPA());
        $this->assertTrue($native->isNative());
        $this->assertFalse($spa->requiresClientSecret());
        $this->assertFalse($native->requiresClientSecret());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_organization_dto_from_array(): void
    {
        $data = [
            'id' => 'org123',
            'name' => 'test-org',
            'display_name' => 'Test Organization',
            'metadata' => ['key' => 'value'],
            'branding' => [
                'logo_url' => 'https://example.com/logo.png',
                'colors' => [
                    'primary' => '#000000',
                    'page_background' => '#FFFFFF',
                ],
            ],
        ];

        $dto = Auth0OrganizationDTO::fromArray($data);

        $this->assertEquals('org123', $dto->id);
        $this->assertEquals('test-org', $dto->name);
        $this->assertEquals('Test Organization', $dto->displayName);
        $this->assertTrue($dto->hasCustomBranding());
        $this->assertEquals('https://example.com/logo.png', $dto->getLogoUrl());
        $this->assertEquals('#000000', $dto->getPrimaryColor());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_creates_role_dto_from_array(): void
    {
        $data = [
            'id' => 'role123',
            'name' => 'custom-role',
            'description' => 'Custom Role',
            'permissions' => [
                ['permission_name' => 'read:users', 'resource_server_identifier' => 'api'],
                ['permission_name' => 'write:users', 'resource_server_identifier' => 'api'],
            ],
        ];

        $dto = Auth0RoleDTO::fromArray($data);

        $this->assertEquals('role123', $dto->id);
        $this->assertEquals('custom-role', $dto->name);
        $this->assertEquals('Custom Role', $dto->description);
        $this->assertCount(2, $dto->permissions);
        $this->assertTrue($dto->hasPermission('read:users'));
        $this->assertFalse($dto->isSystemRole());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_identifies_system_roles(): void
    {
        $systemRole = new Auth0RoleDTO(
            id: 'role123',
            name: 'admin',
            description: 'Admin Role',
        );

        $customRole = new Auth0RoleDTO(
            id: 'role456',
            name: 'custom-role',
            description: 'Custom Role',
        );

        $this->assertTrue($systemRole->isSystemRole());
        $this->assertFalse($customRole->isSystemRole());
    }
}
