<?php

namespace Tests\Feature\Auth;

use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class LoginScopesTest extends IntegrationTestCase
{
    #[Test]
    public function it_reaches_a_scope_gated_endpoint_with_a_scope_requested_at_login(): void
    {
        $organization = $this->createOrganization();
        $owner = $this->createApiOrganizationOwner(['organization_id' => $organization->id]);

        $token = $this->login($owner->email, ['openid', 'enterprise.audit.read']);

        $this->withToken($token)->getJson('/api/v1/enterprise/audit/exports')->assertOk();
    }

    #[Test]
    public function it_still_refuses_a_scope_gated_endpoint_without_the_scope(): void
    {
        $organization = $this->createOrganization();
        $owner = $this->createApiOrganizationOwner(['organization_id' => $organization->id]);

        $token = $this->login($owner->email, ['openid']);

        $this->withToken($token)->getJson('/api/v1/enterprise/audit/exports')->assertForbidden();
    }

    #[Test]
    public function it_does_not_let_a_requested_scope_bypass_permissions(): void
    {
        $organization = $this->createOrganization();
        $member = $this->createApiUser(['organization_id' => $organization->id]);

        $token = $this->login($member->email, ['openid', 'enterprise.audit.read']);

        $this->withToken($token)->getJson('/api/v1/enterprise/audit/exports')->assertForbidden();
    }

    #[Test]
    public function it_rejects_scopes_that_are_not_registered_or_grant_full_access(): void
    {
        $user = $this->createApiUser(['organization_id' => $this->createOrganization()->id]);

        foreach (['admin', '*', 'not.a.scope'] as $scope) {
            $this->postJson('/api/v1/auth/login', [
                'email' => $user->email,
                'password' => 'password',
                'scopes' => ['openid', $scope],
            ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
        }
    }

    private function login(string $email, array $scopes): string
    {
        return $this->postJson('/api/v1/auth/login', [
            'email' => $email,
            'password' => 'password',
            'scopes' => $scopes,
        ])->assertOk()->json('access_token');
    }
}
