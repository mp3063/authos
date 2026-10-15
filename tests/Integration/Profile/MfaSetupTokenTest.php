<?php

namespace Tests\Integration\Profile;

use App\Models\Organization;
use App\Models\User;
use App\Services\Auth\MfaSetupTokenIssuer;
use Illuminate\Support\Facades\Mail;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class MfaSetupTokenTest extends IntegrationTestCase
{
    private function memberWhoMustSetUpMfa(): User
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => true]]);

        return User::factory()->forOrganization($organization)->create();
    }

    private function setupTokenFor(User $user): string
    {
        return app(MfaSetupTokenIssuer::class)->issue($user)['setup_token'];
    }

    private function withBearer(string $token): static
    {
        $this->app['auth']->forgetGuards();

        return $this->withHeader('Authorization', 'Bearer '.$token);
    }

    #[Test]
    public function it_issues_a_setup_token_that_expires_in_fifteen_minutes(): void
    {
        $user = $this->memberWhoMustSetUpMfa();

        $issued = app(MfaSetupTokenIssuer::class)->issue($user);

        $this->assertSame('Bearer', $issued['token_type']);
        $this->assertSame(900, $issued['expires_in']);
        $this->assertSame(['mfa.setup'], $user->tokens()->sole()->scopes);
    }

    #[Test]
    public function it_revokes_earlier_setup_tokens_when_issuing_a_new_one(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $otherToken = $user->createToken('Other Token', ['openid'])->token;
        $this->setupTokenFor($user);
        $this->setupTokenFor($user);

        $latest = $this->setupTokenFor($user);

        $this->assertSame(1, $user->tokens()->where('revoked', false)->where('name', 'MFA Setup Token')->count());
        $this->assertSame(3, $user->tokens()->where('name', 'MFA Setup Token')->count());
        $this->assertFalse($otherToken->fresh()->revoked);
        $this->withBearer($latest)->getJson('/api/v1/mfa/status')->assertOk();
    }

    #[Test]
    public function it_mints_the_setup_token_itself_with_a_fifteen_minute_lifetime(): void
    {
        $user = $this->memberWhoMustSetUpMfa();

        $token = $this->setupTokenFor($user);

        $claims = json_decode(base64_decode(strtr(explode('.', $token)[1], '-_', '+/')), true);
        $this->assertEqualsWithDelta(now()->addSeconds(900)->timestamp, $claims['exp'], 5);
        $this->assertEqualsWithDelta(now()->addSeconds(900)->timestamp, $user->tokens()->sole()->expires_at->timestamp, 5);
    }

    #[Test]
    public function it_leaves_the_lifetime_of_other_personal_access_tokens_alone(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $this->setupTokenFor($user);

        $token = $user->createToken('Full Token', ['*'])->getToken();

        $this->assertTrue($token->expires_at->greaterThan(now()->addMonths(5)));
    }

    #[Test]
    public function it_lets_a_setup_token_reach_the_mfa_enrollment_endpoints(): void
    {
        Mail::fake();
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $status = $this->withBearer($token)->getJson('/api/v1/mfa/status');
        $setup = $this->withBearer($token)->postJson('/api/v1/mfa/setup');
        $enable = $this->withBearer($token)->postJson('/api/v1/mfa/enable', ['code' => $this->totpCodeFor($user->fresh())]);

        $status->assertOk();
        $setup->assertOk();
        $enable->assertOk();
        $this->assertTrue($user->fresh()->hasMfaEnabled());
    }

    #[Test]
    public function it_lets_a_setup_token_log_out(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $logout = $this->withBearer($token)->postJson('/api/v1/auth/logout');
        $status = $this->withBearer($token)->getJson('/api/v1/mfa/status');

        $logout->assertOk();
        $status->assertUnauthorized();
    }

    #[Test]
    public function it_refuses_a_setup_token_on_the_public_mfa_verify_endpoint(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $response = $this->withBearer($token)->postJson('/api/v1/auth/mfa/verify', ['totp_code' => '123456']);

        $response->assertForbidden();
        $response->assertJsonPath('error', 'mfa_setup_required');
    }

    #[Test]
    public function it_rejects_an_expired_setup_token_on_the_public_mfa_verify_endpoint(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $this->travel(16)->minutes();
        $response = $this->withBearer($token)->postJson('/api/v1/auth/mfa/verify', ['totp_code' => '123456']);

        $response->assertUnauthorized();
        $response->assertJsonPath('error', 'setup_token_expired');
    }

    #[Test]
    public function it_refuses_a_setup_token_everywhere_else(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        foreach (['/api/v1/profile', '/api/v1/users', '/api/v1/oauth/userinfo', '/api/v1/enterprise/audit/exports'] as $uri) {
            $response = $this->withBearer($token)->getJson($uri);

            $response->assertForbidden();
            $response->assertJsonPath('error', 'mfa_setup_required');
        }
    }

    #[Test]
    public function it_accepts_a_setup_token_at_fourteen_minutes(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $this->travel(14)->minutes();
        $response = $this->withBearer($token)->getJson('/api/v1/mfa/status');

        $response->assertOk();
    }

    #[Test]
    public function it_refuses_a_setup_token_on_the_mfa_routes_outside_enrollment(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        foreach (['/api/v1/mfa/disable', '/api/v1/mfa/disable/totp', '/api/v1/mfa/recovery-codes', '/api/v1/mfa/recovery-codes/regenerate', '/api/v1/mfa/backup-codes/regenerate'] as $uri) {
            $response = $this->withBearer($token)->postJson($uri, ['password' => 'password']);

            $response->assertForbidden();
            $response->assertJsonPath('error', 'mfa_setup_required');
        }
    }

    #[Test]
    public function it_rejects_a_setup_token_after_fifteen_minutes(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);

        $this->travel(16)->minutes();
        $response = $this->withBearer($token)->getJson('/api/v1/mfa/status');

        $response->assertUnauthorized();
        $response->assertJsonPath('error', 'setup_token_expired');
    }

    #[Test]
    public function it_revokes_the_setup_token_when_mfa_is_enabled(): void
    {
        Mail::fake();
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);
        $this->withBearer($token)->postJson('/api/v1/mfa/setup')->assertOk();

        $this->withBearer($token)->postJson('/api/v1/mfa/enable', ['code' => $this->totpCodeFor($user->fresh())])->assertOk();
        $response = $this->withBearer($token)->getJson('/api/v1/mfa/status');

        $response->assertUnauthorized();
    }

    #[Test]
    public function it_revokes_the_setup_token_when_verify_totp_enables_mfa(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $this->setupTokenFor($user);
        $this->withBearer($token)->postJson('/api/v1/mfa/setup/totp')->assertOk();

        $this->withBearer($token)->postJson('/api/v1/mfa/verify/totp', ['code' => $this->totpCodeFor($user->fresh())])->assertOk();
        $response = $this->withBearer($token)->getJson('/api/v1/mfa/status');

        $response->assertUnauthorized();
    }

    #[Test]
    public function it_does_not_restrict_a_token_with_the_wildcard_scope(): void
    {
        $user = $this->memberWhoMustSetUpMfa();
        $token = $user->createToken('Full Token', ['*'])->accessToken;

        $response = $this->withBearer($token)->getJson('/api/v1/profile');

        $response->assertOk();
    }
}
