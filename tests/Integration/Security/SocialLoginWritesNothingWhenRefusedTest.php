<?php

namespace Tests\Integration\Security;

use App\Models\Organization;
use App\Models\SocialAccount;
use App\Models\User;
use Illuminate\Support\Facades\Config;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use Mockery;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class SocialLoginWritesNothingWhenRefusedTest extends IntegrationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Config::set('services.google', ['client_id' => 'google-client', 'client_secret' => 'secret', 'redirect' => 'http://localhost/callback']);
        Config::set('services.github', ['client_id' => 'github-client', 'client_secret' => 'secret', 'redirect' => 'http://localhost/callback']);
    }

    private function fakeProviderUser(string $provider, string $providerId, string $email): void
    {
        $socialUser = (new SocialiteTwoUser)
            ->setRaw(['id' => $providerId])
            ->map(['id' => $providerId, 'name' => 'Social User', 'email' => $email, 'nickname' => null, 'avatar' => null])
            ->setToken('provider-token');

        $driver = Mockery::mock();
        $driver->shouldReceive('stateless')->andReturnSelf();
        $driver->shouldReceive('user')->andReturn($socialUser);
        Socialite::shouldReceive('driver')->with($provider)->andReturn($driver);
    }

    #[Test]
    public function it_does_not_link_a_provider_to_an_mfa_account_found_by_email_on_the_api_path(): void
    {
        $user = User::factory()->withMfa()->forOrganization(Organization::factory()->create())->create();
        $this->fakeProviderUser('github', 'github-attacker', $user->email);

        $response = $this->getJson('/api/v1/auth/social/github/callback');

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonStructure(['challenge_token']);
        $this->assertDatabaseMissing('social_accounts', ['provider' => 'github']);
        $this->assertNull($user->fresh()->provider_id);
    }

    #[Test]
    public function it_still_signs_in_an_mfa_user_through_an_existing_link(): void
    {
        $user = User::factory()->withMfa()->forOrganization(Organization::factory()->create())->create([
            'provider' => 'github',
            'provider_id' => 'github-linked',
        ]);
        SocialAccount::create(['user_id' => $user->id, 'provider' => 'github', 'provider_id' => 'github-linked', 'email' => $user->email]);
        $this->fakeProviderUser('github', 'github-linked', $user->email);

        $response = $this->getJson('/api/v1/auth/social/github/callback');

        $response->assertStatus(202)
            ->assertJsonPath('mfa_required', true)
            ->assertJsonStructure(['challenge_token'])
            ->assertJsonMissingPath('data.access_token');
        $this->assertSame(0, $user->tokens()->count());
    }

    #[Test]
    public function it_does_not_create_a_user_when_the_web_path_refuses_an_unknown_email(): void
    {
        Organization::factory()->create(['is_active' => true]);
        $usersBefore = User::count();
        $this->fakeProviderUser('google', 'google-stranger', 'stranger@example.com');

        $response = $this->get('/auth/social/google/callback');

        $response->assertRedirect('/admin/login?error=insufficient_privileges');
        $this->assertGuest();
        $this->assertSame($usersBefore, User::count());
        $this->assertDatabaseMissing('users', ['email' => 'stranger@example.com']);
        $this->assertDatabaseMissing('social_accounts', ['provider_id' => 'google-stranger']);
    }

    #[Test]
    public function it_does_not_link_a_provider_when_the_web_path_refuses_a_user_without_panel_access(): void
    {
        $user = User::factory()->forOrganization(Organization::factory()->create())->create();
        $this->fakeProviderUser('google', 'google-member', $user->email);

        $response = $this->get('/auth/social/google/callback');

        $response->assertRedirect('/admin/login?error=insufficient_privileges');
        $this->assertGuest();
        $this->assertDatabaseMissing('social_accounts', ['user_id' => $user->id]);
        $this->assertNull($user->fresh()->provider_id);
    }

    #[Test]
    public function it_signs_up_a_new_api_social_user_without_an_organization_when_no_slug_is_given(): void
    {
        Organization::factory()->create(['is_active' => true]);
        $this->fakeProviderUser('github', 'github-newcomer', 'newcomer@example.com');

        $response = $this->getJson('/api/v1/auth/social/github/callback');

        $response->assertOk()->assertJsonPath('data.user.organization', null);
        $this->assertNull(User::where('email', 'newcomer@example.com')->sole()->organization_id);
    }

    #[Test]
    public function it_refuses_an_api_social_sign_up_into_an_organization_that_disallows_registration(): void
    {
        $organization = Organization::factory()->create(['settings' => ['allow_registration' => false]]);
        $usersBefore = User::count();
        $this->fakeProviderUser('github', 'github-closed', 'closed@example.com');

        $response = $this->getJson('/api/v1/auth/social/github/callback?organization='.$organization->slug);

        $response->assertStatus(400)->assertJsonPath('success', false)->assertJsonMissingPath('data.access_token');
        $this->assertSame($usersBefore, User::count());
        $this->assertDatabaseMissing('social_accounts', ['provider_id' => 'github-closed']);
    }
}
