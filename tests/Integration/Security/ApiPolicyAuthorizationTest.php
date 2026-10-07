<?php

namespace Tests\Integration\Security;

use App\Models\SSOConfiguration;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ApiPolicyAuthorizationTest extends IntegrationTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(['api', 'auth:api'])->put('api/v1/policy-probe/sso-configurations/{id}', function (string $id) {
            Gate::authorize('update', SSOConfiguration::findOrFail($id));

            return response()->json(['authorized' => true]);
        });

        Route::middleware(['api', 'auth:api'])->get('api/v1/policy-probe/permission', function () {
            Gate::authorize('organizations.delete');

            return response()->json(['authorized' => true]);
        });
    }

    #[Test]
    public function it_lets_a_policy_allow_an_organization_owner_on_an_api_route(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'api');
        $config = $this->createSsoConfigurationFor($owner);

        $this->actingAsApiUserWithToken($owner)
            ->putJson("/api/v1/policy-probe/sso-configurations/{$config->id}")
            ->assertOk();
    }

    #[Test]
    public function it_lets_a_policy_deny_a_regular_member_on_an_api_route(): void
    {
        $member = $this->createApiUser();
        $config = $this->createSsoConfigurationFor($member);

        $this->actingAsApiUserWithToken($member)
            ->putJson("/api/v1/policy-probe/sso-configurations/{$config->id}")
            ->assertForbidden();
    }

    #[Test]
    public function it_lets_a_policy_deny_an_owner_of_another_organization_on_an_api_route(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'api');
        $config = $this->createSsoConfigurationFor($this->createApiUser());

        $this->actingAsApiUserWithToken($owner)
            ->putJson("/api/v1/policy-probe/sso-configurations/{$config->id}")
            ->assertForbidden();
    }

    #[Test]
    public function it_still_denies_a_permission_the_api_user_lacks(): void
    {
        $member = $this->createApiUser();

        $this->actingAsApiUserWithToken($member)
            ->getJson('/api/v1/policy-probe/permission')
            ->assertForbidden();
    }

    private function createSsoConfigurationFor(User $organizationMember): SSOConfiguration
    {
        $application = $this->createOAuthApplication(['organization_id' => $organizationMember->organization_id]);

        return SSOConfiguration::factory()->create(['application_id' => $application->id]);
    }
}
