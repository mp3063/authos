<?php

namespace Tests\Unit\Models;

use App\Models\Organization;
use App\Models\User;
use App\Services\Auth\MfaCodeVerifier;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class MfaRequirementTest extends TestCase
{
    private function organizationRequiringMfa(mixed $value = true): Organization
    {
        return Organization::factory()->create(['settings' => ['require_mfa' => $value]]);
    }

    #[Test]
    public function it_requires_mfa_for_a_member_of_an_organization_that_requires_it(): void
    {
        $user = User::factory()->forOrganization($this->organizationRequiringMfa())->create();

        $this->assertTrue($user->requiresMfa());
        $this->assertTrue($user->mustSetUpMfa());
    }

    #[Test]
    public function it_requires_mfa_for_a_user_who_enabled_it_in_an_organization_that_does_not(): void
    {
        $organization = Organization::factory()->create(['settings' => ['require_mfa' => false]]);
        $user = User::factory()->forOrganization($organization)->withMfa()->create();

        $this->assertTrue($user->requiresMfa());
        $this->assertFalse($user->mustSetUpMfa());
    }

    #[Test]
    public function it_does_not_require_mfa_for_a_super_admin_without_an_organization_and_without_mfa(): void
    {
        $user = User::factory()->create(['organization_id' => null]);

        $this->assertFalse($user->requiresMfa());
        $this->assertFalse($user->mustSetUpMfa());
    }

    #[Test]
    public function it_says_a_member_must_set_up_mfa_only_while_they_have_none(): void
    {
        $user = User::factory()->forOrganization($this->organizationRequiringMfa())->create();
        $this->assertTrue($user->mustSetUpMfa());

        $user->update(['mfa_methods' => ['totp']]);

        $this->assertFalse($user->fresh()->mustSetUpMfa());
        $this->assertTrue($user->fresh()->requiresMfa());
    }

    #[Test]
    public function it_treats_a_string_false_setting_as_not_required(): void
    {
        $this->assertFalse($this->organizationRequiringMfa('false')->requiresMfa());
        $this->assertFalse($this->organizationRequiringMfa(0)->requiresMfa());
        $this->assertFalse(Organization::factory()->create(['settings' => null])->requiresMfa());
    }

    #[Test]
    public function it_treats_truthy_string_settings_as_required(): void
    {
        $this->assertTrue($this->organizationRequiringMfa('1')->requiresMfa());
        $this->assertTrue($this->organizationRequiringMfa('true')->requiresMfa());
        $this->assertTrue($this->organizationRequiringMfa(1)->requiresMfa());
    }

    #[Test]
    public function it_builds_users_with_mfa_whose_codes_verify(): void
    {
        $user = User::factory()->withMfa()->create();

        $this->assertTrue(app(MfaCodeVerifier::class)->verifyTotpCode($user, $this->totpCodeFor($user)));
        $this->assertCount(8, $user->fresh()->two_factor_recovery_codes);
    }
}
