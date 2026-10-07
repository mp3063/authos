<?php

namespace Tests\Unit\Policies;

use App\Models\Application;
use App\Models\Organization;
use App\Models\User;
use App\Models\UserApplication;
use App\Policies\UserApplicationPolicy;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class UserApplicationPolicyTest extends TestCase
{
    private UserApplicationPolicy $policy;

    private Organization $organization;

    private UserApplication $assignment;

    protected function setUp(): void
    {
        parent::setUp();

        $this->policy = new UserApplicationPolicy;
        $this->organization = Organization::factory()->create();
        $member = User::factory()->create(['organization_id' => $this->organization->id]);
        $application = Application::factory()->create(['organization_id' => $this->organization->id]);
        $this->assignment = (new UserApplication)->forceFill([
            'user_id' => $member->id,
            'application_id' => $application->id,
        ]);
    }

    #[Test]
    public function admin_of_the_same_organization_can_manage_the_assignment(): void
    {
        $admin = $this->createUser(['organization_id' => $this->organization->id], 'Organization Admin');

        $this->assertTrue($this->policy->view($admin, $this->assignment));
        $this->assertTrue($this->policy->update($admin, $this->assignment));
        $this->assertTrue($this->policy->delete($admin, $this->assignment));
    }

    #[Test]
    public function admin_of_another_organization_cannot_manage_the_assignment(): void
    {
        $outsider = $this->createUser([], 'Organization Admin');

        $this->assertFalse($this->policy->view($outsider, $this->assignment));
        $this->assertFalse($this->policy->update($outsider, $this->assignment));
        $this->assertFalse($this->policy->delete($outsider, $this->assignment));
        $this->assertFalse($this->policy->restore($outsider, $this->assignment));
    }

    #[Test]
    public function assigned_user_can_view_their_own_assignment(): void
    {
        $member = User::find($this->assignment->user_id);

        $this->assertTrue($this->policy->view($member, $this->assignment));
    }

    #[Test]
    public function super_admin_can_manage_assignments_in_any_organization(): void
    {
        $superAdmin = $this->createUser([], 'Super Admin');

        $this->assertTrue($this->policy->update($superAdmin, $this->assignment));
        $this->assertTrue($this->policy->delete($superAdmin, $this->assignment));
    }
}
