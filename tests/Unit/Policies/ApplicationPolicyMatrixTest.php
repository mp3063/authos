<?php

namespace Tests\Unit\Policies;

use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\User;
use App\Models\UserApplication;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ApplicationPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    #[Test]
    #[DataProvider('applicationMatrix')]
    public function it_applies_the_matrix_to_applications(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, Application::class,
            fn (int $organizationId) => Application::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('applicationGroupMatrix')]
    public function it_applies_the_matrix_to_application_groups(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, ApplicationGroup::class,
            fn (int $organizationId) => ApplicationGroup::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('userApplicationMatrix')]
    public function it_applies_the_matrix_to_user_applications(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $actor = $this->actor($role);

        $this->assertAbility($expected, $actor, $ability, UserApplication::class,
            function (int $organizationId): UserApplication {
                $member = User::factory()->create(['organization_id' => $organizationId]);
                $application = Application::factory()->create(['organization_id' => $organizationId]);

                return (new UserApplication)->forceFill(['user_id' => $member->id, 'application_id' => $application->id]);
            }, $sameOrg);
    }

    #[Test]
    public function it_lets_a_plain_member_view_their_own_assignment_in_any_organization(): void
    {
        $member = $this->createUser([], 'User', 'web');
        $other = $this->createUser([], 'User', 'web');
        $application = Application::factory()->create(['organization_id' => $other->organization_id]);
        $assignment = (new UserApplication)->forceFill(['user_id' => $member->id, 'application_id' => $application->id]);

        $this->assertTrue(Gate::forUser($member)->allows('view', $assignment));
        $this->assertFalse(Gate::forUser($member)->allows('update', $assignment));
    }

    public static function applicationMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'restore', false, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, true],
            ['Organization Admin', 'update', true, true],
            ['Organization Admin', 'update', false, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['Application Manager', 'viewAny', true, true],
            ['Application Manager', 'view', true, true],
            ['Application Manager', 'create', true, true],
            ['Application Manager', 'update', true, true],
            ['Application Manager', 'update', false, false],
            ['Application Manager', 'delete', true, false],
            ['Application Manager', 'deleteAny', true, false],
            ['Application Manager', 'restore', true, false],
            ['Application Manager', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:applications.delete', 'delete', true, true],
            ['no organization', 'viewAny', true, false],
            ['no organization', 'create', true, false],
        ];
    }

    public static function applicationGroupMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'restore', false, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, true],
            ['Organization Admin', 'update', true, true],
            ['Organization Admin', 'update', false, false],
            ['Organization Admin', 'delete', true, false],
            ['Organization Admin', 'deleteAny', true, false],
            ['Organization Admin', 'restore', true, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['Application Manager', 'viewAny', true, true],
            ['Application Manager', 'view', true, true],
            ['Application Manager', 'create', true, true],
            ['Application Manager', 'update', true, true],
            ['Application Manager', 'update', false, false],
            ['Application Manager', 'delete', true, false],
            ['Application Manager', 'deleteAny', true, false],
            ['Application Manager', 'restore', true, false],
            ['Application Manager', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:applications.delete', 'delete', true, true],
            ['no organization', 'viewAny', true, false],
            ['no organization', 'create', true, false],
        ];
    }

    public static function userApplicationMatrix(): array
    {
        return [
            ['Organization Owner', 'viewAny', true, true],
            ['Organization Owner', 'view', true, true],
            ['Organization Owner', 'view', false, false],
            ['Organization Owner', 'create', true, true],
            ['Organization Owner', 'update', true, true],
            ['Organization Owner', 'update', false, false],
            ['Organization Owner', 'delete', true, true],
            ['Organization Owner', 'delete', false, false],
            ['Organization Owner', 'deleteAny', true, true],
            ['Organization Owner', 'restore', true, true],
            ['Organization Owner', 'restore', false, false],
            ['Organization Owner', 'forceDelete', true, false],
            ['Organization Admin', 'viewAny', true, true],
            ['Organization Admin', 'view', true, true],
            ['Organization Admin', 'view', false, false],
            ['Organization Admin', 'create', true, true],
            ['Organization Admin', 'update', true, true],
            ['Organization Admin', 'update', false, false],
            ['Organization Admin', 'delete', true, true],
            ['Organization Admin', 'delete', false, false],
            ['Organization Admin', 'deleteAny', true, true],
            ['Organization Admin', 'restore', true, true],
            ['Organization Admin', 'restore', false, false],
            ['Organization Admin', 'forceDelete', true, false],
            ['Application Manager', 'viewAny', true, true],
            ['Application Manager', 'view', true, true],
            ['Application Manager', 'create', true, true],
            ['Application Manager', 'update', true, true],
            ['Application Manager', 'update', false, false],
            ['Application Manager', 'delete', true, true],
            ['Application Manager', 'deleteAny', true, true],
            ['Application Manager', 'restore', true, true],
            ['Application Manager', 'forceDelete', true, false],
            ['User', 'viewAny', true, true],
            ['User', 'view', true, true],
            ['User', 'view', false, false],
            ['User', 'create', true, false],
            ['User', 'update', true, false],
            ['User', 'update', false, false],
            ['User', 'delete', true, false],
            ['User', 'deleteAny', true, false],
            ['User', 'restore', true, false],
            ['User', 'forceDelete', true, false],
            ['custom:applications.update', 'update', true, true],
            ['no organization', 'viewAny', true, false],
        ];
    }

    private function actor(string $role): User
    {
        if ($role === 'no organization') {
            $user = $this->createUser([], 'Organization Owner', 'web');
            $user->update(['organization_id' => null]);

            return $user;
        }

        if (str_starts_with($role, 'custom:')) {
            $user = $this->createUser([], 'User', 'web');
            CustomRole::factory()->forOrganization($user->organization)
                ->create(['permissions' => [substr($role, strlen('custom:'))]])
                ->assignToUser($user);

            return $user;
        }

        return $this->createUser([], $role, 'web');
    }

    /**
     * @param  class-string<Model>  $modelClass
     * @param  callable(int): Model  $makeRecord
     */
    private function assertAbility(bool $expected, User $actor, string $ability, string $modelClass, callable $makeRecord, bool $sameOrg): void
    {
        if (in_array($ability, self::RECORDLESS_ABILITIES, true)) {
            $this->assertSame($expected, Gate::forUser($actor)->allows($ability, $modelClass));

            return;
        }

        $organizationId = $sameOrg ? $actor->organization_id : Organization::factory()->create()->id;
        $record = $makeRecord($organizationId);

        $this->assertSame($expected, Gate::forUser($actor)->allows($ability, $record));
    }
}
