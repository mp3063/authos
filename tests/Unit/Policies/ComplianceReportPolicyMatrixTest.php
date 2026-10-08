<?php

namespace Tests\Unit\Policies;

use App\Models\ComplianceReport;
use App\Models\CustomRole;
use App\Models\Organization;
use App\Models\ScheduledComplianceReport;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class ComplianceReportPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    private const ABILITIES = ['viewAny', 'view', 'create', 'update', 'delete', 'deleteAny', 'restore', 'forceDelete'];

    #[Test]
    #[DataProvider('complianceReportMatrix')]
    public function it_applies_the_matrix_to_compliance_reports(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, ComplianceReport::class,
            fn (int $organizationId) => ComplianceReport::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('complianceReportMatrix')]
    public function it_applies_the_matrix_to_scheduled_compliance_reports(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, ScheduledComplianceReport::class,
            fn (int $organizationId) => ScheduledComplianceReport::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    public static function complianceReportMatrix(): array
    {
        $roles = [
            'Organization Owner' => 'TTTTTTTF',
            'Organization Admin' => 'TTFFFFFF',
            'Auditor' => 'TTTTTTTF',
            'User' => 'FFFFFFFF',
        ];
        $rows = [];

        foreach ($roles as $role => $cells) {
            foreach (self::ABILITIES as $index => $ability) {
                $rows[] = [$role, $ability, true, $cells[$index] === 'T'];
            }
        }

        foreach (['view', 'update', 'delete'] as $ability) {
            $rows[] = ['Organization Owner', $ability, false, false];
        }

        $rows[] = ['custom:auth_logs.export', 'update', true, true];
        $rows[] = ['custom:auth_logs.read', 'view', true, true];
        $rows[] = ['custom:auth_logs.read', 'update', true, false];
        $rows[] = ['no organization', 'viewAny', true, false];
        $rows[] = ['no organization', 'view', true, false];
        $rows[] = ['no organization', 'create', true, false];
        $rows[] = ['no organization', 'deleteAny', true, false];

        return $rows;
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
        $record = $makeRecord($organizationId ?? Organization::factory()->create()->id);

        $this->assertSame($expected, Gate::forUser($actor)->allows($ability, $record));
    }
}
