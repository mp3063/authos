<?php

namespace Tests\Unit\Policies;

use App\Models\AccountLockout;
use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\BulkImportJob;
use App\Models\CustomRole;
use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class AuditAndSecurityPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    private const ABILITIES = ['viewAny', 'view', 'create', 'update', 'delete', 'deleteAny', 'restore', 'forceDelete'];

    #[Test]
    #[DataProvider('auditExportMatrix')]
    public function it_applies_the_matrix_to_audit_exports(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, AuditExport::class,
            fn (int $organizationId) => AuditExport::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('authenticationLogMatrix')]
    public function it_applies_the_matrix_to_authentication_logs(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, AuthenticationLog::class,
            fn (int $organizationId) => AuthenticationLog::factory()->create([
                'user_id' => User::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('bulkImportJobMatrix')]
    public function it_applies_the_matrix_to_bulk_import_jobs(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, BulkImportJob::class,
            fn (int $organizationId) => BulkImportJob::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('migrationJobMatrix')]
    public function it_applies_the_matrix_to_migration_jobs(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, MigrationJob::class,
            fn (int $organizationId) => MigrationJob::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('securityIncidentMatrix')]
    public function it_applies_the_matrix_to_security_incidents(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, SecurityIncident::class,
            fn (int $organizationId) => SecurityIncident::factory()->create([
                'organization_id' => $organizationId,
                'user_id' => User::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('accountLockoutMatrix')]
    public function it_applies_the_matrix_to_account_lockouts(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, AccountLockout::class,
            fn (int $organizationId) => AccountLockout::factory()->create([
                'user_id' => User::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('globalTableMatrix')]
    public function it_restricts_the_ip_blocklist_to_super_admins(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, IpBlocklist::class,
            fn () => IpBlocklist::factory()->create(), $sameOrg);
    }

    #[Test]
    #[DataProvider('globalTableMatrix')]
    public function it_restricts_failed_login_attempts_to_super_admins(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, FailedLoginAttempt::class,
            fn () => FailedLoginAttempt::factory()->create(), $sameOrg);
    }

    #[Test]
    public function it_scopes_an_incident_without_an_organization_id_to_its_users_organization(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $incident = SecurityIncident::factory()->create([
            'organization_id' => null,
            'user_id' => User::factory()->create(['organization_id' => $owner->organization_id])->id,
        ]);
        $foreign = SecurityIncident::factory()->create([
            'organization_id' => null,
            'user_id' => User::factory()->create(['organization_id' => Organization::factory()->create()->id])->id,
        ]);

        $this->assertTrue(Gate::forUser($owner)->allows('update', $incident));
        $this->assertFalse(Gate::forUser($owner)->allows('update', $foreign));
    }

    #[Test]
    public function it_denies_an_incident_without_user_or_organization_to_non_super_admins(): void
    {
        $owner = $this->createUser([], 'Organization Owner', 'web');
        $incident = SecurityIncident::factory()->create(['organization_id' => null, 'user_id' => null]);

        $this->assertFalse(Gate::forUser($owner)->allows('view', $incident));
        $this->assertFalse(Gate::forUser($owner)->allows('update', $incident));
    }

    public static function auditExportMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTTFTTTF',
            'Organization Admin' => 'TTFFFFFF',
            'Auditor' => 'TTTFTTTF',
            'User' => 'FFFFFFFF',
        ], ['custom:auth_logs.export' => ['create', true], 'custom:auth_logs.read' => ['view', true]]);
    }

    public static function authenticationLogMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFFFFFF',
            'Organization Admin' => 'TTFFFFFF',
            'Auditor' => 'TTFFFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:auth_logs.read' => ['view', true], 'custom:auth_logs.export' => ['delete', false]]);
    }

    public static function bulkImportJobMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTTTTTTF',
            'Organization Admin' => 'TTTTFFFF',
            'User' => 'TTFFFFFF',
        ], ['custom:users.create' => ['update', true], 'custom:users.delete' => ['delete', true]]);
    }

    public static function migrationJobMatrix(): array
    {
        return self::matrix([
            'Super Admin' => 'TTTTTTTT',
            'Organization Owner' => 'TTFTFFFF',
            'Organization Admin' => 'TTFFFFFF',
            'User' => 'TTFFFFFF',
        ], ['custom:organizations.update' => ['update', true]]);
    }

    public static function securityIncidentMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFTFFFF',
            'Organization Admin' => 'TTFFFFFF',
            'Auditor' => 'TTFFFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:organizations.update' => ['update', true], 'custom:auth_logs.read' => ['view', true]]);
    }

    public static function accountLockoutMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFTFFFF',
            'Organization Admin' => 'TTFTFFFF',
            'Auditor' => 'TTFFFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:users.update' => ['update', true], 'custom:auth_logs.read' => ['view', true]]);
    }

    public static function globalTableMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'FFFFFFFF',
            'Organization Admin' => 'FFFFFFFF',
            'Auditor' => 'FFFFFFFF',
            'User' => 'FFFFFFFF',
            'Super Admin' => 'TTTTTTTT',
        ], [], false);
    }

    /**
     * @param  array<string, string>  $roles
     * @param  array<string, array{0: string, 1: bool}>  $extra
     * @return list<array{0: string, 1: string, 2: bool, 3: bool}>
     */
    private static function matrix(array $roles, array $extra, bool $orgScoped = true): array
    {
        $rows = [];

        foreach ($roles as $role => $cells) {
            foreach (self::ABILITIES as $index => $ability) {
                $rows[] = [$role, $ability, true, $cells[$index] === 'T'];
            }
        }

        foreach ($orgScoped ? ['view', 'update', 'delete'] : [] as $ability) {
            $rows[] = ['Organization Owner', $ability, false, false];
        }

        foreach ($extra as $role => [$ability, $expected]) {
            $rows[] = [$role, $ability, true, $expected];
        }

        if ($orgScoped) {
            $rows[] = ['no organization', 'viewAny', true, false];
            $rows[] = ['no organization', 'view', true, false];
            $rows[] = ['no organization', 'deleteAny', true, false];
        }

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
