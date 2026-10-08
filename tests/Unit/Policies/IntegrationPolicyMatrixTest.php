<?php

namespace Tests\Unit\Policies;

use App\Models\Application;
use App\Models\CustomDomain;
use App\Models\CustomRole;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\SocialAccount;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use App\Models\WebhookEvent;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class IntegrationPolicyMatrixTest extends TestCase
{
    private const RECORDLESS_ABILITIES = ['viewAny', 'create', 'deleteAny'];

    private const ABILITIES = ['viewAny', 'view', 'create', 'update', 'delete', 'deleteAny', 'restore', 'forceDelete'];

    #[Test]
    #[DataProvider('ssoConfigurationMatrix')]
    public function it_applies_the_matrix_to_sso_configurations(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, SSOConfiguration::class,
            fn (int $organizationId) => SSOConfiguration::factory()->forOrganization(Organization::findOrFail($organizationId))->create(), $sameOrg);
    }

    #[Test]
    #[DataProvider('ldapConfigurationMatrix')]
    public function it_applies_the_matrix_to_ldap_configurations(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, LdapConfiguration::class,
            fn (int $organizationId) => LdapConfiguration::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('ldapConfigurationMatrix')]
    public function it_applies_the_matrix_to_custom_domains(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, CustomDomain::class,
            fn (int $organizationId) => CustomDomain::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('ssoSessionMatrix')]
    public function it_applies_the_matrix_to_sso_sessions(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, SSOSession::class,
            fn (int $organizationId) => SSOSession::factory()->create([
                'user_id' => User::factory()->create(['organization_id' => $organizationId])->id,
                'application_id' => Application::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('socialAccountMatrix')]
    public function it_applies_the_matrix_to_social_accounts(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, SocialAccount::class,
            fn (int $organizationId) => SocialAccount::factory()->create([
                'user_id' => User::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('webhookMatrix')]
    public function it_applies_the_matrix_to_webhooks(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, Webhook::class,
            fn (int $organizationId) => Webhook::factory()->create(['organization_id' => $organizationId]), $sameOrg);
    }

    #[Test]
    #[DataProvider('webhookDeliveryMatrix')]
    public function it_applies_the_matrix_to_webhook_deliveries(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $this->assertAbility($expected, $this->actor($role), $ability, WebhookDelivery::class,
            fn (int $organizationId) => WebhookDelivery::factory()->create([
                'webhook_id' => Webhook::factory()->create(['organization_id' => $organizationId])->id,
            ]), $sameOrg);
    }

    #[Test]
    #[DataProvider('webhookEventMatrix')]
    public function it_applies_the_matrix_to_webhook_events(string $role, string $ability, bool $sameOrg, bool $expected): void
    {
        $event = WebhookEvent::query()->create(['name' => 'matrix.event', 'category' => 'test', 'description' => 'x', 'is_active' => true]);

        $this->assertAbility($expected, $this->actor($role), $ability, WebhookEvent::class, fn () => $event, $sameOrg);
    }

    #[Test]
    public function it_lets_a_plain_member_manage_their_own_sso_session_in_any_organization(): void
    {
        $member = $this->createUser([], 'User', 'web');
        $session = SSOSession::factory()->create([
            'user_id' => $member->id,
            'application_id' => Application::factory()->create(['organization_id' => Organization::factory()->create()->id])->id,
        ]);

        foreach (['view', 'update', 'delete'] as $ability) {
            $this->assertTrue(Gate::forUser($member)->allows($ability, $session), $ability);
        }
    }

    #[Test]
    public function it_lets_a_plain_member_manage_only_their_own_social_account(): void
    {
        $member = $this->createUser([], 'User', 'web');
        $own = SocialAccount::factory()->create(['user_id' => $member->id]);
        $colleague = SocialAccount::factory()->create(['user_id' => User::factory()->create(['organization_id' => $member->organization_id])->id]);

        foreach (['view', 'update', 'delete'] as $ability) {
            $this->assertTrue(Gate::forUser($member)->allows($ability, $own), $ability);
        }
        $this->assertFalse(Gate::forUser($member)->allows('update', $colleague));
        $this->assertFalse(Gate::forUser($member)->allows('delete', $colleague));
    }

    #[Test]
    public function it_denies_a_webhook_delivery_whose_webhook_is_missing(): void
    {
        $actor = $this->createUser([], 'Organization Owner', 'web');
        $delivery = new WebhookDelivery(['webhook_id' => null]);

        $this->assertFalse(Gate::forUser($actor)->allows('view', $delivery));
        $this->assertFalse(Gate::forUser($actor)->allows('update', $delivery));
    }

    public static function ssoConfigurationMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTTTTTTF',
            'Organization Admin' => 'TTFFFFFF',
            'Auditor' => 'TTFFFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:organizations.update' => ['update', true], 'no organization' => ['viewAny', false]]);
    }

    public static function ldapConfigurationMatrix(): array
    {
        return self::ssoConfigurationMatrix();
    }

    public static function ssoSessionMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFTTTTF',
            'Organization Admin' => 'TTFTTTTF',
            'Auditor' => 'TTFFFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:users.update' => ['delete', true], 'no organization' => ['viewAny', false]]);
    }

    public static function socialAccountMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFFTTTF',
            'Organization Admin' => 'TTFFTTTF',
            'User' => 'TTFFFFFF',
        ], ['custom:users.update' => ['delete', true], 'no organization' => ['viewAny', false]]);
    }

    public static function webhookMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTTTTTTF',
            'Organization Admin' => 'TTTTTTTF',
            'User' => 'FFFFFFFF',
        ], ['custom:webhooks.update' => ['update', true], 'custom:webhooks.delete' => ['delete', true], 'no organization' => ['viewAny', false]]);
    }

    public static function webhookDeliveryMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFTFFFF',
            'Organization Admin' => 'TTFTFFFF',
            'User' => 'FFFFFFFF',
        ], ['custom:webhooks.update' => ['update', true], 'no organization' => ['viewAny', false]]);
    }

    public static function webhookEventMatrix(): array
    {
        return self::matrix([
            'Organization Owner' => 'TTFFFFFF',
            'Organization Admin' => 'TTFFFFFF',
            'User' => 'TTFFFFFF',
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
