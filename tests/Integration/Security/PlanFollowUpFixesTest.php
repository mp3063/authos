<?php

namespace Tests\Integration\Security;

use App\Filament\Resources\OrganizationResource\Pages\ListOrganizations;
use App\Imports\UsersImport;
use App\Models\Organization;
use App\Models\Role;
use App\Models\SSOSession;
use App\Models\User;
use App\Notifications\PasswordResetNotification;
use App\Services\Auth0\DTOs\Auth0OrganizationDTO;
use App\Services\Auth0\Migration\Importers\OrganizationImporter;
use App\Services\InvitationService;
use App\Services\UserRoleService;
use Filament\Auth\Pages\PasswordReset\ResetPassword;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class PlanFollowUpFixesTest extends IntegrationTestCase
{
    #[Test]
    public function it_gives_imported_auth0_organizations_a_unique_slug(): void
    {
        $dto = fn (string $id, string $name) => new Auth0OrganizationDTO($id, $name, 'Acme Corp', [], []);

        $result = (new OrganizationImporter)->import([
            $dto('org_1', 'Acme Corp'),
            $dto('org_2', 'acme-corp'),
        ]);

        $this->assertSame(2, $result->getSuccessCount());
        $this->assertSame(
            ['acme-corp', 'acme-corp-2'],
            Organization::orderBy('id')->pluck('slug')->all()
        );
    }

    #[Test]
    public function it_resolves_user_import_roles_on_the_api_guard_only(): void
    {
        $organization = $this->createOrganization();
        $admin = $this->createSuperAdmin();
        Role::create(['name' => 'Reviewer', 'guard_name' => 'web', 'organization_id' => $organization->id]);
        $apiRole = Role::create(['name' => 'Reviewer', 'guard_name' => 'api', 'organization_id' => $organization->id]);

        $import = new UsersImport(
            $organization,
            $admin,
            false,
            'Reviewer',
            false,
            app(InvitationService::class),
            app(UserRoleService::class)
        );
        $import->collection(new Collection([collect(['email' => 'new@example.com', 'name' => 'New User', 'role' => 'Reviewer', 'password' => 'Str0ng-Passw0rd!'])]));

        $user = User::where('email', 'new@example.com')->firstOrFail();
        $this->assertSame([$apiRole->id], $user->roles()->pluck('roles.id')->all());
    }

    #[Test]
    public function it_filters_organizations_by_every_representation_that_requires_mfa(): void
    {
        $required = collect([true, 1, '1', 'true', 'on', 'yes'])
            ->map(fn ($value) => $this->createOrganization(['settings' => ['require_mfa' => $value]]));
        $notRequired = collect([false, 0, '0', 'false', 'off', 'no'])
            ->map(fn ($value) => $this->createOrganization(['settings' => ['require_mfa' => $value]]))
            ->push($this->createOrganization(['settings' => []]));
        $this->actingAs($this->createSuperAdmin());

        Livewire::test(ListOrganizations::class)
            ->filterTable('requires_mfa', true)
            ->assertCanSeeTableRecords($required)
            ->assertCanNotSeeTableRecords($notRequired);
    }

    #[Test]
    public function it_emails_a_reset_link_that_completes_the_reset_in_the_panel(): void
    {
        Notification::fake();
        $user = $this->createUser(['email' => 'reset-me@example.com', 'organization_id' => $this->createOrganization()->id], 'Organization Owner');

        $this->postJson('/api/v1/auth/password/email', ['email' => $user->email])->assertOk();

        $url = '';
        Notification::assertSentTo($user, PasswordResetNotification::class, function ($notification) use ($user, &$url) {
            $url = $notification->toMail($user)->actionUrl;

            return true;
        });
        $this->assertStringContainsString('/admin/password-reset/reset', $url);
        $this->get($url)->assertOk();

        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        Livewire::withQueryParams($query)
            ->test(ResetPassword::class)
            ->fillForm(['password' => 'Brand-New-Passw0rd!', 'passwordConfirmation' => 'Brand-New-Passw0rd!'])
            ->call('resetPassword')
            ->assertHasNoErrors();

        $this->assertTrue(Hash::check('Brand-New-Passw0rd!', $user->fresh()->password));
    }

    #[Test]
    public function it_does_not_reuse_the_slug_of_a_soft_deleted_organization(): void
    {
        $this->createOrganization(['name' => 'Acme Corp', 'slug' => 'acme-corp'])->delete();

        (new OrganizationImporter)->import([new Auth0OrganizationDTO('org_1', 'Acme Corp', 'Acme Corp', [], [])]);

        $this->assertSame('acme-corp-2', Organization::sole()->slug);
    }

    #[Test]
    public function it_completes_an_api_reset_with_the_emailed_token(): void
    {
        Notification::fake();
        $user = $this->createUser(['email' => 'api-reset@example.com']);
        $this->postJson('/api/v1/auth/password/email', ['email' => $user->email])->assertOk();

        $token = '';
        Notification::assertSentTo($user, PasswordResetNotification::class, function ($notification) use (&$token) {
            $token = $notification->token;

            return true;
        });

        $this->postJson('/api/v1/auth/password/reset', [
            'email' => $user->email,
            'token' => $token,
            'password' => 'Brand-New-Passw0rd!',
            'password_confirmation' => 'Brand-New-Passw0rd!',
        ])->assertOk();

        $this->assertTrue(Hash::check('Brand-New-Passw0rd!', $user->fresh()->password));
        $this->assertNotNull($user->fresh()->password_changed_at);
    }

    #[Test]
    public function it_links_a_user_without_panel_access_to_the_configured_reset_url(): void
    {
        config(['auth.password_reset_url' => 'https://app.example.com/reset-password']);
        $user = $this->createUser(['email' => 'plain@example.com', 'organization_id' => $this->createOrganization()->id], 'Organization Member');

        $url = (new PasswordResetNotification('tok123'))->toMail($user)->actionUrl;

        $this->assertSame('https://app.example.com/reset-password?token=tok123&email=plain%40example.com', $url);
    }

    #[Test]
    public function it_ends_sessions_and_enforces_the_api_password_rules_on_a_panel_reset(): void
    {
        $user = $this->createUser(['organization_id' => $this->createOrganization()->id], 'Organization Owner');
        $accessToken = $user->createToken('t')->token;
        $session = SSOSession::factory()->create(['user_id' => $user->id]);
        $token = Password::broker()->createToken($user);
        $component = fn () => Livewire::withQueryParams(['token' => $token, 'email' => $user->email])->test(ResetPassword::class);

        $component()
            ->fillForm(['password' => 'weakpass', 'passwordConfirmation' => 'weakpass'])
            ->call('resetPassword')
            ->assertHasErrors();
        $this->assertFalse($accessToken->fresh()->revoked);

        $component()
            ->fillForm(['password' => 'Brand-New-Passw0rd!', 'passwordConfirmation' => 'Brand-New-Passw0rd!'])
            ->call('resetPassword')
            ->assertHasNoErrors();

        $this->assertTrue($accessToken->fresh()->revoked);
        $this->assertNotNull($session->fresh()->logged_out_at);
        $this->assertNotNull($user->fresh()->password_changed_at);
    }
}
