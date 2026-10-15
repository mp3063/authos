<?php

namespace Tests\Integration\Security;

use App\Filament\Resources\OrganizationResource\Pages\ListOrganizations;
use App\Imports\UsersImport;
use App\Models\Organization;
use App\Models\Role;
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
}
