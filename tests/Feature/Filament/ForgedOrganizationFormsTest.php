<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\ApplicationGroupResource\Pages\CreateApplicationGroup;
use App\Filament\Resources\ApplicationResource\Pages\CreateApplication;
use App\Filament\Resources\CustomDomains\Pages\CreateCustomDomain;
use App\Filament\Resources\Invitations\Pages\CreateInvitation;
use App\Filament\Resources\LdapConfigurations\Pages\CreateLdapConfiguration;
use App\Filament\Resources\MigrationJobResource\Pages\ListMigrationJobs;
use App\Filament\Resources\OrganizationBrandingResource\Pages\CreateOrganizationBranding;
use App\Filament\Resources\PermissionResource\Pages\CreatePermission;
use App\Filament\Resources\SocialAccounts\Pages\CreateSocialAccount;
use App\Filament\Resources\SSOConfigurationResource\Pages\CreateSSOConfiguration;
use App\Filament\Resources\UserResource\Pages\EditUser;
use App\Filament\Resources\UserResource\RelationManagers\ApplicationsRelationManager;
use App\Filament\Resources\WebhookResource\Pages\CreateWebhook;
use App\Filament\Widgets\ApplicationAccessMatrix;
use App\Models\Application;
use App\Models\ApplicationGroup;
use App\Models\CustomDomain;
use App\Models\Invitation;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Models\User;
use App\Models\Webhook;
use App\Models\WebhookEvent;
use Illuminate\Support\Facades\Queue;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class ForgedOrganizationFormsTest extends IntegrationTestCase
{
    private User $owner;

    private Organization $otherOrganization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->owner = $this->createUser([], 'Organization Owner', 'web');
        $this->otherOrganization = Organization::factory()->create();
        $this->actingAs($this->owner);
    }

    #[Test]
    public function it_rejects_a_webhook_for_another_organization(): void
    {
        WebhookEvent::create(['name' => 'user.created', 'category' => 'user', 'description' => 'A user was created', 'is_active' => true, 'version' => '1.0']);

        Livewire::test(CreateWebhook::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm([
                'name' => 'Forged',
                'url' => 'https://example.com/hook',
                'events' => ['user.created'],
                'organization_id' => $this->otherOrganization->id,
            ])
            ->call('create');

        $this->assertDatabaseMissing('webhooks', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, Webhook::where('name', 'Forged')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_an_sso_configuration_for_an_application_of_another_organization(): void
    {
        $foreign = Application::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $own = Application::factory()->create(['organization_id' => $this->owner->organization_id]);

        Livewire::test(CreateSSOConfiguration::class)
            ->fillForm(['name' => 'Forged', 'provider' => 'oidc', 'application_id' => $foreign->id, 'callback_url' => 'https://example.com/cb', 'logout_url' => 'https://example.com/out'])
            ->call('create')
            ->assertHasFormErrors(['application_id']);

        $this->assertDatabaseMissing('sso_configurations', ['application_id' => $foreign->id]);

        Livewire::test(CreateSSOConfiguration::class)
            ->fillForm(['name' => 'Own', 'provider' => 'oidc', 'application_id' => $own->id, 'callback_url' => 'https://example.com/cb', 'logout_url' => 'https://example.com/out'])
            ->call('create')
            ->assertHasNoFormErrors(['application_id']);
    }

    #[Test]
    public function it_rejects_an_ldap_configuration_for_another_organization(): void
    {
        Livewire::test(CreateLdapConfiguration::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm([
                'organization_id' => $this->otherOrganization->id,
                'name' => 'Forged',
                'host' => 'ldap.example.com',
                'port' => 389,
                'base_dn' => 'dc=example,dc=com',
                'username' => 'cn=admin',
                'password' => 'secret',
                'user_attribute' => 'uid',
            ])
            ->call('create');

        $this->assertDatabaseMissing('ldap_configurations', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, LdapConfiguration::where('name', 'Forged')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_a_custom_domain_for_another_organization(): void
    {
        Livewire::test(CreateCustomDomain::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm([
                'organization_id' => $this->otherOrganization->id,
                'domain' => 'forged.example.com',
            ])
            ->call('create');

        $this->assertDatabaseMissing('custom_domains', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, CustomDomain::where('domain', 'forged.example.com')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_an_application_for_another_organization(): void
    {
        Livewire::test(CreateApplication::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm(['name' => 'Forged', 'redirect_uris' => ['https://example.com/cb'], 'organization_id' => $this->otherOrganization->id])
            ->call('create');

        $this->assertDatabaseMissing('applications', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, Application::where('name', 'Forged')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_an_application_group_for_another_organization(): void
    {
        $foreignParent = ApplicationGroup::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $foreignApplication = Application::factory()->create(['organization_id' => $this->otherOrganization->id]);

        Livewire::test(CreateApplicationGroup::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm(['name' => 'Forged', 'organization_id' => $this->otherOrganization->id, 'parent_id' => $foreignParent->id])
            ->call('create')
            ->assertHasFormErrors(['parent_id']);

        Livewire::test(CreateApplicationGroup::class)
            ->fillForm(['name' => 'Forged', 'applications' => [$foreignApplication->id]])
            ->call('create')
            ->assertHasFormErrors(['applications.0']);

        $this->assertDatabaseMissing('application_groups', ['name' => 'Forged']);

        Livewire::test(CreateApplicationGroup::class)
            ->fillForm(['name' => 'Own', 'organization_id' => $this->otherOrganization->id])
            ->call('create');

        $this->assertSame($this->owner->organization_id, ApplicationGroup::where('name', 'Own')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_organization_branding_for_another_organization(): void
    {
        Livewire::test(CreateOrganizationBranding::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm(['organization_id' => $this->otherOrganization->id, 'primary_color' => '#112233', 'secondary_color' => '#445566'])
            ->call('create');

        $this->assertDatabaseMissing('organization_branding', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, OrganizationBranding::where('primary_color', '#112233')->value('organization_id'));
    }

    #[Test]
    public function it_rejects_an_invitation_for_another_organization(): void
    {
        Livewire::test(CreateInvitation::class)
            ->assertFormFieldIsHidden('organization_id')
            ->fillForm([
                'organization_id' => $this->otherOrganization->id,
                'email' => 'forged@example.com',
                'role' => 'user',
            ])
            ->call('create');

        $this->assertDatabaseMissing('invitations', ['organization_id' => $this->otherOrganization->id]);
        $this->assertSame($this->owner->organization_id, Invitation::where('email', 'forged@example.com')->value('organization_id'));
    }

    #[Test]
    public function it_forbids_an_organization_owner_from_creating_a_social_account_for_a_foreign_user(): void
    {
        Livewire::test(CreateSocialAccount::class)->assertForbidden();
    }

    #[Test]
    public function it_rejects_a_migration_for_another_organization(): void
    {
        Queue::fake();

        Livewire::test(ListMigrationJobs::class)
            ->callAction('new_migration', [
                'source' => 'auth0',
                'organization_id' => $this->otherOrganization->id,
                'tenant_domain' => 'tenant.auth0.com',
                'api_token' => 'token',
            ]);

        $this->assertDatabaseMissing('migration_jobs', ['organization_id' => $this->otherOrganization->id]);
        $this->assertDatabaseHas('migration_jobs', ['organization_id' => $this->owner->organization_id]);
    }

    #[Test]
    public function it_rejects_attaching_an_application_of_another_organization_to_a_user(): void
    {
        $foreignApplication = Application::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $target = User::factory()->create(['organization_id' => $this->owner->organization_id]);

        Livewire::test(ApplicationsRelationManager::class, ['ownerRecord' => $target, 'pageClass' => EditUser::class])
            ->callTableAction('attach', data: ['recordId' => $foreignApplication->id])
            ->assertHasTableActionErrors(['recordId']);

        $this->assertDatabaseMissing('user_applications', ['application_id' => $foreignApplication->id]);
    }

    #[Test]
    public function it_ignores_access_matrix_grants_for_a_user_of_another_organization(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->owner->organization_id]);
        $foreignUser = User::factory()->create(['organization_id' => $this->otherOrganization->id]);

        Livewire::test(ApplicationAccessMatrix::class)->call('grantAccess', $foreignUser->id, $application->id);

        $this->assertDatabaseMissing('user_applications', ['user_id' => $foreignUser->id]);
    }

    #[Test]
    public function it_revokes_a_foreign_users_access_to_an_application_of_the_callers_organization(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->owner->organization_id]);
        $foreignUser = User::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $foreignUser->applications()->attach($application->id);

        Livewire::test(ApplicationAccessMatrix::class)->call('revokeAccess', $foreignUser->id, $application->id);

        $this->assertDatabaseMissing('user_applications', ['user_id' => $foreignUser->id, 'application_id' => $application->id]);
    }

    #[Test]
    public function it_grants_and_revokes_access_for_a_user_of_the_callers_organization(): void
    {
        $application = Application::factory()->create(['organization_id' => $this->owner->organization_id]);
        $member = User::factory()->create(['organization_id' => $this->owner->organization_id]);

        $matrix = Livewire::test(ApplicationAccessMatrix::class)->call('grantAccess', $member->id, $application->id);
        $this->assertDatabaseHas('user_applications', ['user_id' => $member->id, 'application_id' => $application->id]);

        $matrix->call('revokeAccess', $member->id, $application->id);
        $this->assertDatabaseMissing('user_applications', ['user_id' => $member->id, 'application_id' => $application->id]);
    }

    #[Test]
    public function it_ignores_access_matrix_revokes_for_an_application_of_another_organization(): void
    {
        $foreignApplication = Application::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $foreignUser = User::factory()->create(['organization_id' => $this->otherOrganization->id]);
        $foreignUser->applications()->attach($foreignApplication->id);

        Livewire::test(ApplicationAccessMatrix::class)->call('revokeAccess', $foreignUser->id, $foreignApplication->id);

        $this->assertDatabaseHas('user_applications', ['user_id' => $foreignUser->id, 'application_id' => $foreignApplication->id]);
    }

    #[Test]
    public function it_rejects_permission_names_equal_to_a_policy_ability(): void
    {
        $this->actingAs($this->createSuperAdmin());

        Livewire::test(CreatePermission::class)
            ->fillForm(['name' => 'update', 'guard_name' => 'web'])
            ->call('create')
            ->assertHasFormErrors(['name']);

        $this->assertDatabaseMissing('permissions', ['name' => 'update']);
    }
}
