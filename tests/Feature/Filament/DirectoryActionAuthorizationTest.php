<?php

namespace Tests\Feature\Filament;

use App\Filament\Resources\CustomDomains\Pages\ListCustomDomains;
use App\Filament\Resources\LdapConfigurations\Pages\ListLdapConfigurations;
use App\Filament\Resources\LdapConfigurations\Pages\ViewLdapConfiguration;
use App\Jobs\SyncLdapUsersJob;
use App\Models\CustomDomain;
use App\Models\LdapConfiguration;
use App\Models\Organization;
use App\Services\LdapAuthService;
use Illuminate\Support\Facades\Queue;
use Livewire\Livewire;
use PHPUnit\Framework\Attributes\Test;
use Tests\Feature\Filament\Concerns\CallsHiddenActions;
use Tests\Integration\IntegrationTestCase;

class DirectoryActionAuthorizationTest extends IntegrationTestCase
{
    use CallsHiddenActions;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
    }

    private function actingAsRole(string $role): void
    {
        $this->actingAs($this->createUser(['organization_id' => $this->organization->id], $role));
    }

    private function ldap(): LdapConfiguration
    {
        return LdapConfiguration::factory()->create(['organization_id' => $this->organization->id, 'is_active' => true, 'sync_status' => null]);
    }

    #[Test]
    public function it_hides_and_forbids_ldap_actions_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Admin');
        Queue::fake();
        $this->mock(LdapAuthService::class)->shouldNotReceive('testConnection');
        $ldap = $this->ldap();

        $list = Livewire::test(ListLdapConfigurations::class)
            ->assertTableActionHidden('test_connection', $ldap)
            ->assertTableActionHidden('sync_users', $ldap)
            ->assertTableBulkActionHidden('delete');
        $this->forceTableAction($list, 'test_connection', $ldap);
        $this->forceTableAction($list, 'sync_users', $ldap);
        $this->forceTableBulkAction($list, 'delete', [$ldap]);

        $view = Livewire::test(ViewLdapConfiguration::class, ['record' => $ldap->getRouteKey()])
            ->assertActionHidden('test_connection')
            ->assertActionHidden('sync_now');
        $this->forcePageAction($view, 'test_connection');
        $this->forcePageAction($view, 'sync_now');

        Queue::assertNothingPushed();
        $this->assertNull($ldap->fresh()->sync_status);
        $this->assertNotNull(LdapConfiguration::find($ldap->id));
    }

    #[Test]
    public function an_owner_can_test_and_sync_an_ldap_configuration(): void
    {
        $this->actingAsRole('Organization Owner');
        Queue::fake();
        $this->mock(LdapAuthService::class)->shouldReceive('testConnection')->once()->andReturn(['user_count' => 3]);
        $ldap = $this->ldap();

        Livewire::test(ListLdapConfigurations::class)
            ->assertTableActionVisible('test_connection', $ldap)
            ->callTableAction('test_connection', $ldap)
            ->callTableAction('sync_users', $ldap);

        Queue::assertPushed(SyncLdapUsersJob::class);
        $this->assertSame('pending', $ldap->fresh()->sync_status);
    }

    #[Test]
    public function it_hides_and_forbids_verify_domain_for_a_role_without_the_permission(): void
    {
        $this->actingAsRole('Organization Admin');
        $domain = CustomDomain::factory()->create(['organization_id' => $this->organization->id]);

        $list = Livewire::test(ListCustomDomains::class)
            ->assertTableActionHidden('verify_domain', $domain)
            ->assertTableBulkActionHidden('delete');
        $this->forceTableAction($list, 'verify_domain', $domain);
        $this->forceTableBulkAction($list, 'delete', [$domain]);

        $this->assertNull($domain->fresh()->verified_at);
        $this->assertNotNull(CustomDomain::find($domain->id));
    }

    #[Test]
    public function an_owner_can_verify_a_domain(): void
    {
        $this->actingAsRole('Organization Owner');
        $domain = CustomDomain::factory()->create(['organization_id' => $this->organization->id]);

        Livewire::test(ListCustomDomains::class)
            ->assertTableActionVisible('verify_domain', $domain)
            ->callTableAction('verify_domain', $domain);

        $this->assertNotNull($domain->fresh()->verified_at);
    }
}
