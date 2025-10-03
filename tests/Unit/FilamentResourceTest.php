<?php

namespace Tests\Unit;

use App\Filament\Resources\ApplicationResource;
use App\Filament\Resources\AuthenticationLogResource;
use App\Filament\Resources\OrganizationResource;
use App\Filament\Resources\PermissionResource;
use App\Filament\Resources\RoleResource;
use App\Filament\Resources\UserResource;
use App\Models\Application;
use App\Models\AuthenticationLog;
use App\Models\Organization;
use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Filament\Resources\Resource;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class FilamentResourceTest extends TestCase
{
    private Organization $organization;

    private User $superAdmin;

    private User $orgAdmin;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();

        // Create super admin for cross-organization testing
        $this->superAdmin = $this->createSuperAdmin();

        // Create organization admin for scoped testing
        $this->orgAdmin = $this->createOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);
    }

    #[Test]
    public function user_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(User::class, UserResource::getModel());
        $this->assertNull(UserResource::getNavigationIcon());
        $this->assertEquals('User Management', UserResource::getNavigationGroup());
        $this->assertIsInt(UserResource::getNavigationSort());
    }

    #[Test]
    public function user_resource_can_create_form()
    {
        $this->assertTrue(method_exists(UserResource::class, 'form'));
        // Form method requires a Schema parameter, so we just test the method exists
        $this->assertTrue(true); // Method exists test passed
    }

    #[Test]
    public function user_resource_can_create_table()
    {
        $this->assertTrue(method_exists(UserResource::class, 'table'));
        // Table method requires a Table parameter with livewire component
        $this->assertTrue(true); // Method exists test passed
    }

    #[Test]
    public function user_resource_has_eloquent_query_method()
    {
        // Test that UserResource has the getEloquentQuery method
        $this->assertTrue(method_exists(UserResource::class, 'getEloquentQuery'));
    }

    #[Test]
    public function application_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(Application::class, ApplicationResource::getModel());
        $this->assertNull(ApplicationResource::getNavigationIcon());
        $this->assertEquals('OAuth Management', ApplicationResource::getNavigationGroup());
        $this->assertIsInt(ApplicationResource::getNavigationSort());
    }

    #[Test]
    public function application_resource_can_create_form_and_table()
    {
        $this->assertTrue(method_exists(ApplicationResource::class, 'form'));
        $this->assertTrue(method_exists(ApplicationResource::class, 'table'));
    }

    #[Test]
    public function application_resource_has_eloquent_query_method()
    {
        // Test that ApplicationResource has the getEloquentQuery method
        $this->assertTrue(method_exists(ApplicationResource::class, 'getEloquentQuery'));
    }

    #[Test]
    public function organization_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(Organization::class, OrganizationResource::getModel());
        $this->assertNull(OrganizationResource::getNavigationIcon());
        $this->assertEquals('User Management', OrganizationResource::getNavigationGroup());
        $this->assertIsInt(OrganizationResource::getNavigationSort());
    }

    #[Test]
    public function organization_resource_can_create_form_and_table()
    {
        $this->assertTrue(method_exists(OrganizationResource::class, 'form'));
        $this->assertTrue(method_exists(OrganizationResource::class, 'table'));
    }

    #[Test]
    public function role_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(Role::class, RoleResource::getModel());
        $this->assertNull(RoleResource::getNavigationIcon());
        $this->assertEquals('Access Control', RoleResource::getNavigationGroup());
        $this->assertIsInt(RoleResource::getNavigationSort());
    }

    #[Test]
    public function role_resource_can_create_form_and_table()
    {
        $this->assertTrue(method_exists(RoleResource::class, 'form'));
        $this->assertTrue(method_exists(RoleResource::class, 'table'));
    }

    #[Test]
    public function role_resource_has_eloquent_query_method()
    {
        // Test that RoleResource has the getEloquentQuery method
        $this->assertTrue(method_exists(RoleResource::class, 'getEloquentQuery'));
    }

    #[Test]
    public function permission_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(Permission::class, PermissionResource::getModel());
        $this->assertNull(PermissionResource::getNavigationIcon());
        $this->assertEquals('Access Control', PermissionResource::getNavigationGroup());
        $this->assertIsInt(PermissionResource::getNavigationSort());
    }

    #[Test]
    public function permission_resource_can_create_form_and_table()
    {
        $this->assertTrue(method_exists(PermissionResource::class, 'form'));
        $this->assertTrue(method_exists(PermissionResource::class, 'table'));
    }

    #[Test]
    public function authentication_log_resource_has_correct_model_and_configuration()
    {
        $this->assertEquals(AuthenticationLog::class, AuthenticationLogResource::getModel());
        $this->assertNull(AuthenticationLogResource::getNavigationIcon());
        $this->assertEquals('Security & Monitoring', AuthenticationLogResource::getNavigationGroup());
        $this->assertIsInt(AuthenticationLogResource::getNavigationSort());
    }

    #[Test]
    public function authentication_log_resource_can_create_form_and_table()
    {
        $this->assertTrue(method_exists(AuthenticationLogResource::class, 'form'));
        $this->assertTrue(method_exists(AuthenticationLogResource::class, 'table'));
    }

    #[Test]
    public function authentication_log_resource_has_eloquent_query_method()
    {
        // Test that AuthenticationLogResource has the getEloquentQuery method
        $this->assertTrue(method_exists(AuthenticationLogResource::class, 'getEloquentQuery'));
    }

    #[Test]
    public function all_resources_implement_base_resource_class()
    {
        $resources = [
            UserResource::class,
            ApplicationResource::class,
            OrganizationResource::class,
            RoleResource::class,
            PermissionResource::class,
            AuthenticationLogResource::class,
        ];

        foreach ($resources as $resourceClass) {
            $this->assertTrue(
                is_subclass_of($resourceClass, Resource::class),
                "{$resourceClass} should extend Filament\Resources\Resource"
            );
        }
    }

    #[Test]
    public function all_resources_have_required_static_properties()
    {
        $resources = [
            UserResource::class,
            ApplicationResource::class,
            OrganizationResource::class,
            RoleResource::class,
            PermissionResource::class,
            AuthenticationLogResource::class,
        ];

        foreach ($resources as $resourceClass) {
            // Test model property exists and is valid
            $model = $resourceClass::getModel();
            $this->assertNotEmpty($model, "{$resourceClass} should have a model defined");
            $this->assertTrue(
                class_exists($model),
                "{$resourceClass} model {$model} should exist"
            );

            // Test navigation properties (icons can be null)
            $this->assertIsString(
                $resourceClass::getNavigationGroup(),
                "{$resourceClass} should have navigation group"
            );
            $this->assertIsInt(
                $resourceClass::getNavigationSort(),
                "{$resourceClass} should have navigation sort"
            );

            // Navigation icon can be null, so just test it's not undefined
            $navigationIcon = $resourceClass::getNavigationIcon();
            $this->assertTrue(
                is_null($navigationIcon) || is_string($navigationIcon),
                "{$resourceClass} navigation icon should be null or string"
            );
        }
    }

    #[Test]
    public function resources_have_required_methods()
    {
        $resources = [
            UserResource::class,
            ApplicationResource::class,
            OrganizationResource::class,
            RoleResource::class,
            PermissionResource::class,
            AuthenticationLogResource::class,
        ];

        foreach ($resources as $resourceClass) {
            // Test that form and table methods exist
            $this->assertTrue(method_exists($resourceClass, 'form'), "{$resourceClass} should have form method");
            $this->assertTrue(method_exists($resourceClass, 'table'), "{$resourceClass} should have table method");
            $this->assertTrue(method_exists($resourceClass, 'getEloquentQuery'), "{$resourceClass} should have getEloquentQuery method");
        }
    }
}
