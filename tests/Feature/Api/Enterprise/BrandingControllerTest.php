<?php

namespace Tests\Feature\Api\Enterprise;

use App\Models\Organization;
use App\Models\User;
use App\Services\BrandingService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Laravel\Passport\Passport;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class BrandingControllerTest extends TestCase
{
    private Organization $organization;

    private User $adminUser;

    private User $regularUser;

    private BrandingService $brandingService;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');

        $this->organization = Organization::factory()->create([
            'settings' => [
                'enterprise_features' => [
                    'custom_branding_enabled' => true,
                ],
            ],
        ]);

        Role::firstOrCreate(['name' => 'User', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'api']);
        Role::firstOrCreate(['name' => 'Super Admin', 'guard_name' => 'api']);

        $this->adminUser = $this->createApiOrganizationAdmin([
            'organization_id' => $this->organization->id,
        ]);

        $this->regularUser = $this->createApiUser([
            'organization_id' => $this->organization->id,
        ]);
    }

    public function test_can_get_organization_branding(): void
    {
        Passport::actingAs($this->adminUser, ['organizations.read']);

        $response = $this->getJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding");

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'logo_url',
                    'background_url',
                    'primary_color',
                    'secondary_color',
                    'accent_color',
                    'custom_css',
                    'custom_html',
                ],
                'message',
            ]);
    }

    public function test_can_update_branding_settings(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'primary_color' => '#1a73e8',
            'secondary_color' => '#34a853',
            'accent_color' => '#fbbc04',
            'custom_css' => '.btn { border-radius: 4px; }',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'branding',
                ],
                'message',
            ])
            ->assertJson([
                'success' => true,
                'data' => [
                    'branding' => [
                        'primary_color' => '#1a73e8',
                        'secondary_color' => '#34a853',
                        'accent_color' => '#fbbc04',
                    ],
                ],
            ]);

        $this->assertDatabaseHas('organization_branding', [
            'organization_id' => $this->organization->id,
            'primary_color' => '#1a73e8',
        ]);
    }

    public function test_can_upload_logo(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $file = UploadedFile::fake()->image('logo.png', 500, 500);

        $response = $this->postJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding/logo", [
            'logo' => $file,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'logo_url',
                ],
                'message',
            ]);

        Storage::disk('public')->assertExists("branding/logos/{$this->organization->id}/".$file->hashName());
    }

    public function test_can_upload_background(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $file = UploadedFile::fake()->image('background.jpg', 1920, 1080);

        $response = $this->postJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding/background", [
            'background' => $file,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'background_url',
                ],
                'message',
            ]);

        Storage::disk('public')->assertExists("branding/backgrounds/{$this->organization->id}/".$file->hashName());
    }

    public function test_validates_image_uploads(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $file = UploadedFile::fake()->create('document.pdf', 1000);

        $response = $this->postJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding/logo", [
            'logo' => $file,
        ]);

        $response->assertStatus(422)
            ->assertJsonStructure([
                'success',
                'error',
                'error_description',
                'errors' => [
                    'logo',
                ],
            ]);
    }

    public function test_validates_logo_dimensions(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $file = UploadedFile::fake()->image('logo.png', 100, 100);

        $response = $this->postJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding/logo", [
            'logo' => $file,
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['logo']);
    }

    public function test_validates_color_formats(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'primary_color' => 'invalid-color',
            'secondary_color' => '#12345',
            'accent_color' => 'rgb(255, 0, 0)',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['primary_color', 'secondary_color']);
    }

    public function test_sanitizes_custom_css(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $maliciousCSS = '.btn { color: red; } <script>alert("xss")</script>';

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'custom_css' => $maliciousCSS,
        ]);

        $response->assertStatus(200);

        $branding = $this->organization->fresh()->branding;
        $this->assertStringNotContainsString('<script>', $branding->custom_css);
        $this->assertStringNotContainsString('alert', $branding->custom_css);
    }

    public function test_sanitizes_custom_html(): void
    {
        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $maliciousHTML = '<div>Safe content</div><script>alert("xss")</script>';

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'custom_html' => $maliciousHTML,
        ]);

        $response->assertStatus(200);

        $branding = $this->organization->fresh()->branding;
        $this->assertStringNotContainsString('<script>', $branding->custom_html);
        $this->assertStringContainsString('<div>Safe content</div>', $branding->custom_html);
    }

    public function test_cannot_update_another_organizations_branding(): void
    {
        $otherOrganization = Organization::factory()->create();

        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $response = $this->putJson("/api/v1/enterprise/organizations/{$otherOrganization->id}/branding", [
            'primary_color' => '#000000',
        ]);

        $response->assertStatus(403);
    }

    public function test_deletes_old_logo_when_uploading_new(): void
    {
        $oldFile = UploadedFile::fake()->image('old-logo.png', 500, 500);
        $oldPath = $oldFile->storeAs("branding/logos/{$this->organization->id}", 'old-logo.png', 'public');

        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $newFile = UploadedFile::fake()->image('new-logo.png', 500, 500);

        $response = $this->postJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding/logo", [
            'logo' => $newFile,
        ]);

        $response->assertStatus(200);

        Storage::disk('public')->assertMissing($oldPath);
        Storage::disk('public')->assertExists("branding/logos/{$this->organization->id}/".$newFile->hashName());
    }

    public function test_requires_branding_permission(): void
    {
        Passport::actingAs($this->regularUser, ['applications.read']);

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'primary_color' => '#000000',
        ]);

        $response->assertStatus(403);
    }

    public function test_branding_disabled_for_organization_returns_error(): void
    {
        $this->organization->update([
            'settings' => [
                'enterprise_features' => [
                    'custom_branding_enabled' => false,
                ],
            ],
        ]);

        Passport::actingAs($this->adminUser, ['enterprise.branding.manage']);

        $response = $this->putJson("/api/v1/enterprise/organizations/{$this->organization->id}/branding", [
            'primary_color' => '#000000',
        ]);

        $response->assertStatus(403)
            ->assertJson([
                'success' => false,
                'error' => 'feature_disabled',
            ]);
    }
}
