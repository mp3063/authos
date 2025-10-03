<?php

namespace Tests\Unit\Services;

use App\Models\Organization;
use App\Models\OrganizationBranding;
use App\Services\BrandingService;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use Tests\TestCase;

class BrandingServiceTest extends TestCase
{
    private BrandingService $service;

    private Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('public');

        $this->service = new BrandingService;
        $this->organization = Organization::factory()->create();
    }

    public function test_get_branding_returns_null_when_not_exists(): void
    {
        $branding = $this->service->getBranding($this->organization);

        $this->assertNull($branding);
    }

    public function test_get_branding_returns_existing_branding(): void
    {
        $existing = OrganizationBranding::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $branding = $this->service->getBranding($this->organization);

        $this->assertNotNull($branding);
        $this->assertEquals($existing->id, $branding->id);
    }

    public function test_get_or_create_branding_creates_default_branding(): void
    {
        $branding = $this->service->getOrCreateBranding($this->organization);

        $this->assertInstanceOf(OrganizationBranding::class, $branding);
        $this->assertEquals($this->organization->id, $branding->organization_id);
        $this->assertEquals('#3B82F6', $branding->primary_color);
        $this->assertEquals('#10B981', $branding->secondary_color);
        $this->assertIsArray($branding->settings);
    }

    public function test_get_or_create_branding_returns_existing_branding(): void
    {
        $existing = OrganizationBranding::factory()->create([
            'organization_id' => $this->organization->id,
            'primary_color' => '#FF0000',
        ]);

        $branding = $this->service->getOrCreateBranding($this->organization);

        $this->assertEquals($existing->id, $branding->id);
        $this->assertEquals('#FF0000', $branding->primary_color);
    }

    public function test_update_branding_updates_primary_color(): void
    {
        $branding = OrganizationBranding::factory()->create([
            'organization_id' => $this->organization->id,
        ]);

        $updated = $this->service->updateBranding($this->organization, [
            'primary_color' => '#1a73e8',
        ]);

        $this->assertEquals('#1a73e8', $updated->primary_color);
    }

    public function test_update_branding_updates_secondary_color(): void
    {
        $updated = $this->service->updateBranding($this->organization, [
            'secondary_color' => '#34a853',
        ]);

        $this->assertEquals('#34a853', $updated->secondary_color);
    }

    public function test_update_branding_sanitizes_custom_css(): void
    {
        $maliciousCSS = '.btn { color: red; } <script>alert("xss")</script>';

        $updated = $this->service->updateBranding($this->organization, [
            'custom_css' => $maliciousCSS,
        ]);

        $this->assertStringNotContainsString('<script>', $updated->custom_css);
        $this->assertStringNotContainsString('alert', $updated->custom_css);
    }

    public function test_update_branding_merges_settings(): void
    {
        $branding = OrganizationBranding::factory()->create([
            'organization_id' => $this->organization->id,
            'settings' => ['existing' => 'value'],
        ]);

        $updated = $this->service->updateBranding($this->organization, [
            'settings' => ['new' => 'data'],
        ]);

        $this->assertArrayHasKey('existing', $updated->settings);
        $this->assertArrayHasKey('new', $updated->settings);
        $this->assertEquals('value', $updated->settings['existing']);
        $this->assertEquals('data', $updated->settings['new']);
    }

    public function test_upload_logo_stores_file(): void
    {
        $file = UploadedFile::fake()->image('logo.png', 500, 500);

        $url = $this->service->uploadLogo($this->organization, $file);

        $this->assertNotNull($url);

        $branding = $this->organization->branding()->first();
        $this->assertNotNull($branding->logo_path);
        Storage::disk('public')->assertExists($branding->logo_path);
    }

    public function test_upload_logo_deletes_old_logo(): void
    {
        $oldFile = UploadedFile::fake()->image('old.png', 500, 500);
        $oldUrl = $this->service->uploadLogo($this->organization, $oldFile);

        $branding = $this->organization->branding()->first();
        $oldPath = $branding->logo_path;

        $newFile = UploadedFile::fake()->image('new.png', 500, 500);
        $newUrl = $this->service->uploadLogo($this->organization, $newFile);

        Storage::disk('public')->assertMissing($oldPath);
        Storage::disk('public')->assertExists($branding->fresh()->logo_path);
    }

    public function test_upload_logo_validates_file_extension(): void
    {
        $file = UploadedFile::fake()->create('document.pdf', 1000);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid file extension');

        $this->service->uploadLogo($this->organization, $file);
    }

    public function test_upload_background_stores_file(): void
    {
        $file = UploadedFile::fake()->image('background.jpg', 1920, 1080);

        $url = $this->service->uploadBackground($this->organization, $file);

        $this->assertNotNull($url);

        $branding = $this->organization->branding()->first();
        $this->assertNotNull($branding->login_background_path);
        Storage::disk('public')->assertExists($branding->login_background_path);
    }

    public function test_upload_background_deletes_old_background(): void
    {
        $oldFile = UploadedFile::fake()->image('old-bg.jpg', 1920, 1080);
        $this->service->uploadBackground($this->organization, $oldFile);

        $branding = $this->organization->branding()->first();
        $oldPath = $branding->login_background_path;

        $newFile = UploadedFile::fake()->image('new-bg.jpg', 1920, 1080);
        $this->service->uploadBackground($this->organization, $newFile);

        Storage::disk('public')->assertMissing($oldPath);
        Storage::disk('public')->assertExists($branding->fresh()->login_background_path);
    }

    public function test_delete_logo_removes_file_and_path(): void
    {
        $file = UploadedFile::fake()->image('logo.png', 500, 500);
        $this->service->uploadLogo($this->organization, $file);

        $branding = $this->organization->branding()->first();
        $path = $branding->logo_path;

        $this->service->deleteLogo($this->organization);

        Storage::disk('public')->assertMissing($path);
        $this->assertNull($branding->fresh()->logo_path);
    }

    public function test_delete_background_removes_file_and_path(): void
    {
        $file = UploadedFile::fake()->image('background.jpg', 1920, 1080);
        $this->service->uploadBackground($this->organization, $file);

        $branding = $this->organization->branding()->first();
        $path = $branding->login_background_path;

        $this->service->deleteBackground($this->organization);

        Storage::disk('public')->assertMissing($path);
        $this->assertNull($branding->fresh()->login_background_path);
    }

    public function test_sanitize_css_removes_script_tags(): void
    {
        $maliciousCSS = '.btn { color: red; } <script>alert("xss")</script>';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('<script>', $sanitized);
        $this->assertStringNotContainsString('alert', $sanitized);
    }

    public function test_sanitize_css_removes_javascript_protocol(): void
    {
        $maliciousCSS = 'background: url(javascript:alert("xss"))';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('javascript:', $sanitized);
    }

    public function test_sanitize_css_removes_event_handlers(): void
    {
        $maliciousCSS = 'div { onclick: alert("xss"); onerror: alert("xss"); }';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('onclick', $sanitized);
        $this->assertStringNotContainsString('onerror', $sanitized);
    }

    public function test_sanitize_css_removes_expression(): void
    {
        $maliciousCSS = 'width: expression(alert("xss"))';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('expression', $sanitized);
    }

    public function test_sanitize_css_removes_behavior(): void
    {
        $maliciousCSS = 'behavior: url(xss.htc)';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('behavior:', $sanitized);
    }

    public function test_sanitize_css_removes_import(): void
    {
        $maliciousCSS = '@import url("evil.css");';

        $sanitized = $this->service->sanitizeCSS($maliciousCSS);

        $this->assertStringNotContainsString('@import', $sanitized);
    }

    public function test_sanitize_css_preserves_safe_styles(): void
    {
        $safeCSS = '.btn { color: #3B82F6; border-radius: 4px; padding: 8px 16px; }';

        $sanitized = $this->service->sanitizeCSS($safeCSS);

        $this->assertStringContainsString('color', $sanitized);
        $this->assertStringContainsString('border-radius', $sanitized);
        $this->assertStringContainsString('padding', $sanitized);
    }
}
