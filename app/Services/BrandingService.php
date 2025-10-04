<?php

namespace App\Services;

use App\Models\Organization;
use App\Models\OrganizationBranding;
use Exception;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;

class BrandingService
{
    /**
     * Get organization branding
     */
    public function getBranding(Organization $organization): ?OrganizationBranding
    {
        return $organization->branding()->first();
    }

    /**
     * Get or create organization branding
     */
    public function getOrCreateBranding(Organization $organization): OrganizationBranding
    {
        return $organization->branding()->firstOrCreate(
            ['organization_id' => $organization->id],
            [
                'primary_color' => '#3B82F6',
                'secondary_color' => '#10B981',
                'settings' => [],
            ]
        );
    }

    /**
     * Update branding settings
     */
    public function updateBranding(Organization $organization, array $data): OrganizationBranding
    {
        $branding = $this->getOrCreateBranding($organization);

        $updateData = [];

        if (isset($data['primary_color'])) {
            $updateData['primary_color'] = $data['primary_color'];
        }

        if (isset($data['secondary_color'])) {
            $updateData['secondary_color'] = $data['secondary_color'];
        }

        if (isset($data['custom_css'])) {
            $updateData['custom_css'] = $branding->sanitizeCustomCss($data['custom_css']);
        }

        if (isset($data['email_templates'])) {
            $updateData['email_templates'] = $data['email_templates'];
        }

        // Store custom_html and accent_color in settings for now (not in DB schema yet)
        $settings = $branding->settings ?? [];

        if (isset($data['custom_html'])) {
            $settings['custom_html'] = $this->sanitizeHTML($data['custom_html']);
        }

        if (isset($data['accent_color'])) {
            $settings['accent_color'] = $data['accent_color'];
        }

        if (isset($data['settings'])) {
            $settings = array_merge($settings, $data['settings']);
        }

        if (! empty($settings)) {
            $updateData['settings'] = $settings;
        }

        $branding->update($updateData);

        return $branding->fresh();
    }

    /**
     * Upload logo
     *
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function uploadLogo(Organization $organization, UploadedFile $file): string
    {
        try {
            $this->validateImage($file, 'logo');

            $branding = $this->getOrCreateBranding($organization);

            // Delete all old logos in the organization's logo directory
            $logoDirectory = "branding/logos/{$organization->id}";
            if (Storage::disk('public')->exists($logoDirectory)) {
                Storage::disk('public')->deleteDirectory($logoDirectory);
            }

            // Store file using hashName for consistency with tests
            $path = $file->store($logoDirectory, 'public');

            // Update branding record
            $branding->update(['logo_path' => $path]);

            Log::info('Logo uploaded', [
                'organization_id' => $organization->id,
                'path' => $path,
            ]);

            return Storage::disk('public')->url($path);
        } catch (InvalidArgumentException $e) {
            // Let validation exceptions through without wrapping
            throw $e;
        } catch (Exception $e) {
            Log::error('Failed to upload logo', [
                'organization_id' => $organization->id,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('Failed to upload logo: '.$e->getMessage());
        }
    }

    /**
     * Upload login background
     *
     * @throws InvalidArgumentException
     * @throws Exception
     */
    public function uploadBackground(Organization $organization, UploadedFile $file): string
    {
        try {
            $this->validateImage($file, 'background');

            $branding = $this->getOrCreateBranding($organization);

            // Delete all old backgrounds in the organization's background directory
            $backgroundDirectory = "branding/backgrounds/{$organization->id}";
            if (Storage::disk('public')->exists($backgroundDirectory)) {
                Storage::disk('public')->deleteDirectory($backgroundDirectory);
            }

            // Store file using hashName for consistency with tests
            $path = $file->store($backgroundDirectory, 'public');

            // Update branding record
            $branding->update(['login_background_path' => $path]);

            Log::info('Background uploaded', [
                'organization_id' => $organization->id,
                'path' => $path,
            ]);

            return Storage::disk('public')->url($path);
        } catch (InvalidArgumentException $e) {
            // Let validation exceptions through without wrapping
            throw $e;
        } catch (Exception $e) {
            Log::error('Failed to upload background', [
                'organization_id' => $organization->id,
                'error' => $e->getMessage(),
            ]);

            throw new Exception('Failed to upload background: '.$e->getMessage());
        }
    }

    /**
     * Delete logo
     */
    public function deleteLogo(Organization $organization): void
    {
        $branding = $organization->branding()->first();

        if ($branding && $branding->logo_path) {
            Storage::disk('public')->delete($branding->logo_path);
            $branding->update(['logo_path' => null]);
        }
    }

    /**
     * Delete background
     */
    public function deleteBackground(Organization $organization): void
    {
        $branding = $organization->branding()->first();

        if ($branding && $branding->login_background_path) {
            Storage::disk('public')->delete($branding->login_background_path);
            $branding->update(['login_background_path' => null]);
        }
    }

    /**
     * Sanitize CSS to prevent XSS attacks
     */
    public function sanitizeCSS(string $css): string
    {
        // Remove dangerous patterns
        $dangerousPatterns = [
            '/<script[^>]*>.*?<\/script>/is',
            '/javascript:/i',
            '/expression\s*\(/i',
            '/behavior\s*:/i',
            '/vbscript:/i',
            '/@import\s+/i',
            '/binding\s*:/i',
            '/-moz-binding/i',
            '/onclick/i',
            '/onerror/i',
            '/onload/i',
            '/on\w+\s*=/i',
        ];

        $sanitized = $css;
        foreach ($dangerousPatterns as $pattern) {
            $sanitized = preg_replace($pattern, '', $sanitized);
        }

        // Remove any remaining script tags
        $sanitized = strip_tags($sanitized);

        return trim($sanitized);
    }

    /**
     * Sanitize HTML to prevent XSS attacks
     */
    public function sanitizeHTML(string $html): string
    {
        // Remove script tags completely (including content)
        $html = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $html);

        // Remove potentially dangerous patterns
        $dangerous = [
            '/javascript:/i',
            '/on\w+\s*=/i', // Remove all event handlers (onclick, onerror, etc.)
        ];

        foreach ($dangerous as $pattern) {
            $html = preg_replace($pattern, '', $html);
        }

        return trim($html);
    }

    /**
     * Validate image file
     *
     * @throws InvalidArgumentException
     */
    private function validateImage(UploadedFile $file, string $type = 'logo'): void
    {
        $config = config('services.branding');

        // Check extension
        $allowedExtensions = $config['allowed_extensions'] ?? ['png', 'jpg', 'jpeg', 'svg'];
        if (! in_array(strtolower($file->getClientOriginalExtension()), $allowedExtensions)) {
            throw new InvalidArgumentException(
                'Invalid file extension. Allowed: '.implode(', ', $allowedExtensions)
            );
        }

        // Check size
        $maxSize = $type === 'logo'
            ? ($config['logo_max_size'] ?? 2048)
            : ($config['background_max_size'] ?? 5120);

        if ($file->getSize() > $maxSize * 1024) {
            throw new InvalidArgumentException(
                "File size exceeds maximum of {$maxSize} KB"
            );
        }

        // Validate dimensions for images (not SVG)
        if (in_array($file->getClientOriginalExtension(), ['png', 'jpg', 'jpeg'])) {
            $dimensions = @getimagesize($file->getRealPath());

            if (! $dimensions) {
                throw new InvalidArgumentException('Invalid image file');
            }

            $maxWidth = $type === 'logo' ? 2000 : 4000;
            $maxHeight = $type === 'logo' ? 2000 : 4000;

            if ($dimensions[0] > $maxWidth || $dimensions[1] > $maxHeight) {
                throw new InvalidArgumentException(
                    "Image dimensions exceed maximum of {$maxWidth}x{$maxHeight} pixels"
                );
            }
        }
    }
}
