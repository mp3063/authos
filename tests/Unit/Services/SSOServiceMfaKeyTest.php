<?php

namespace Tests\Unit\Services;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\SSOSession;
use App\Services\SSOService;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class SSOServiceMfaKeyTest extends TestCase
{
    #[Test]
    public function it_reads_the_require_mfa_org_setting(): void
    {
        $user = $this->createUser();
        $user->organization->update(['settings' => ['require_mfa' => true]]);
        $application = Application::factory()->create(['organization_id' => $user->organization_id]);
        $user->applications()->attach($application->id, ['granted_at' => now()]);
        $config = SSOConfiguration::factory()->create([
            'application_id' => $application->id,
            'provider' => 'oidc',
            'is_active' => true,
        ]);

        $result = app(SSOService::class)->initiateSSOFlow($user->id, $application->id, $config->id);

        $session = SSOSession::where('session_token', $result['session_token'])->firstOrFail();
        $this->assertArrayHasKey('mfa_verified', $session->metadata);
        $this->assertFalse($session->metadata['mfa_verified']);
    }
}
