<?php

namespace Tests\Feature\Auth;

use App\Models\Application;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class WebLoginSurfaceTest extends IntegrationTestCase
{
    #[Test]
    public function it_does_not_expose_fortify_login_or_registration_routes(): void
    {
        foreach (['/login', '/register', '/two-factor-challenge', '/passkeys/login'] as $uri) {
            $status = $this->post($uri)->getStatusCode();

            $this->assertSame(404, $status, "POST {$uri} returned {$status}");
        }
    }

    #[Test]
    public function it_sends_a_guest_on_oauth_authorize_to_the_panel_login(): void
    {
        $application = Application::factory()->create();
        $query = http_build_query([
            'client_id' => $application->passport_client_id,
            'redirect_uri' => $application->redirect_uris[0],
            'response_type' => 'code',
            'scope' => '',
            'state' => 'abc123',
        ]);

        $response = $this->get('/oauth/authorize?'.$query);

        $response->assertRedirect(route('filament.admin.auth.login'));
        $this->assertSame(url('/oauth/authorize?'.$query), session('url.intended'));
    }
}
