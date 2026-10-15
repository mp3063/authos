<?php

namespace Tests\Integration\OAuth;

use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class DeviceCodeGrantDisabledTest extends TestCase
{
    #[Test]
    public function it_does_not_offer_the_device_code_grant(): void
    {
        $this->postJson('/oauth/device/code', [
            'client_id' => 'any',
            'scope' => '',
        ])->assertNotFound();
    }

    #[Test]
    public function it_does_not_register_the_device_routes(): void
    {
        $this->assertFalse(Route::has('passport.device'));
        $this->assertFalse(Route::has('passport.device.code'));
    }
}
