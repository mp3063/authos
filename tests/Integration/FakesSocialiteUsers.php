<?php

namespace Tests\Integration;

use App\Services\SocialAuthService;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use Mockery;

trait FakesSocialiteUsers
{
    protected function signInThroughFakedSocialiteAs(string $provider, string $providerId, string $email): void
    {
        $this->useRealSocialAuthService();

        $socialUser = (new SocialiteTwoUser)
            ->setRaw(['id' => $providerId])
            ->map(['id' => $providerId, 'name' => 'Social User', 'email' => $email, 'nickname' => null, 'avatar' => null])
            ->setToken('provider-token');

        $driver = Mockery::mock();
        $driver->shouldReceive('stateless')->andReturnSelf();
        $driver->shouldReceive('user')->andReturn($socialUser);
        Socialite::shouldReceive('driver')->with($provider)->andReturn($driver);
    }

    protected function useRealSocialAuthService(): void
    {
        $this->app->forgetInstance(SocialAuthService::class);
    }
}
