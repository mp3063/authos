<?php

namespace Database\Factories;

use App\Models\OAuthAuthorizationCode;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Laravel\Passport\Client;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\OAuthAuthorizationCode>
 */
class OAuthAuthorizationCodeFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     */
    protected $model = OAuthAuthorizationCode::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'id' => bin2hex(random_bytes(40)),
            'user_id' => User::factory(),
            'client_id' => function () {
                // Create a simple OAuth client for testing
                return Client::create([
                    'owner_type' => null,
                    'owner_id' => null,
                    'name' => 'Test Client',
                    'secret' => 'test_secret',
                    'provider' => null,
                    'redirect_uris' => json_encode(['http://localhost/callback']),
                    'grant_types' => json_encode(['authorization_code', 'refresh_token']),
                    'revoked' => false,
                ])->id;
            },
            'scopes' => ['openid', 'profile'],
            'redirect_uri' => $this->faker->url(),
            'code_challenge' => null,
            'code_challenge_method' => null,
            'state' => $this->faker->optional()->regexify('[A-Za-z0-9]{32}'),
            'expires_at' => now()->addMinutes(10),
            'revoked' => false,
        ];
    }

    /**
     * Create an authorization code with PKCE
     */
    public function withPKCE(): static
    {
        return $this->state(function (array $attributes) {
            $codeVerifier = base64_encode(random_bytes(32));
            $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

            return [
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => 'S256',
            ];
        });
    }

    /**
     * Create an expired authorization code
     */
    public function expired(): static
    {
        return $this->state(function (array $attributes) {
            return [
                'expires_at' => now()->subMinutes(15),
            ];
        });
    }

    /**
     * Create a revoked authorization code
     */
    public function revoked(): static
    {
        return $this->state(function (array $attributes) {
            return [
                'revoked' => true,
            ];
        });
    }

    /**
     * Create an authorization code with specific scopes
     */
    public function withScopes(array $scopes): static
    {
        return $this->state(function (array $attributes) use ($scopes) {
            return [
                'scopes' => $scopes,
            ];
        });
    }
}
