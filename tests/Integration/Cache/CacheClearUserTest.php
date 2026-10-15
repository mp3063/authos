<?php

namespace Tests\Integration\Cache;

use App\Models\Organization;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;
use Tests\Integration\IntegrationTestCase;

class CacheClearUserTest extends IntegrationTestCase
{
    #[Test]
    public function it_clears_only_the_given_users_api_cache_entries(): void
    {
        config(['cache.default' => 'database']);
        $prefix = config('cache.prefix', '');
        $organization = Organization::factory()->create();
        $user = $this->createUser(['organization_id' => $organization->id], 'User', 'api');
        $other = $this->createUser(['organization_id' => $organization->id], 'User', 'api');
        $perms = md5('users.read');
        $query = md5('');

        $own = [
            "api_cache:GET:_api_v1_users:{$query}:{$user->id}:{$perms}",
            "api_cache:GET:_api_v1_organizations:{$query}:{$user->id}:".md5('a'),
        ];
        $others = [
            "api_cache:GET:_api_v1_users:{$query}:{$other->id}:{$perms}",
            "api_cache:GET:_api_v1_users_{$user->id}:{$query}:{$other->id}:{$perms}",
            "api_cache:GET:_api_v1_users:{$user->id}:{$other->id}:{$perms}",
            "api_cache:GET:_api_v1_users:{$query}:{$other->id}:{$user->id}",
        ];
        foreach ([...$own, ...$others] as $key) {
            DB::table('cache')->insert(['key' => $prefix.$key, 'value' => 's:1:"x";', 'expiration' => now()->addHour()->timestamp]);
        }

        $this->actingAsApiUserWithToken($user)->deleteJson('/api/v1/cache/clear-user')->assertOk();

        foreach ($own as $key) {
            $this->assertDatabaseMissing('cache', ['key' => $prefix.$key]);
        }
        foreach ($others as $key) {
            $this->assertDatabaseHas('cache', ['key' => $prefix.$key]);
        }
    }
}
