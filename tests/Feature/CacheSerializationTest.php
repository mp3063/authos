<?php

namespace Tests\Feature;

use App\Models\IpBlocklist;
use App\Services\Security\IpBlocklistService;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

class CacheSerializationTest extends TestCase
{
    #[Test]
    public function it_runs_tests_against_a_cache_that_refuses_objects_like_production(): void
    {
        Cache::put('cache-serialization-probe', collect(['value']));

        $this->assertInstanceOf(\__PHP_Incomplete_Class::class, Cache::get('cache-serialization-probe'));
    }

    #[Test]
    public function it_reads_the_blocked_ip_list_back_from_the_cache(): void
    {
        IpBlocklist::factory()->create(['ip_address' => '203.0.113.7', 'is_active' => true, 'expires_at' => null]);
        $service = app(IpBlocklistService::class);

        $service->getBlockedIps();
        $cached = $service->getBlockedIps();

        $this->assertInstanceOf(Collection::class, $cached);
        $this->assertTrue($cached->contains('203.0.113.7'));
    }
}
