<?php

namespace Tests\Unit\Services\Security;

use App\Models\IpBlocklist;
use App\Models\User;
use App\Services\Security\IpBlocklistService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Tests\TestCase;

class IpBlocklistServiceTest extends TestCase
{
    private IpBlocklistService $service;

    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new IpBlocklistService;
        Cache::flush();
    }

    protected function tearDown(): void
    {
        // Clean up Mockery expectations to prevent "risky" test warnings
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_blocks_ip_address(): void
    {
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $block = $this->service->blockIp($ipAddress, 'temporary', 'Test block');

        $this->assertInstanceOf(IpBlocklist::class, $block);
        $this->assertEquals($ipAddress, $block->ip_address);
        $this->assertEquals('temporary', $block->block_type);
        $this->assertEquals('Test block', $block->reason);
        $this->assertTrue($block->is_active);
        $this->assertNotNull($block->expires_at);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_blocks_ip_permanently(): void
    {
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $block = $this->service->blockIp($ipAddress, 'permanent', 'Permanent ban');

        $this->assertEquals('permanent', $block->block_type);
        $this->assertNull($block->expires_at);
        $this->assertTrue($block->is_active);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_custom_duration_for_temporary_block(): void
    {
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $block = $this->service->blockIp($ipAddress, 'temporary', 'Test block', 48);

        $expectedExpiry = now()->addHours(48);
        $this->assertEqualsWithDelta(
            $expectedExpiry->timestamp,
            $block->expires_at->timestamp,
            60 // 1 minute delta
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_uses_default_duration_from_config(): void
    {
        Config::set('security.ip_blocklist.default_block_duration_hours', 72);

        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $block = $this->service->blockIp($ipAddress, 'temporary', 'Test block');

        $expectedExpiry = now()->addHours(72);
        $this->assertEqualsWithDelta(
            $expectedExpiry->timestamp,
            $block->expires_at->timestamp,
            60
        );
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_updates_existing_block(): void
    {
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning')->twice();

        // Create initial block
        $firstBlock = $this->service->blockIp($ipAddress, 'temporary', 'First violation', 24);

        // Block again with different reason
        $secondBlock = $this->service->blockIp($ipAddress, 'temporary', 'Second violation', 48);

        // Should be the same record, updated
        $this->assertEquals($firstBlock->id, $secondBlock->id);
        $this->assertEquals('Second violation', $secondBlock->reason);
        $this->assertEquals(2, $secondBlock->incident_count);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_tracks_blocked_by_user(): void
    {
        $ipAddress = '192.168.1.1';
        $admin = User::factory()->create();

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        $block = $this->service->blockIp($ipAddress, 'temporary', 'Admin block', null, $admin);

        $this->assertEquals($admin->id, $block->blocked_by);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_unblocks_ip_address(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        $result = $this->service->unblockIp($ipAddress);

        $this->assertTrue($result);

        $block = IpBlocklist::where('ip_address', $ipAddress)->first();
        $this->assertFalse($block->is_active);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_false_when_unblocking_non_blocked_ip(): void
    {
        $ipAddress = '192.168.1.1';

        $result = $this->service->unblockIp($ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_if_ip_is_blocked(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'expires_at' => now()->addHours(24),
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_ip_not_blocked_when_inactive(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => false,
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_ip_not_blocked_when_expired(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'expires_at' => now()->subHours(1),
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertFalse($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_checks_permanent_block_has_no_expiry(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'block_type' => 'permanent',
            'expires_at' => null,
        ]);

        $result = $this->service->isIpBlocked($ipAddress);

        $this->assertTrue($result);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_blocked_ips_with_caching(): void
    {
        IpBlocklist::factory()->count(5)->create([
            'is_active' => true,
            'expires_at' => now()->addHours(24),
        ]);

        // First call should query database
        $firstCall = $this->service->getBlockedIps();

        // Second call should use cache
        $secondCall = $this->service->getBlockedIps();

        $this->assertCount(5, $firstCall);
        $this->assertEquals($firstCall, $secondCall);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_expires_temporary_blocks(): void
    {
        // Create active blocks with expired timestamps
        IpBlocklist::factory()->count(3)->create([
            'is_active' => true,
            'block_type' => 'temporary',
            'expires_at' => now()->subHours(1),
        ]);

        // Create one that hasn't expired
        IpBlocklist::factory()->create([
            'is_active' => true,
            'block_type' => 'temporary',
            'expires_at' => now()->addHours(1),
        ]);

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        $expired = $this->service->expireBlocks();

        $this->assertEquals(3, $expired);
        $this->assertEquals(1, IpBlocklist::where('is_active', true)->count());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_does_not_expire_permanent_blocks(): void
    {
        IpBlocklist::factory()->create([
            'is_active' => true,
            'block_type' => 'permanent',
            'expires_at' => null,
        ]);

        $expired = $this->service->expireBlocks();

        $this->assertEquals(0, $expired);
        $this->assertEquals(1, IpBlocklist::where('is_active', true)->count());
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_block_details(): void
    {
        $ipAddress = '192.168.1.1';

        $created = IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
            'block_type' => 'temporary',
            'reason' => 'Test block',
            'expires_at' => now()->addHours(24),
        ]);

        $details = $this->service->getBlockDetails($ipAddress);

        $this->assertNotNull($details);
        $this->assertEquals($created->id, $details->id);
        $this->assertEquals('Test block', $details->reason);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_returns_null_for_non_blocked_ip_details(): void
    {
        $ipAddress = '192.168.1.1';

        $details = $this->service->getBlockDetails($ipAddress);

        $this->assertNull($details);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_cache_on_block(): void
    {
        $ipAddress = '192.168.1.1';

        // Populate cache
        $this->service->getBlockedIps();

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning');

        // Block should clear cache
        $this->service->blockIp($ipAddress);

        // Verify cache was cleared by checking it's repopulated
        $blocked = $this->service->getBlockedIps();
        $this->assertCount(1, $blocked);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_clears_cache_on_unblock(): void
    {
        $ipAddress = '192.168.1.1';

        IpBlocklist::factory()->create([
            'ip_address' => $ipAddress,
            'is_active' => true,
        ]);

        // Populate cache
        $this->service->getBlockedIps();

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('info');

        // Unblock should clear cache
        $this->service->unblockIp($ipAddress);

        // Verify cache was cleared
        $blocked = $this->service->getBlockedIps();
        $this->assertCount(0, $blocked);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_gets_statistics(): void
    {
        IpBlocklist::factory()->count(3)->create([
            'is_active' => true,
            'block_type' => 'permanent',
        ]);

        IpBlocklist::factory()->count(5)->create([
            'is_active' => true,
            'block_type' => 'temporary',
            'expires_at' => now()->addHours(24),
        ]);

        IpBlocklist::factory()->count(2)->create([
            'is_active' => false, // Inactive
        ]);

        IpBlocklist::factory()->create([
            'is_active' => true,
            'block_type' => 'temporary',
            'blocked_at' => now()->subMinutes(30),
        ]);

        $stats = $this->service->getStatistics();

        $this->assertEquals(9, $stats['total_active_blocks']);
        $this->assertEquals(3, $stats['permanent_blocks']);
        $this->assertEquals(6, $stats['temporary_blocks']);
        $this->assertGreaterThanOrEqual(1, $stats['blocks_today']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function it_handles_multiple_blocks_for_same_ip(): void
    {
        $ipAddress = '192.168.1.1';

        Log::shouldReceive('channel')->andReturnSelf();
        Log::shouldReceive('warning')->times(3);

        // First block
        $block1 = $this->service->blockIp($ipAddress, 'temporary', 'First violation');
        $this->assertEquals(1, $block1->incident_count);

        // Second block (should update)
        $block2 = $this->service->blockIp($ipAddress, 'temporary', 'Second violation');
        $this->assertEquals(2, $block2->incident_count);

        // Third block (should update again)
        $block3 = $this->service->blockIp($ipAddress, 'temporary', 'Third violation');
        $this->assertEquals(3, $block3->incident_count);

        // All should be same record
        $this->assertEquals($block1->id, $block2->id);
        $this->assertEquals($block2->id, $block3->id);
    }
}
