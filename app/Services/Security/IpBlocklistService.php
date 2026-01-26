<?php

namespace App\Services\Security;

use App\Models\IpBlocklist;
use App\Models\User;
use App\Notifications\IpBlockedNotification;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class IpBlocklistService
{
    protected string $cacheKey = 'security:blocked_ips';

    protected int $cacheTtl = 300; // 5 minutes

    /**
     * Block an IP address
     */
    public function blockIp(
        string $ipAddress,
        string $blockType = 'temporary',
        string $reason = 'Security violation',
        ?int $durationHours = null,
        ?User $blockedBy = null
    ): IpBlocklist {
        // Check if already blocked
        $existing = IpBlocklist::where('ip_address', $ipAddress)
            ->where('is_active', true)
            ->first();

        if ($existing) {
            // Update existing block
            $existing->update([
                'block_type' => $blockType,
                'reason' => $reason,
                'incident_count' => $existing->incident_count + 1,
                'expires_at' => $durationHours ? now()->addHours($durationHours) : $existing->expires_at,
            ]);

            Log::channel('security')->warning('IP address block updated', [
                'ip_address' => $ipAddress,
                'block_type' => $blockType,
                'reason' => $reason,
                'incident_count' => $existing->incident_count,
            ]);

            $this->clearCache();

            return $existing;
        }

        // Create new block
        $expiresAt = null;
        if ($blockType === 'temporary') {
            $hours = $durationHours ?? config('security.ip_blocklist.default_block_duration_hours', 24);
            $expiresAt = now()->addHours($hours);
        }

        $block = IpBlocklist::create([
            'ip_address' => $ipAddress,
            'block_type' => $blockType,
            'reason' => $reason,
            'blocked_at' => now(),
            'expires_at' => $expiresAt,
            'blocked_by' => $blockedBy?->id,
            'incident_count' => 1,
            'is_active' => true,
        ]);

        Log::channel('security')->warning('IP address blocked', [
            'ip_address' => $ipAddress,
            'block_type' => $blockType,
            'reason' => $reason,
            'expires_at' => $expiresAt,
        ]);

        // Notify admins about IP blocking
        try {
            $admins = User::role('Super Admin')->get();
            foreach ($admins as $admin) {
                $admin->notify(new IpBlockedNotification($block));
            }
        } catch (\Spatie\Permission\Exceptions\RoleDoesNotExist $e) {
            // Role may not exist in test environment
        }

        $this->clearCache();

        return $block;
    }

    /**
     * Unblock an IP address
     */
    public function unblockIp(string $ipAddress): bool
    {
        $updated = IpBlocklist::where('ip_address', $ipAddress)
            ->where('is_active', true)
            ->update(['is_active' => false]);

        if ($updated) {
            Log::channel('security')->info('IP address unblocked', [
                'ip_address' => $ipAddress,
            ]);

            $this->clearCache();

            return true;
        }

        return false;
    }

    /**
     * Check if IP is blocked (with caching)
     */
    public function isIpBlocked(string $ipAddress): bool
    {
        $blockedIps = $this->getBlockedIps();

        return $blockedIps->contains($ipAddress);
    }

    /**
     * Get all currently blocked IPs (cached)
     */
    public function getBlockedIps(): Collection
    {
        return Cache::remember($this->cacheKey, $this->cacheTtl, function () {
            return IpBlocklist::where('is_active', true)
                ->where(function ($query) {
                    $query->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                })
                ->pluck('ip_address');
        });
    }

    /**
     * Auto-expire temporary blocks
     */
    public function expireBlocks(): int
    {
        $expired = IpBlocklist::where('is_active', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->update(['is_active' => false]);

        if ($expired > 0) {
            Log::channel('security')->info("Expired {$expired} IP blocks");
            $this->clearCache();
        }

        return $expired;
    }

    /**
     * Get block details for IP
     */
    public function getBlockDetails(string $ipAddress): ?IpBlocklist
    {
        return IpBlocklist::where('ip_address', $ipAddress)
            ->where('is_active', true)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->first();
    }

    /**
     * Clear blocked IPs cache
     */
    protected function clearCache(): void
    {
        Cache::forget($this->cacheKey);
    }

    /**
     * Get statistics
     */
    public function getStatistics(): array
    {
        return [
            'total_active_blocks' => IpBlocklist::where('is_active', true)->count(),
            'permanent_blocks' => IpBlocklist::where('is_active', true)
                ->where('block_type', 'permanent')->count(),
            'temporary_blocks' => IpBlocklist::where('is_active', true)
                ->where('block_type', 'temporary')->count(),
            'expired_blocks' => IpBlocklist::where('is_active', false)->count(),
            'blocks_today' => IpBlocklist::where('blocked_at', '>=', now()->subDay())->count(),
            'total_incidents' => IpBlocklist::sum('incident_count'),
        ];
    }
}
