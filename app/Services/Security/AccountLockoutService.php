<?php

namespace App\Services\Security;

use App\Models\AccountLockout;
use App\Models\FailedLoginAttempt;
use App\Models\User;
use App\Notifications\AccountLockedNotification;
use App\Notifications\AccountUnlockedNotification;
use Illuminate\Support\Facades\Log;

class AccountLockoutService
{
    protected SecurityIncidentService $incidentService;

    public function __construct(SecurityIncidentService $incidentService)
    {
        $this->incidentService = $incidentService;
    }

    /**
     * Progressive lockout durations in minutes: [attempts => duration]
     */
    protected array $lockoutSchedule = [
        3 => 5,    // 3 attempts = 5 minutes
        5 => 15,   // 5 attempts = 15 minutes
        7 => 30,   // 7 attempts = 30 minutes
        10 => 60,  // 10 attempts = 1 hour
        15 => 1440, // 15 attempts = 24 hours
    ];

    /**
     * Check if account should be locked and apply lockout if necessary
     */
    public function checkAndApplyLockout(string $email, string $ipAddress): ?AccountLockout
    {
        $timeWindow = now()->subHour();

        $attemptCount = FailedLoginAttempt::where('email', $email)
            ->where('attempted_at', '>=', $timeWindow)
            ->count();

        $lockoutDuration = $this->getLockoutDuration($attemptCount);

        if ($lockoutDuration > 0) {
            return $this->lockAccount($email, $ipAddress, $attemptCount, $lockoutDuration);
        }

        return null;
    }

    /**
     * Lock an account
     */
    public function lockAccount(
        string $email,
        ?string $ipAddress = null,
        int $attemptCount = 0,
        ?int $durationMinutes = null,
        string $lockoutType = 'progressive'
    ): AccountLockout {
        $user = User::where('email', $email)->first();

        $unlockAt = $durationMinutes ? now()->addMinutes($durationMinutes) : null;

        $lockout = AccountLockout::create([
            'user_id' => $user?->id,
            'email' => $email,
            'ip_address' => $ipAddress,
            'lockout_type' => $lockoutType,
            'attempt_count' => $attemptCount,
            'locked_at' => now(),
            'unlock_at' => $unlockAt,
            'reason' => $this->getLockoutReason($attemptCount, $lockoutType),
        ]);

        Log::channel('security')->warning('Account locked', [
            'email' => $email,
            'attempt_count' => $attemptCount,
            'duration_minutes' => $durationMinutes,
            'unlock_at' => $unlockAt,
        ]);

        // NOTE: Security incident creation is handled by IntrusionDetectionService, not here.
        // Account lockout is a countermeasure, while intrusion detection is the detection mechanism.
        // Separation of concerns: lockout (3+ attempts) vs brute force detection (5+ attempts).

        // Send notification to user if exists
        if ($user) {
            try {
                $user->notify(new AccountLockedNotification($lockout));
            } catch (\Exception $e) {
                Log::channel('security')->error('Failed to send account locked notification', [
                    'email' => $email,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $lockout;
    }

    /**
     * Check if an account is currently locked
     */
    public function isAccountLocked(string $email): bool
    {
        return AccountLockout::where('email', $email)
            ->whereNull('unlocked_at')
            ->where(function ($query) {
                $query->whereNull('unlock_at')
                    ->orWhere('unlock_at', '>', now());
            })
            ->exists();
    }

    /**
     * Get active lockout for email
     */
    public function getActiveLockout(string $email): ?AccountLockout
    {
        return AccountLockout::where('email', $email)
            ->whereNull('unlocked_at')
            ->where(function ($query) {
                $query->whereNull('unlock_at')
                    ->orWhere('unlock_at', '>', now());
            })
            ->first();
    }

    /**
     * Unlock an account
     */
    public function unlockAccount(string $email, string $method = 'auto'): bool
    {
        $lockout = $this->getActiveLockout($email);

        if (! $lockout) {
            return false;
        }

        $lockout->update([
            'unlocked_at' => now(),
            'unlock_method' => $method,
        ]);

        Log::channel('security')->info('Account unlocked', [
            'email' => $email,
            'method' => $method,
        ]);

        // Send notification to user
        if ($lockout->user) {
            try {
                $lockout->user->notify(new AccountUnlockedNotification($lockout));
            } catch (\Exception $e) {
                Log::channel('security')->error('Failed to send account unlocked notification', [
                    'email' => $email,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return true;
    }

    /**
     * Unlock account by admin
     */
    public function unlockByAdmin(string $email, User $admin): bool
    {
        $result = $this->unlockAccount($email, 'admin');

        if ($result) {
            Log::channel('security')->info('Account unlocked by admin', [
                'email' => $email,
                'admin_id' => $admin->id,
                'admin_email' => $admin->email,
            ]);
        }

        return $result;
    }

    /**
     * Auto-unlock expired lockouts
     */
    public function unlockExpiredAccounts(): int
    {
        $expiredLockouts = AccountLockout::whereNull('unlocked_at')
            ->whereNotNull('unlock_at')
            ->where('unlock_at', '<=', now())
            ->get();

        $count = 0;

        foreach ($expiredLockouts as $lockout) {
            $lockout->update([
                'unlocked_at' => now(),
                'unlock_method' => 'auto',
            ]);

            // Send notification
            if ($lockout->user) {
                try {
                    $lockout->user->notify(new AccountUnlockedNotification($lockout));
                } catch (\Exception $e) {
                    Log::channel('security')->error('Failed to send account unlocked notification', [
                        'lockout_id' => $lockout->id,
                        'error' => $e->getMessage(),
                    ]);
                }
            }

            $count++;
        }

        if ($count > 0) {
            Log::channel('security')->info("Auto-unlocked {$count} expired accounts");
        }

        return $count;
    }

    /**
     * Get lockout duration based on attempt count
     */
    protected function getLockoutDuration(int $attemptCount): int
    {
        $lockoutDuration = 0;

        foreach ($this->lockoutSchedule as $attempts => $duration) {
            if ($attemptCount >= $attempts) {
                $lockoutDuration = $duration;
            }
        }

        return $lockoutDuration;
    }

    /**
     * Get lockout reason text
     */
    protected function getLockoutReason(int $attemptCount, string $lockoutType): string
    {
        if ($lockoutType === 'admin_initiated') {
            return 'Account locked by administrator';
        }

        if ($lockoutType === 'permanent') {
            return 'Account permanently locked due to security concerns';
        }

        $duration = $this->getLockoutDuration($attemptCount);

        return "Account temporarily locked due to {$attemptCount} failed login attempts. Duration: {$duration} minutes.";
    }

    /**
     * Get remaining lockout time in minutes
     */
    public function getRemainingLockoutTime(string $email): ?int
    {
        $lockout = $this->getActiveLockout($email);

        if (! $lockout || ! $lockout->unlock_at) {
            return null;
        }

        $remaining = now()->diffInMinutes($lockout->unlock_at, false);

        return $remaining > 0 ? $remaining : 0;
    }

    /**
     * Clear failed attempts after successful login
     */
    public function clearFailedAttempts(string $email): void
    {
        FailedLoginAttempt::where('email', $email)
            ->where('attempted_at', '>=', now()->subHour())
            ->delete();
    }
}
