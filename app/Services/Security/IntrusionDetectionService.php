<?php

namespace App\Services\Security;

use App\Models\FailedLoginAttempt;
use App\Models\IpBlocklist;
use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class IntrusionDetectionService
{
    protected SecurityIncidentService $incidentService;

    protected IpBlocklistService $ipBlocklistService;

    public function __construct(
        SecurityIncidentService $incidentService,
        IpBlocklistService $ipBlocklistService
    ) {
        $this->incidentService = $incidentService;
        $this->ipBlocklistService = $ipBlocklistService;
    }

    /**
     * Check for brute force attacks
     */
    public function detectBruteForce(string $email, string $ipAddress): bool
    {
        $timeWindow = now()->subMinutes(15);

        // Check failed attempts by email
        $emailAttempts = FailedLoginAttempt::where('email', $email)
            ->where('attempted_at', '>=', $timeWindow)
            ->count();

        // Check failed attempts by IP
        $ipAttempts = FailedLoginAttempt::where('ip_address', $ipAddress)
            ->where('attempted_at', '>=', $timeWindow)
            ->count();

        // Thresholds for detection
        $emailThreshold = config('security.brute_force.email_threshold', 5);
        $ipThreshold = config('security.brute_force.ip_threshold', 10);

        if ($emailAttempts >= $emailThreshold || $ipAttempts >= $ipThreshold) {
            $this->incidentService->createIncident([
                'type' => 'brute_force',
                'severity' => $emailAttempts >= $emailThreshold * 2 ? 'critical' : 'high',
                'ip_address' => $ipAddress,
                'endpoint' => '/api/auth/login',
                'description' => "Brute force attack detected: {$emailAttempts} attempts on email, {$ipAttempts} attempts from IP",
                'metadata' => [
                    'email' => $email,
                    'email_attempts' => $emailAttempts,
                    'ip_attempts' => $ipAttempts,
                ],
            ]);

            // Auto-block IP if threshold is severe
            if ($ipAttempts >= $ipThreshold * 2) {
                $this->ipBlocklistService->blockIp($ipAddress, 'brute_force', 'Automatic block due to excessive failed login attempts');
            }

            return true;
        }

        return false;
    }

    /**
     * Detect credential stuffing attacks
     */
    public function detectCredentialStuffing(string $ipAddress): bool
    {
        $timeWindow = now()->subMinutes(5);

        // Count unique emails attempted from this IP
        $uniqueEmails = FailedLoginAttempt::where('ip_address', $ipAddress)
            ->where('attempted_at', '>=', $timeWindow)
            ->distinct('email')
            ->count('email');

        $threshold = config('security.credential_stuffing.threshold', 10);

        if ($uniqueEmails >= $threshold) {
            $this->incidentService->createIncident([
                'type' => 'credential_stuffing',
                'severity' => 'critical',
                'ip_address' => $ipAddress,
                'endpoint' => '/api/auth/login',
                'description' => "Credential stuffing attack detected: {$uniqueEmails} unique email attempts in 5 minutes",
                'metadata' => [
                    'unique_emails_count' => $uniqueEmails,
                ],
            ]);

            // Immediate IP block for credential stuffing
            $this->ipBlocklistService->blockIp($ipAddress, 'credential_stuffing', 'Automatic block due to credential stuffing attack');

            return true;
        }

        return false;
    }

    /**
     * Detect suspicious API usage patterns
     */
    public function detectAnomalousApiActivity(Request $request): bool
    {
        $ipAddress = $request->ip();
        $cacheKey = "api_requests:{$ipAddress}";

        // Track requests per minute
        $requests = Cache::get($cacheKey, []);
        $requests[] = now()->timestamp;

        // Keep only requests from last minute
        $requests = array_filter($requests, fn ($timestamp) => $timestamp >= now()->subMinute()->timestamp);

        Cache::put($cacheKey, $requests, now()->addMinutes(2));

        $requestsPerMinute = count($requests);
        $threshold = config('security.api_rate.anomaly_threshold', 100);

        if ($requestsPerMinute >= $threshold) {
            $this->incidentService->createIncident([
                'type' => 'api_abuse',
                'severity' => 'high',
                'ip_address' => $ipAddress,
                'endpoint' => $request->path(),
                'description' => "Anomalous API activity: {$requestsPerMinute} requests per minute",
                'metadata' => [
                    'requests_per_minute' => $requestsPerMinute,
                    'user_agent' => $request->userAgent(),
                ],
            ]);

            return true;
        }

        return false;
    }

    /**
     * Detect SQL injection attempts
     */
    public function detectSqlInjection(Request $request): bool
    {
        $sqlPatterns = [
            '/(\bOR\b|\bAND\b).*=.*/',
            '/UNION.*SELECT/i',
            '/SELECT.*FROM/i',
            '/INSERT.*INTO/i',
            '/UPDATE.*SET/i',
            '/DELETE.*FROM/i',
            '/DROP.*TABLE/i',
            '/--|\#|\/\*/',
            '/\bEXEC\b|\bEXECUTE\b/i',
        ];

        $suspiciousInput = false;
        $matchedPattern = null;
        $matchedInput = null;

        foreach ($request->all() as $key => $value) {
            if (is_string($value)) {
                foreach ($sqlPatterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $suspiciousInput = true;
                        $matchedPattern = $pattern;
                        $matchedInput = $key;
                        break 2;
                    }
                }
            }
        }

        if ($suspiciousInput) {
            $this->incidentService->createIncident([
                'type' => 'sql_injection',
                'severity' => 'critical',
                'ip_address' => $request->ip(),
                'endpoint' => $request->path(),
                'description' => 'SQL injection attempt detected in request parameters',
                'metadata' => [
                    'pattern' => $matchedPattern,
                    'parameter' => $matchedInput,
                    'user_agent' => $request->userAgent(),
                ],
            ]);

            return true;
        }

        return false;
    }

    /**
     * Detect XSS attempts
     */
    public function detectXss(Request $request): bool
    {
        $xssPatterns = [
            '/<script\b[^>]*>/i',
            '/<\/script>/i',
            '/javascript:/i',
            '/onerror\s*=/i',
            '/onload\s*=/i',
            '/<iframe\b[^>]*>/i',
            '/<embed\b[^>]*>/i',
            '/<object\b[^>]*>/i',
        ];

        $suspiciousInput = false;
        $matchedPattern = null;
        $matchedInput = null;

        foreach ($request->all() as $key => $value) {
            if (is_string($value)) {
                foreach ($xssPatterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $suspiciousInput = true;
                        $matchedPattern = $pattern;
                        $matchedInput = $key;
                        break 2;
                    }
                }
            }
        }

        if ($suspiciousInput) {
            $this->incidentService->createIncident([
                'type' => 'xss_attempt',
                'severity' => 'high',
                'ip_address' => $request->ip(),
                'endpoint' => $request->path(),
                'description' => 'XSS attempt detected in request parameters',
                'metadata' => [
                    'pattern' => $matchedPattern,
                    'parameter' => $matchedInput,
                    'user_agent' => $request->userAgent(),
                ],
            ]);

            return true;
        }

        return false;
    }

    /**
     * Detect unusual login patterns
     */
    public function detectUnusualLoginPattern(User $user, Request $request): bool
    {
        // Check for impossible travel (login from different countries within short time)
        $lastLogin = $user->authenticationLogs()
            ->where('event', 'login_success')
            ->where('created_at', '>=', now()->subHours(2))
            ->latest()
            ->first();

        if ($lastLogin) {
            // In a real implementation, you would use GeoIP to detect location changes
            // For now, we'll check for different IPs
            if ($lastLogin->ip_address !== $request->ip()) {
                Log::channel('security')->warning('Unusual login pattern detected', [
                    'user_id' => $user->id,
                    'previous_ip' => $lastLogin->ip_address,
                    'current_ip' => $request->ip(),
                ]);

                $this->incidentService->createIncident([
                    'type' => 'unusual_login_pattern',
                    'severity' => 'medium',
                    'ip_address' => $request->ip(),
                    'user_id' => $user->id,
                    'endpoint' => '/api/auth/login',
                    'description' => 'Login from different IP address within short time frame',
                    'metadata' => [
                        'previous_ip' => $lastLogin->ip_address,
                        'current_ip' => $request->ip(),
                        'time_difference_minutes' => now()->diffInMinutes($lastLogin->created_at),
                    ],
                ]);

                return true;
            }
        }

        // Check for unusual login time (e.g., outside business hours for specific users)
        $hour = now()->hour;
        if ($hour < 6 || $hour > 22) {
            Log::channel('security')->info('Login outside normal hours', [
                'user_id' => $user->id,
                'hour' => $hour,
            ]);
        }

        return false;
    }

    /**
     * Record failed login attempt
     */
    public function recordFailedAttempt(string $email, Request $request, string $reason = 'invalid_credentials'): void
    {
        FailedLoginAttempt::create([
            'email' => $email,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'attempt_type' => 'password',
            'failure_reason' => $reason,
            'attempted_at' => now(),
            'metadata' => [
                'endpoint' => $request->path(),
                'method' => $request->method(),
            ],
        ]);

        // Detect attacks after recording
        $this->detectBruteForce($email, $request->ip());
        $this->detectCredentialStuffing($request->ip());
    }

    /**
     * Check if IP is blocked
     */
    public function isIpBlocked(string $ipAddress): bool
    {
        return IpBlocklist::where('ip_address', $ipAddress)
            ->where('is_active', true)
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->exists();
    }

    /**
     * Get security score for IP address
     */
    public function getIpSecurityScore(string $ipAddress): int
    {
        $score = 100; // Start with perfect score

        // Recent failed attempts
        $failedAttempts = FailedLoginAttempt::where('ip_address', $ipAddress)
            ->where('attempted_at', '>=', now()->subDay())
            ->count();

        $score -= min($failedAttempts * 5, 50);

        // Security incidents
        $incidents = SecurityIncident::where('ip_address', $ipAddress)
            ->where('detected_at', '>=', now()->subWeek())
            ->count();

        $score -= min($incidents * 10, 40);

        // Previous blocks
        $blocks = IpBlocklist::where('ip_address', $ipAddress)
            ->where('blocked_at', '>=', now()->subMonth())
            ->count();

        $score -= min($blocks * 20, 30);

        return max($score, 0);
    }
}
