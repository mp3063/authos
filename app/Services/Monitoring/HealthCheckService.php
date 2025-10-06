<?php

namespace App\Services\Monitoring;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

class HealthCheckService
{
    /**
     * Perform comprehensive health check.
     */
    public function checkHealth(bool $detailed = false): array
    {
        $checks = [
            'database' => $this->checkDatabase(),
            'cache' => $this->checkCache(),
            'oauth' => $this->checkOAuth(),
            'storage' => $this->checkStorage(),
            'queue' => $this->checkQueue(),
        ];

        if ($detailed) {
            $checks['ldap'] = $this->checkLDAP();
            $checks['email'] = $this->checkEmail();
            $checks['disk_space'] = $this->checkDiskSpace();
            $checks['php_extensions'] = $this->checkPhpExtensions();
        }

        $overallStatus = $this->calculateOverallStatus($checks);

        return [
            'status' => $overallStatus,
            'timestamp' => now()->toIso8601String(),
            'checks' => $checks,
            'version' => config('app.version', '1.0.0'),
            'environment' => config('app.env'),
        ];
    }

    /**
     * Check database connectivity and performance.
     */
    public function checkDatabase(): array
    {
        $startTime = microtime(true);

        try {
            // Test connection
            DB::connection()->getPdo();

            // Test query performance
            $queryStart = microtime(true);
            DB::table('users')->limit(1)->count();
            $queryTime = round((microtime(true) - $queryStart) * 1000, 2);

            // Get connection info
            $connection = DB::connection();
            $driverName = $connection->getDriverName();
            $databaseName = $connection->getDatabaseName();

            // Get table count
            $tables = $this->getDatabaseTableCount();

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'query_time_ms' => $queryTime,
                'driver' => $driverName,
                'database' => $databaseName,
                'tables' => $tables,
                'message' => 'Database connection successful',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('Database health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Database connection failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check cache system connectivity.
     */
    public function checkCache(): array
    {
        $startTime = microtime(true);

        try {
            $testKey = 'health_check_'.time();
            $testValue = 'test_'.rand(1000, 9999);

            // Test write
            Cache::put($testKey, $testValue, 10);

            // Test read
            $retrieved = Cache::get($testKey);

            // Test delete
            Cache::forget($testKey);

            if ($retrieved !== $testValue) {
                throw new \Exception('Cache read/write mismatch');
            }

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'driver' => config('cache.default'),
                'message' => 'Cache system operational',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('Cache health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Cache system failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check OAuth/Passport configuration.
     */
    public function checkOAuth(): array
    {
        $startTime = microtime(true);

        try {
            $issues = [];

            // Check private key
            $privateKeyPath = storage_path('oauth-private.key');
            if (! File::exists($privateKeyPath)) {
                $issues[] = 'Private key not found';
            } elseif (! is_readable($privateKeyPath)) {
                $issues[] = 'Private key not readable';
            }

            // Check public key
            $publicKeyPath = storage_path('oauth-public.key');
            if (! File::exists($publicKeyPath)) {
                $issues[] = 'Public key not found';
            } elseif (! is_readable($publicKeyPath)) {
                $issues[] = 'Public key not readable';
            }

            // Check for clients
            $clientCount = DB::table('oauth_clients')->count();

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            if (! empty($issues)) {
                return [
                    'status' => 'degraded',
                    'response_time_ms' => $responseTime,
                    'clients' => $clientCount,
                    'message' => 'OAuth keys have issues',
                    'issues' => $issues,
                ];
            }

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'clients' => $clientCount,
                'message' => 'OAuth system operational',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('OAuth health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'OAuth check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check storage accessibility.
     */
    public function checkStorage(): array
    {
        $startTime = microtime(true);

        try {
            $testFile = storage_path('framework/cache/health_check_'.time().'.tmp');
            $testContent = 'health_check_'.rand(1000, 9999);

            // Test write
            File::put($testFile, $testContent);

            // Test read
            $retrieved = File::get($testFile);

            // Test delete
            File::delete($testFile);

            if ($retrieved !== $testContent) {
                throw new \Exception('Storage read/write mismatch');
            }

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'writable' => true,
                'message' => 'Storage system operational',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('Storage health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Storage check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check queue system.
     */
    public function checkQueue(): array
    {
        $startTime = microtime(true);

        try {
            $connection = config('queue.default');
            $driver = config("queue.connections.{$connection}.driver");

            // Get failed jobs count
            $failedJobsCount = DB::table('failed_jobs')->count();

            // Get pending jobs count (if using database)
            $pendingJobsCount = 0;
            if ($driver === 'database') {
                $pendingJobsCount = DB::table('jobs')->count();
            }

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            $status = 'healthy';
            if ($failedJobsCount > 100) {
                $status = 'degraded';
            }

            return [
                'status' => $status,
                'response_time_ms' => $responseTime,
                'driver' => $driver,
                'failed_jobs' => $failedJobsCount,
                'pending_jobs' => $pendingJobsCount,
                'message' => $status === 'healthy' ? 'Queue system operational' : 'High number of failed jobs',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('Queue health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Queue check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check LDAP connectivity (if configured).
     */
    public function checkLDAP(): array
    {
        $startTime = microtime(true);

        try {
            $ldapConfigCount = DB::table('ldap_configurations')
                ->where('enabled', true)
                ->count();

            if ($ldapConfigCount === 0) {
                return [
                    'status' => 'not_configured',
                    'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                    'message' => 'LDAP not configured',
                ];
            }

            // If LDAP is configured, we'd test connection here
            // For now, just check configuration exists

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'configurations' => $ldapConfigCount,
                'message' => 'LDAP configurations present',
            ];

        } catch (\Exception $e) {
            Log::channel('monitoring')->error('LDAP health check failed', [
                'error' => $e->getMessage(),
            ]);

            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'LDAP check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check email system.
     */
    public function checkEmail(): array
    {
        $startTime = microtime(true);

        try {
            $mailer = config('mail.default');
            $driver = config("mail.mailers.{$mailer}.transport");

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            return [
                'status' => 'healthy',
                'response_time_ms' => $responseTime,
                'driver' => $driver,
                'message' => 'Email system configured',
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Email check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check disk space.
     */
    public function checkDiskSpace(): array
    {
        $startTime = microtime(true);

        try {
            $path = storage_path();
            $freeSpace = disk_free_space($path);
            $totalSpace = disk_total_space($path);
            $usedSpace = $totalSpace - $freeSpace;
            $usedPercentage = round(($usedSpace / $totalSpace) * 100, 2);

            $responseTime = round((microtime(true) - $startTime) * 1000, 2);

            $status = 'healthy';
            if ($usedPercentage > 90) {
                $status = 'critical';
            } elseif ($usedPercentage > 80) {
                $status = 'degraded';
            }

            return [
                'status' => $status,
                'response_time_ms' => $responseTime,
                'free_space_bytes' => $freeSpace,
                'total_space_bytes' => $totalSpace,
                'used_percentage' => $usedPercentage,
                'message' => $status === 'healthy' ? 'Disk space adequate' : 'Low disk space',
            ];

        } catch (\Exception $e) {
            return [
                'status' => 'unhealthy',
                'response_time_ms' => round((microtime(true) - $startTime) * 1000, 2),
                'message' => 'Disk space check failed: '.$e->getMessage(),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Check required PHP extensions.
     */
    public function checkPhpExtensions(): array
    {
        $startTime = microtime(true);

        $requiredExtensions = [
            'openssl',
            'pdo',
            'mbstring',
            'tokenizer',
            'xml',
            'ctype',
            'json',
            'bcmath',
        ];

        $missingExtensions = [];
        foreach ($requiredExtensions as $extension) {
            if (! extension_loaded($extension)) {
                $missingExtensions[] = $extension;
            }
        }

        $responseTime = round((microtime(true) - $startTime) * 1000, 2);

        $status = empty($missingExtensions) ? 'healthy' : 'unhealthy';

        return [
            'status' => $status,
            'response_time_ms' => $responseTime,
            'required' => $requiredExtensions,
            'missing' => $missingExtensions,
            'message' => $status === 'healthy' ? 'All PHP extensions loaded' : 'Missing PHP extensions',
        ];
    }

    /**
     * Calculate overall system status.
     */
    private function calculateOverallStatus(array $checks): string
    {
        $statuses = array_column($checks, 'status');

        if (in_array('unhealthy', $statuses)) {
            return 'unhealthy';
        }

        if (in_array('critical', $statuses)) {
            return 'critical';
        }

        if (in_array('degraded', $statuses)) {
            return 'degraded';
        }

        return 'healthy';
    }

    /**
     * Get database table count.
     */
    private function getDatabaseTableCount(): int
    {
        try {
            $driver = DB::connection()->getDriverName();

            if ($driver === 'pgsql') {
                return DB::select("SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = 'public'")[0]->count;
            } elseif ($driver === 'mysql') {
                return DB::select('SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = DATABASE()')[0]->count;
            }

            return 0;
        } catch (\Exception $e) {
            return 0;
        }
    }

    /**
     * Get readiness status (for Kubernetes-style probes).
     */
    public function checkReadiness(): array
    {
        // Check critical dependencies only
        $database = $this->checkDatabase();
        $cache = $this->checkCache();

        $ready = $database['status'] === 'healthy' && $cache['status'] === 'healthy';

        return [
            'ready' => $ready,
            'timestamp' => now()->toIso8601String(),
            'checks' => [
                'database' => $database['status'],
                'cache' => $cache['status'],
            ],
        ];
    }

    /**
     * Get liveness status (for Kubernetes-style probes).
     */
    public function checkLiveness(): array
    {
        // Simple check - if we can respond, we're alive
        return [
            'alive' => true,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
