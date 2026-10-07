<?php

namespace App\Services\Monitoring;

use Exception;

class SystemResourceHealthCheck
{
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

        } catch (Exception $e) {
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
}
