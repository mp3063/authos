<?php

namespace App\Services;

use App\Services\Contracts\BaseServiceInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Base service class providing common functionality
 */
abstract class BaseService implements BaseServiceInterface
{
    /**
     * Execute database transaction with error handling
     */
    protected function executeInTransaction(callable $callback): mixed
    {
        return DB::transaction(function () use ($callback) {
            try {
                return $callback();
            } catch (\Exception $e) {
                Log::error('Service transaction failed', [
                    'service' => static::class,
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString(),
                ]);
                throw $e;
            }
        });
    }

    /**
     * Log service action
     */
    protected function logAction(string $action, array $context = []): void
    {
        Log::info("Service action: {$action}", array_merge([
            'service' => static::class,
            'timestamp' => now()->toISOString(),
        ], $context));
    }

    /**
     * Handle service exceptions
     */
    protected function handleException(\Exception $exception, string $action, array $context = []): void
    {
        Log::error("Service error in {$action}", array_merge([
            'service' => static::class,
            'error' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
        ], $context));
    }
}
