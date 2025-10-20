<?php

namespace App\Database;

use Illuminate\Database\SQLiteConnection;

class TestingSQLiteConnection extends SQLiteConnection
{
    /**
     * Configure PDO for better parallel test execution
     * Increase timeout and enable WAL mode
     */
    protected function configurePdoForTesting(\PDO $pdo): void
    {
        // Increase busy timeout to 30 seconds (30000 ms) for parallel tests
        // This prevents "database is locked" errors in parallel execution
        $pdo->exec('PRAGMA busy_timeout = 30000');

        // Enable Write-Ahead Logging for better concurrency
        $pdo->exec('PRAGMA journal_mode = WAL');

        // Improve performance for testing
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA cache_size = 10000');
    }

    /**
     * Get a new PDO instance for the connection
     */
    public function getPdo(): \PDO
    {
        $pdo = parent::getPdo();

        // Configure PDO settings once per connection
        static $configured = [];
        $connectionKey = spl_object_id($pdo);

        if (!isset($configured[$connectionKey])) {
            $this->configurePdoForTesting($pdo);
            $configured[$connectionKey] = true;
        }

        return $pdo;
    }

    /**
     * Run the statement to start a new transaction.
     *
     * Fix for PHP 8.4: Check if already in transaction before attempting to start one.
     * SQLite doesn't support nested transactions, so we need to track this ourselves.
     * Also includes retry logic for "database is locked" errors in parallel tests.
     *
     * @return void
     */
    protected function executeBeginTransactionStatement()
    {
        $pdo = $this->getPdo();

        // Check if we're already in a transaction
        // If yes, don't try to start another one (SQLite doesn't support nested transactions)
        try {
            if ($pdo->inTransaction()) {
                // Already in a transaction - don't start a new one
                // This prevents "cannot start a transaction within a transaction" errors
                return;
            }
        } catch (\Exception $e) {
            // inTransaction() failed - try to start transaction anyway
        }

        // Start the transaction with retry logic for "database is locked" errors
        $maxRetries = 3;
        $retryDelay = 100000; // 100ms in microseconds

        for ($attempt = 0; $attempt < $maxRetries; $attempt++) {
            try {
                if (version_compare(PHP_VERSION, '8.4.0') >= 0) {
                    // For PHP 8.4, we still need to use the explicit BEGIN statement
                    // but only if we're not already in a transaction
                    $mode = $this->getConfig('transaction_mode') ?? 'DEFERRED';
                    $pdo->exec("BEGIN {$mode} TRANSACTION");
                } else {
                    $pdo->beginTransaction();
                }

                // Success - exit the retry loop
                return;
            } catch (\PDOException $e) {
                // If we get "cannot start a transaction within a transaction", just ignore
                if (str_contains($e->getMessage(), 'cannot start a transaction within a transaction')) {
                    return;
                }

                // If database is locked and we have retries left, wait and retry
                if (str_contains($e->getMessage(), 'database is locked') && $attempt < $maxRetries - 1) {
                    usleep($retryDelay * ($attempt + 1)); // Exponential backoff
                    continue;
                }

                // Other errors or max retries reached - throw
                throw $e;
            }
        }
    }
}
