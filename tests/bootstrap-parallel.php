<?php

/**
 * Bootstrap file for parallel test execution
 *
 * This file configures per-process SQLite databases when running tests in parallel.
 * ParaTest sets TEST_TOKEN environment variable for each process, which we use
 * to create separate database files and prevent "no such table" race conditions.
 */

// Check if we're running in parallel mode (ParaTest sets TEST_TOKEN)
$testToken = getenv('TEST_TOKEN');

if ($testToken !== false && $testToken !== '') {
    // We're running in parallel - use per-process SQLite file
    $basePath = dirname(__DIR__);
    $databaseDir = $basePath.'/database';
    $databasePath = $databaseDir."/testing_parallel_{$testToken}.sqlite";

    // Create empty database file if it doesn't exist
    if (! file_exists($databasePath)) {
        touch($databasePath);
    }

    // Set the database path for this process
    putenv("DB_DATABASE={$databasePath}");
    $_ENV['DB_DATABASE'] = $databasePath;
    $_SERVER['DB_DATABASE'] = $databasePath;
}
// Otherwise, phpunit.xml already sets DB_DATABASE=:memory: for sequential execution

// Load the standard Laravel autoloader
require_once dirname(__DIR__).'/vendor/autoload.php';
