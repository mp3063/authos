#!/bin/bash
echo "=== Memory Optimized Test Run ==="
echo "Using 1GB memory limit for tests..."
echo "Starting memory optimized test suite..."
echo ""

# Run with proper memory limit and time tracking
time herd php -d memory_limit=1G -d memory_get_usage=1 artisan test

echo ""
echo "=== Test completed ==="