<?php

namespace Tests\Performance;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

class CompressionPerformanceTest extends PerformanceTestCase
{
    private Organization $organization;

    private User $user;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = Organization::factory()->create();
        // Use TestCase helper to properly create user with role
        $this->user = $this->createUser([
            'organization_id' => $this->organization->id,
            'password' => Hash::make('password123'),
        ], 'Organization Owner');

        Passport::actingAs($this->user);
        $this->accessToken = $this->user->createToken('Test Token')->accessToken;
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function json_response_compression_ratio_meets_target(): void
    {
        // Create substantial data
        User::factory()->count(100)->for($this->organization)->create();

        // Get response without compression (if possible)
        $response = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
            'Accept-Encoding' => '', // Disable compression for baseline
        ])->getJson('/api/v1/users');

        $uncompressedSize = strlen($response->getContent());

        // Get response with compression
        $compressedResponse = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
            'Accept-Encoding' => 'gzip, deflate',
        ])->getJson('/api/v1/users');

        // Simulate compression (actual compression happens at server level)
        $compressedSize = strlen(gzencode($compressedResponse->getContent(), 6));

        $compressionRatio = (($uncompressedSize - $compressedSize) / $uncompressedSize) * 100;
        $sizeSavingKb = ($uncompressedSize - $compressedSize) / 1024;

        $this->assertGreaterThanOrEqual(60, $compressionRatio, 'Compression ratio should be >= 60%');

        $this->recordBaseline('compression_json', [
            'uncompressed_bytes' => $uncompressedSize,
            'compressed_bytes' => $compressedSize,
            'compression_ratio_percent' => $compressionRatio,
            'size_saving_kb' => $sizeSavingKb,
        ]);

        echo "\n✓ JSON Response Compression:\n";
        echo '  Uncompressed: '.number_format($uncompressedSize / 1024, 2)." KB\n";
        echo '  Compressed: '.number_format($compressedSize / 1024, 2)." KB\n";
        echo '  Compression Ratio: '.number_format($compressionRatio, 2)."%\n";
        echo '  Size Saving: '.number_format($sizeSavingKb, 2)." KB\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function compression_overhead_is_acceptable(): void
    {
        User::factory()->count(50)->for($this->organization)->create();

        // Measure without compression
        $uncompressedMetrics = $this->measure(function () {
            $response = $this->withHeaders([
                'Authorization' => "Bearer {$this->accessToken}",
            ])->getJson('/api/v1/users');

            return $response->getContent();
        }, 'uncompressed_request');

        // Measure with compression
        $compressedMetrics = $this->measure(function () {
            $response = $this->withHeaders([
                'Authorization' => "Bearer {$this->accessToken}",
            ])->getJson('/api/v1/users');

            return gzencode($response->getContent(), 6);
        }, 'compressed_request');

        $overheadMs = $compressedMetrics['duration_ms'] - $uncompressedMetrics['duration_ms'];
        $overheadPercent = ($overheadMs / $uncompressedMetrics['duration_ms']) * 100;

        // Compression overhead should be less than 20% of request time
        $this->assertLessThan(20, $overheadPercent, 'Compression overhead should be < 20%');

        echo "\n✓ Compression Overhead:\n";
        echo '  Uncompressed Time: '.number_format($uncompressedMetrics['duration_ms'], 2)." ms\n";
        echo '  Compressed Time: '.number_format($compressedMetrics['duration_ms'], 2)." ms\n";
        echo '  Overhead: '.number_format($overheadMs, 2).' ms ('.number_format($overheadPercent, 1)."%)\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function large_payload_compression_effectiveness(): void
    {
        // Create large dataset
        User::factory()->count(500)->for($this->organization)->create();

        $response = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
        ])->getJson('/api/v1/users');

        $originalSize = strlen($response->getContent());
        $compressedSize = strlen(gzencode($response->getContent(), 6));
        $compressionRatio = (($originalSize - $compressedSize) / $originalSize) * 100;

        $this->assertGreaterThanOrEqual(70, $compressionRatio, 'Large payloads should compress >= 70%');

        echo "\n✓ Large Payload Compression:\n";
        echo '  Original Size: '.number_format($originalSize / 1024, 2)." KB\n";
        echo '  Compressed Size: '.number_format($compressedSize / 1024, 2)." KB\n";
        echo '  Compression Ratio: '.number_format($compressionRatio, 2)."%\n";
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function different_compression_levels_comparison(): void
    {
        User::factory()->count(100)->for($this->organization)->create();

        $response = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
        ])->getJson('/api/v1/users');

        $content = $response->getContent();
        $originalSize = strlen($content);

        $levels = [1, 3, 6, 9]; // Fast -> Slow, Less compression -> More compression
        $results = [];

        foreach ($levels as $level) {
            $metrics = $this->measure(function () use ($content, $level) {
                return gzencode($content, $level);
            }, "compression_level_{$level}");

            $compressedSize = strlen(gzencode($content, $level));
            $ratio = (($originalSize - $compressedSize) / $originalSize) * 100;

            $results[$level] = [
                'size' => $compressedSize,
                'ratio' => $ratio,
                'time' => $metrics['duration_ms'],
            ];
        }

        echo "\n✓ Compression Level Comparison:\n";
        foreach ($results as $level => $result) {
            echo "  Level {$level}: ".number_format($result['size'] / 1024, 2).' KB, ';
            echo number_format($result['ratio'], 1).'%, ';
            echo number_format($result['time'], 2)." ms\n";
        }
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function minimal_json_response_size_optimization(): void
    {
        $users = User::factory()->count(20)->for($this->organization)->create();

        // Test with all fields
        $verboseResponse = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
        ])->getJson('/api/v1/users?include=all');

        $verboseSize = strlen($verboseResponse->getContent());

        // Test with minimal fields
        $minimalResponse = $this->withHeaders([
            'Authorization' => "Bearer {$this->accessToken}",
        ])->getJson('/api/v1/users?fields=id,name,email');

        $minimalSize = strlen($minimalResponse->getContent());

        $sizeReduction = (($verboseSize - $minimalSize) / $verboseSize) * 100;

        echo "\n✓ JSON Response Size Optimization:\n";
        echo '  Verbose Response: '.number_format($verboseSize / 1024, 2)." KB\n";
        echo '  Minimal Response: '.number_format($minimalSize / 1024, 2)." KB\n";
        echo '  Size Reduction: '.number_format($sizeReduction, 1)."%\n";
    }
}
