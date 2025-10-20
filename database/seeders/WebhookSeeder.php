<?php

namespace Database\Seeders;

use App\Enums\WebhookDeliveryStatus;
use App\Models\Organization;
use App\Models\Webhook;
use App\Models\WebhookDelivery;
use Illuminate\Database\Seeder;

class WebhookSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Get organizations
        $defaultOrg = Organization::where('slug', 'default')->first();
        $demoCorpOrg = Organization::where('slug', 'demo-corp')->first();

        if (! $defaultOrg || ! $demoCorpOrg) {
            $this->command->error('Organizations not found. Please run OrganizationSeeder first.');

            return;
        }

        $this->command->info('Creating webhooks and deliveries...');

        // ============================================
        // Default Organization Webhooks
        // ============================================

        // 1. Active webhook - General notifications
        $webhook1 = Webhook::create([
            'organization_id' => $defaultOrg->id,
            'name' => 'User Notifications Webhook',
            'url' => 'https://api.example.com/webhooks/users',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => [
                'user.created',
                'user.updated',
                'user.deleted',
                'user.verified',
            ],
            'is_active' => true,
            'description' => 'Receives notifications for all user-related events',
            'headers' => [
                'X-Custom-Header' => 'value',
                'Authorization' => 'Bearer token123',
            ],
            'timeout_seconds' => 30,
            'delivery_stats' => [
                'total_deliveries' => 156,
                'successful_deliveries' => 152,
                'failed_deliveries' => 4,
                'average_response_time_ms' => 245,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => now()->subHours(2),
        ]);

        // 2. Active webhook - Authentication events
        $webhook2 = Webhook::create([
            'organization_id' => $defaultOrg->id,
            'name' => 'Authentication Monitor',
            'url' => 'https://security.example.com/webhooks/auth',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => [
                'authentication.login',
                'authentication.logout',
                'authentication.failed',
                'authentication.lockout',
                'authentication.mfa_completed',
            ],
            'is_active' => true,
            'description' => 'Security monitoring for authentication events',
            'headers' => [
                'X-Security-Key' => 'secure_key_456',
            ],
            'timeout_seconds' => 15,
            'ip_whitelist' => ['192.168.1.100', '10.0.0.50'],
            'delivery_stats' => [
                'total_deliveries' => 892,
                'successful_deliveries' => 889,
                'failed_deliveries' => 3,
                'average_response_time_ms' => 128,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => now()->subMinutes(15),
        ]);

        // 3. Active webhook - All events
        $webhook3 = Webhook::create([
            'organization_id' => $defaultOrg->id,
            'name' => 'Audit Log Collector',
            'url' => 'https://logs.example.com/webhooks/audit',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => ['*'], // Subscribe to all events
            'is_active' => true,
            'description' => 'Collects all events for audit logging and compliance',
            'timeout_seconds' => 60,
            'delivery_stats' => [
                'total_deliveries' => 2453,
                'successful_deliveries' => 2448,
                'failed_deliveries' => 5,
                'average_response_time_ms' => 312,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => now()->subMinutes(5),
            'metadata' => [
                'compliance_category' => 'audit',
                'retention_days' => 365,
            ],
        ]);

        // 4. Webhook with some failures
        $webhook4 = Webhook::create([
            'organization_id' => $defaultOrg->id,
            'name' => 'Application Events',
            'url' => 'https://api.example.com/webhooks/applications',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => [
                'application.created',
                'application.updated',
                'application.deleted',
                'application.credentials_rotated',
            ],
            'is_active' => true,
            'description' => 'Monitors OAuth application lifecycle events',
            'timeout_seconds' => 30,
            'delivery_stats' => [
                'total_deliveries' => 45,
                'successful_deliveries' => 38,
                'failed_deliveries' => 7,
                'average_response_time_ms' => 423,
            ],
            'consecutive_failures' => 2,
            'failure_count' => 7,
            'last_delivered_at' => now()->subHours(1),
            'last_failed_at' => now()->subMinutes(30),
        ]);

        // 5. Inactive/disabled webhook
        $webhook5 = Webhook::create([
            'organization_id' => $defaultOrg->id,
            'name' => 'Legacy Integration (Disabled)',
            'url' => 'https://old-system.example.com/webhooks',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => ['user.created', 'user.updated'],
            'is_active' => false,
            'description' => 'Disabled legacy webhook - replaced by new system',
            'timeout_seconds' => 30,
            'delivery_stats' => [
                'total_deliveries' => 1234,
                'successful_deliveries' => 1200,
                'failed_deliveries' => 34,
                'average_response_time_ms' => 567,
            ],
            'consecutive_failures' => 10,
            'failure_count' => 34,
            'disabled_at' => now()->subDays(7),
            'last_delivered_at' => now()->subDays(10),
            'last_failed_at' => now()->subDays(7),
        ]);

        // ============================================
        // Demo Corp Organization Webhooks
        // ============================================

        // 6. Active webhook - Organization events
        $webhook6 = Webhook::create([
            'organization_id' => $demoCorpOrg->id,
            'name' => 'Organization Manager',
            'url' => 'https://api.democorp.example.com/webhooks/org',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => [
                'organization.created',
                'organization.updated',
                'organization.member_added',
                'organization.member_removed',
                'organization.settings_changed',
            ],
            'is_active' => true,
            'description' => 'Manages organization-level events and notifications',
            'headers' => [
                'X-Org-Token' => 'democorp_token_789',
            ],
            'timeout_seconds' => 45,
            'delivery_stats' => [
                'total_deliveries' => 67,
                'successful_deliveries' => 67,
                'failed_deliveries' => 0,
                'average_response_time_ms' => 189,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => now()->subHours(3),
        ]);

        // 7. Active webhook - MFA events
        $webhook7 = Webhook::create([
            'organization_id' => $demoCorpOrg->id,
            'name' => 'MFA Security Monitor',
            'url' => 'https://security.democorp.example.com/webhooks/mfa',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => [
                'mfa.enabled',
                'mfa.disabled',
                'mfa.verified',
                'authentication.mfa_challenged',
                'authentication.mfa_completed',
            ],
            'is_active' => true,
            'description' => 'Tracks MFA enrollment and verification events',
            'timeout_seconds' => 20,
            'delivery_stats' => [
                'total_deliveries' => 234,
                'successful_deliveries' => 232,
                'failed_deliveries' => 2,
                'average_response_time_ms' => 156,
            ],
            'consecutive_failures' => 0,
            'last_delivered_at' => now()->subMinutes(45),
        ]);

        // 8. Webhook with high failure rate
        $webhook8 = Webhook::create([
            'organization_id' => $demoCorpOrg->id,
            'name' => 'Unreliable Endpoint (Testing)',
            'url' => 'https://unstable.example.com/webhooks/test',
            'secret' => 'whsec_'.bin2hex(random_bytes(32)),
            'events' => ['user.created'],
            'is_active' => true,
            'description' => 'Test webhook with high failure rate',
            'timeout_seconds' => 10,
            'delivery_stats' => [
                'total_deliveries' => 50,
                'successful_deliveries' => 15,
                'failed_deliveries' => 35,
                'average_response_time_ms' => 8945,
            ],
            'consecutive_failures' => 8,
            'failure_count' => 35,
            'last_delivered_at' => now()->subHours(4),
            'last_failed_at' => now()->subMinutes(10),
        ]);

        $this->command->info('Created 8 webhooks (5 for Default Org, 3 for Demo Corp)');

        // ============================================
        // Create Webhook Deliveries
        // ============================================

        $this->createDeliveriesForWebhook($webhook1, 15); // User notifications
        $this->createDeliveriesForWebhook($webhook2, 25); // Auth monitor
        $this->createDeliveriesForWebhook($webhook3, 30); // Audit log
        $this->createDeliveriesForWebhook($webhook4, 10); // App events (with failures)
        $this->createDeliveriesForWebhook($webhook6, 12); // Org manager
        $this->createDeliveriesForWebhook($webhook7, 18); // MFA monitor
        $this->createDeliveriesForWebhook($webhook8, 20); // Unreliable (many failures)

        $this->command->info('Created webhook deliveries for active webhooks');
        $this->command->info('✓ Webhook seeding completed successfully!');
    }

    /**
     * Create realistic webhook deliveries for a webhook
     */
    private function createDeliveriesForWebhook(Webhook $webhook, int $count): void
    {
        $events = is_array($webhook->events) ? $webhook->events : ['user.created'];

        // Determine failure rate based on webhook stats
        $totalDeliveries = $webhook->delivery_stats['total_deliveries'] ?? 0;
        $failedDeliveries = $webhook->delivery_stats['failed_deliveries'] ?? 0;
        $failureRate = $totalDeliveries > 0 ? ($failedDeliveries / $totalDeliveries) : 0;

        for ($i = 0; $i < $count; $i++) {
            $eventType = $events[0] === '*' ? 'user.created' : $events[array_rand($events)];
            $shouldFail = (mt_rand() / mt_getrandmax()) < $failureRate;

            $baseTime = now()->subDays(rand(0, 7))->subHours(rand(0, 23));

            if ($shouldFail) {
                // Create failed delivery
                WebhookDelivery::create([
                    'webhook_id' => $webhook->id,
                    'event_type' => $eventType,
                    'payload' => [
                        'event' => $eventType,
                        'data' => $this->generatePayloadData($eventType),
                        'timestamp' => $baseTime->toIso8601String(),
                        'webhook_id' => $webhook->id,
                    ],
                    'status' => WebhookDeliveryStatus::FAILED,
                    'http_status_code' => $this->getRandomFailureStatusCode(),
                    'response_body' => json_encode([
                        'error' => 'Connection timeout',
                        'message' => 'Failed to connect to webhook endpoint',
                    ]),
                    'error_message' => 'Connection timeout after '.$webhook->timeout_seconds.' seconds',
                    'attempt_number' => rand(1, 6),
                    'max_attempts' => 6,
                    'request_duration_ms' => $webhook->timeout_seconds * 1000,
                    'signature' => hash_hmac('sha256', json_encode(['event' => $eventType]), $webhook->secret),
                    'next_retry_at' => $baseTime->addMinutes(5),
                    'sent_at' => $baseTime,
                    'completed_at' => $baseTime->addSeconds($webhook->timeout_seconds),
                ]);
            } else {
                // Create successful delivery
                $responseTime = rand(50, 800);

                WebhookDelivery::create([
                    'webhook_id' => $webhook->id,
                    'event_type' => $eventType,
                    'payload' => [
                        'event' => $eventType,
                        'data' => $this->generatePayloadData($eventType),
                        'timestamp' => $baseTime->toIso8601String(),
                        'webhook_id' => $webhook->id,
                    ],
                    'status' => WebhookDeliveryStatus::SUCCESS,
                    'http_status_code' => 200,
                    'response_body' => json_encode([
                        'status' => 'received',
                        'message' => 'Webhook processed successfully',
                        'id' => 'evt_'.bin2hex(random_bytes(12)),
                    ]),
                    'error_message' => null,
                    'attempt_number' => 1,
                    'max_attempts' => 6,
                    'request_duration_ms' => $responseTime,
                    'signature' => hash_hmac('sha256', json_encode(['event' => $eventType]), $webhook->secret),
                    'next_retry_at' => null,
                    'sent_at' => $baseTime,
                    'completed_at' => $baseTime->addMilliseconds($responseTime),
                ]);
            }

            // Occasionally create a retrying delivery
            if ($i % 8 === 0 && $failureRate > 0) {
                WebhookDelivery::create([
                    'webhook_id' => $webhook->id,
                    'event_type' => $eventType,
                    'payload' => [
                        'event' => $eventType,
                        'data' => $this->generatePayloadData($eventType),
                        'timestamp' => now()->subMinutes(rand(5, 30))->toIso8601String(),
                        'webhook_id' => $webhook->id,
                    ],
                    'status' => WebhookDeliveryStatus::RETRYING,
                    'http_status_code' => 503,
                    'response_body' => json_encode(['error' => 'Service temporarily unavailable']),
                    'error_message' => 'HTTP 503: Service Unavailable',
                    'attempt_number' => rand(2, 4),
                    'max_attempts' => 6,
                    'request_duration_ms' => rand(5000, 15000),
                    'signature' => hash_hmac('sha256', json_encode(['event' => $eventType]), $webhook->secret),
                    'next_retry_at' => now()->addMinutes(rand(1, 10)),
                    'sent_at' => now()->subMinutes(rand(5, 30)),
                    'completed_at' => null,
                ]);
            }

            // Occasionally create a pending delivery
            if ($i % 10 === 0) {
                WebhookDelivery::create([
                    'webhook_id' => $webhook->id,
                    'event_type' => $eventType,
                    'payload' => [
                        'event' => $eventType,
                        'data' => $this->generatePayloadData($eventType),
                        'timestamp' => now()->toIso8601String(),
                        'webhook_id' => $webhook->id,
                    ],
                    'status' => WebhookDeliveryStatus::PENDING,
                    'http_status_code' => null,
                    'response_body' => null,
                    'error_message' => null,
                    'attempt_number' => 0,
                    'max_attempts' => 6,
                    'request_duration_ms' => null,
                    'signature' => hash_hmac('sha256', json_encode(['event' => $eventType]), $webhook->secret),
                    'next_retry_at' => now()->addSeconds(rand(5, 60)),
                    'sent_at' => null,
                    'completed_at' => null,
                ]);
            }
        }
    }

    /**
     * Generate realistic payload data based on event type
     */
    private function generatePayloadData(string $eventType): array
    {
        $faker = \Faker\Factory::create();

        return match (true) {
            str_starts_with($eventType, 'user.') => [
                'id' => $faker->randomNumber(6),
                'name' => $faker->name(),
                'email' => $faker->email(),
                'created_at' => $faker->dateTimeBetween('-1 year')->format('Y-m-d H:i:s'),
                'updated_at' => $faker->dateTimeBetween('-1 month')->format('Y-m-d H:i:s'),
            ],
            str_starts_with($eventType, 'authentication.') => [
                'user_id' => $faker->randomNumber(6),
                'ip_address' => $faker->ipv4(),
                'user_agent' => $faker->userAgent(),
                'timestamp' => $faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
                'location' => [
                    'country' => $faker->country(),
                    'city' => $faker->city(),
                ],
            ],
            str_starts_with($eventType, 'application.') => [
                'id' => $faker->randomNumber(6),
                'name' => $faker->company().' App',
                'client_id' => 'app_'.bin2hex(random_bytes(12)),
                'redirect_uris' => [$faker->url()],
                'updated_at' => $faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
            ],
            str_starts_with($eventType, 'organization.') => [
                'id' => $faker->randomNumber(6),
                'name' => $faker->company(),
                'slug' => $faker->slug(),
                'member_count' => $faker->numberBetween(5, 100),
                'updated_at' => $faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
            ],
            str_starts_with($eventType, 'mfa.') => [
                'user_id' => $faker->randomNumber(6),
                'method' => $faker->randomElement(['totp', 'sms', 'email']),
                'enabled' => $faker->boolean(80),
                'timestamp' => $faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
            ],
            default => [
                'id' => $faker->randomNumber(6),
                'type' => $eventType,
                'timestamp' => $faker->dateTimeThisMonth()->format('Y-m-d H:i:s'),
            ],
        };
    }

    /**
     * Get random HTTP status code for failures
     */
    private function getRandomFailureStatusCode(): int
    {
        $codes = [
            400, // Bad Request
            401, // Unauthorized
            403, // Forbidden
            404, // Not Found
            408, // Request Timeout
            429, // Too Many Requests
            500, // Internal Server Error
            502, // Bad Gateway
            503, // Service Unavailable
            504, // Gateway Timeout
        ];

        return $codes[array_rand($codes)];
    }
}
