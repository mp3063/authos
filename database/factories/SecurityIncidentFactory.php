<?php

namespace Database\Factories;

use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\SecurityIncident>
 */
class SecurityIncidentFactory extends Factory
{
    protected $model = SecurityIncident::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $type = fake()->randomElement([
            'brute_force',
            'sql_injection',
            'xss_attempt',
            'credential_stuffing',
            'suspicious_activity',
        ]);

        $severity = fake()->randomElement(['low', 'medium', 'high', 'critical']);

        return [
            'type' => $type,
            'severity' => $severity,
            'ip_address' => fake()->ipv4(),
            'user_agent' => fake()->userAgent(),
            'user_id' => null,
            'endpoint' => fake()->randomElement([
                '/api/v1/auth/login',
                '/api/v1/auth/register',
                '/api/v1/users',
                '/admin/login',
            ]),
            'description' => $this->getDescriptionForType($type),
            'metadata' => [
                'attempts' => fake()->numberBetween(1, 100),
                'timeframe' => fake()->randomElement(['1 minute', '5 minutes', '1 hour']),
            ],
            'status' => 'open',
            'detected_at' => fake()->dateTimeBetween('-7 days', 'now'),
            'resolved_at' => null,
            'resolution_notes' => null,
            'action_taken' => null,
        ];
    }

    /**
     * Get a realistic description for the incident type.
     */
    protected function getDescriptionForType(string $type): string
    {
        $descriptions = [
            'brute_force' => 'Multiple failed login attempts detected from the same IP address',
            'sql_injection' => 'SQL injection pattern detected in request parameters',
            'xss_attempt' => 'Cross-site scripting attempt detected in user input',
            'credential_stuffing' => 'Credential stuffing attack detected',
            'suspicious_activity' => 'Suspicious activity pattern detected',
        ];

        return $descriptions[$type] ?? 'Security incident detected';
    }

    /**
     * Indicate that the incident is a brute force attack.
     */
    public function bruteForce(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => 'brute_force',
            'severity' => 'high',
            'description' => 'Multiple failed login attempts detected from the same IP address',
            'action_taken' => 'blocked_ip',
        ]);
    }

    /**
     * Indicate that the incident is a SQL injection attempt.
     */
    public function sqlInjection(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => 'sql_injection',
            'severity' => 'critical',
            'description' => 'SQL injection pattern detected in request parameters',
            'action_taken' => 'blocked_ip',
        ]);
    }

    /**
     * Indicate that the incident is an XSS attempt.
     */
    public function xssAttempt(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => 'xss_attempt',
            'severity' => 'high',
            'description' => 'Cross-site scripting attempt detected in user input',
        ]);
    }

    /**
     * Indicate that the incident is credential stuffing.
     */
    public function credentialStuffing(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => 'credential_stuffing',
            'severity' => 'critical',
            'description' => 'Credential stuffing attack detected',
            'action_taken' => 'blocked_ip',
        ]);
    }

    /**
     * Indicate that the incident has a specific severity.
     */
    public function severity(string $severity): static
    {
        return $this->state(fn (array $attributes) => [
            'severity' => $severity,
        ]);
    }

    /**
     * Indicate that the incident is open.
     */
    public function open(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'open',
            'resolved_at' => null,
            'resolution_notes' => null,
        ]);
    }

    /**
     * Indicate that the incident is resolved.
     */
    public function resolved(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'resolved',
            'resolved_at' => now(),
            'resolution_notes' => 'Incident investigated and resolved',
        ]);
    }

    /**
     * Indicate that the incident is being investigated.
     */
    public function investigating(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'investigating',
        ]);
    }

    /**
     * Indicate that the incident was a false positive.
     */
    public function falsePositive(): static
    {
        return $this->state(fn (array $attributes) => [
            'status' => 'false_positive',
            'resolved_at' => now(),
            'resolution_notes' => 'Determined to be a false positive',
        ]);
    }

    /**
     * Indicate that the incident is for a specific user.
     */
    public function forUser(User $user): static
    {
        return $this->state(fn (array $attributes) => [
            'user_id' => $user->id,
        ]);
    }

    /**
     * Indicate that the incident is for a specific IP address.
     */
    public function forIp(string $ip): static
    {
        return $this->state(fn (array $attributes) => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Indicate that action was taken.
     */
    public function withAction(string $action): static
    {
        return $this->state(fn (array $attributes) => [
            'action_taken' => $action,
        ]);
    }
}
