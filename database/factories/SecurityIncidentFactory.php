<?php

namespace Database\Factories;

use App\Models\Organization;
use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<SecurityIncident>
 */
class SecurityIncidentFactory extends Factory
{
    protected $model = SecurityIncident::class;

    private const DESCRIPTIONS = [
        'brute_force' => 'Multiple failed login attempts detected from the same IP address',
        'sql_injection' => 'SQL injection pattern detected in request parameters',
        'xss_attempt' => 'Cross-site scripting attempt detected in user input',
        'credential_stuffing' => 'Credential stuffing attack detected',
        'suspicious_activity' => 'Suspicious activity pattern detected',
    ];

    private const ATTACK_PROFILES = [
        'brute_force' => ['severity' => 'high', 'action_taken' => 'blocked_ip'],
        'sql_injection' => ['severity' => 'critical', 'action_taken' => 'blocked_ip'],
        'xss_attempt' => ['severity' => 'high'],
        'credential_stuffing' => ['severity' => 'critical', 'action_taken' => 'blocked_ip'],
    ];

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
            'organization_id' => null,
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
        return self::DESCRIPTIONS[$type] ?? 'Security incident detected';
    }

    /**
     * Indicate that the incident is a specific attack type (brute_force, sql_injection, xss_attempt, credential_stuffing).
     */
    public function ofType(string $type): static
    {
        return $this->state(fn () => [
            'type' => $type,
            'description' => $this->getDescriptionForType($type),
            ...self::ATTACK_PROFILES[$type],
        ]);
    }

    /**
     * Indicate that the incident has a specific severity.
     */
    public function severity(string $severity): static
    {
        return $this->state(fn () => [
            'severity' => $severity,
        ]);
    }

    /**
     * Indicate that the incident is open.
     */
    public function open(): static
    {
        return $this->state(fn () => [
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
        return $this->state(fn () => [
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
        return $this->state(fn () => [
            'status' => 'investigating',
        ]);
    }

    /**
     * Indicate that the incident was a false positive.
     */
    public function falsePositive(): static
    {
        return $this->state(fn () => [
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
        return $this->state(fn () => [
            'user_id' => $user->id,
            'organization_id' => $user->organization_id,
        ]);
    }

    /**
     * Indicate that the incident is for a specific organization.
     */
    public function forOrganization(Organization $organization): static
    {
        return $this->state(fn () => [
            'organization_id' => $organization->id,
        ]);
    }

    /**
     * Indicate that the incident is for a specific IP address.
     */
    public function forIp(string $ip): static
    {
        return $this->state(fn () => [
            'ip_address' => $ip,
        ]);
    }

    /**
     * Indicate that action was taken.
     */
    public function withAction(string $action): static
    {
        return $this->state(fn () => [
            'action_taken' => $action,
        ]);
    }
}
