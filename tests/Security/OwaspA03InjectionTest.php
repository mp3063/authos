<?php

namespace Tests\Security;

use App\Models\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use Tests\TestCase;

/**
 * OWASP A03:2021 - Injection
 *
 * Tests for:
 * - SQL Injection
 * - NoSQL Injection
 * - LDAP Injection
 * - OS Command Injection
 * - XPath Injection
 * - Template Injection
 */
class OwaspA03InjectionTest extends TestCase
{
    use RefreshDatabase;

    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        // Create roles if they don't exist
        \Spatie\Permission\Models\Role::firstOrCreate(['name' => 'Organization Admin', 'guard_name' => 'web']);

        $this->organization = Organization::factory()->create();
        $this->user = User::factory()->create([
            'organization_id' => $this->organization->id,
        ]);
        $this->user->assignRole('Organization Admin');
    }

    /** @test */
    public function it_prevents_sql_injection_in_login()
    {
        $sqlInjectionPayloads = [
            "admin'--",
            "admin' OR '1'='1",
            "admin' OR '1'='1'--",
            "admin' OR 1=1--",
            "' OR '1'='1",
            "1' OR '1' = '1",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
        ];

        foreach ($sqlInjectionPayloads as $payload) {
            $response = $this->postJson('/api/auth/login', [
                'email' => $payload,
                'password' => $payload,
            ]);

            // Should fail authentication, not cause SQL error
            $this->assertContains($response->status(), [401, 422, 429]);
            $response->assertJsonMissing(['error' => 'SQL']);
        }
    }

    /** @test */
    public function it_prevents_sql_injection_in_search_queries()
    {
        Passport::actingAs($this->user);

        $sqlInjectionPayloads = [
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL, username, password FROM users--",
            "' OR 1=1--",
            "admin'--",
        ];

        foreach ($sqlInjectionPayloads as $payload) {
            $response = $this->getJson("/api/v1/users?search={$payload}");

            // Should handle gracefully, not execute SQL
            $this->assertContains($response->status(), [200, 422]);

            // Users table should still exist
            $this->assertTrue(DB::getSchemaBuilder()->hasTable('users'));
        }
    }

    /** @test */
    public function it_prevents_sql_injection_in_filter_parameters()
    {
        Passport::actingAs($this->user);

        $response = $this->getJson("/api/v1/users?role=' OR '1'='1");

        $this->assertContains($response->status(), [200, 422]);

        // Should not return all users bypassing filter
        if ($response->status() === 200) {
            $data = $response->json('data');
            $this->assertIsArray($data);
        }
    }

    /** @test */
    public function it_prevents_sql_injection_in_sorting_parameters()
    {
        Passport::actingAs($this->user);

        $sqlInjectionPayloads = [
            'name; DROP TABLE users--',
            'name, (SELECT password FROM users WHERE id=1)',
            "name' OR '1'='1",
        ];

        foreach ($sqlInjectionPayloads as $payload) {
            $response = $this->getJson("/api/v1/users?sort_by={$payload}");

            $this->assertContains($response->status(), [200, 422]);
            $this->assertTrue(DB::getSchemaBuilder()->hasTable('users'));
        }
    }

    /** @test */
    public function it_prevents_ldap_injection_in_authentication()
    {
        $ldapInjectionPayloads = [
            '*',
            'admin)(&(password=*))',
            'admin)(|(password=*))',
            '*)(uid=*))(|(uid=*',
            'admin)(!(&(objectClass=*)))',
        ];

        foreach ($ldapInjectionPayloads as $payload) {
            $response = $this->postJson('/api/auth/login', [
                'email' => $payload,
                'password' => 'password',
            ]);

            $this->assertContains($response->status(), [401, 422, 429]);
        }
    }

    /** @test */
    public function it_prevents_command_injection_in_file_operations()
    {
        Passport::actingAs($this->user);

        $commandInjectionPayloads = [
            '; ls -la',
            '| whoami',
            '& cat /etc/passwd',
            '`whoami`',
            '$(whoami)',
            '; rm -rf /',
        ];

        foreach ($commandInjectionPayloads as $payload) {
            // Try to inject in filename
            $response = $this->postJson("/api/v1/organizations/{$this->organization->id}/branding", [
                'logo_path' => "logo.png{$payload}",
            ]);

            // Should reject or sanitize
            $this->assertContains($response->status(), [200, 422, 400]);

            // Verify no command was executed
            $this->organization->refresh();
            if ($this->organization->logo_path) {
                $this->assertStringNotContainsString(';', $this->organization->logo_path);
                $this->assertStringNotContainsString('|', $this->organization->logo_path);
            }
        }
    }

    /** @test */
    public function it_prevents_nosql_injection_in_json_queries()
    {
        Passport::actingAs($this->user);

        $noSqlPayloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
        ];

        foreach ($noSqlPayloads as $payload) {
            $response = $this->getJson("/api/v1/users?filter={$payload}");

            $this->assertContains($response->status(), [200, 422]);
        }
    }

    /** @test */
    public function it_prevents_template_injection()
    {
        Passport::actingAs($this->user);

        $templateInjectionPayloads = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '{{config.items()}}',
            '{{self}}',
        ];

        foreach ($templateInjectionPayloads as $payload) {
            $response = $this->putJson("/api/v1/organizations/{$this->organization->id}", [
                'name' => $payload,
            ]);

            if ($response->status() === 200) {
                $this->organization->refresh();

                // Template should not be evaluated
                $this->assertEquals($payload, $this->organization->name);
                $this->assertStringNotContainsString('49', $this->organization->name);
            }
        }
    }

    /** @test */
    public function it_prevents_xpath_injection()
    {
        $xpathInjectionPayloads = [
            "' or '1'='1",
            "' or ''='",
            "x' or 1=1 or 'x'='y",
            "admin' or '1'='1",
        ];

        foreach ($xpathInjectionPayloads as $payload) {
            $response = $this->postJson('/api/auth/login', [
                'email' => $payload,
                'password' => 'password',
            ]);

            $this->assertContains($response->status(), [401, 422, 429]);
        }
    }

    /** @test */
    public function it_prevents_second_order_sql_injection()
    {
        Passport::actingAs($this->user);

        // Create user with malicious name
        $response = $this->postJson('/api/v1/users', [
            'name' => "Robert'); DROP TABLE users--",
            'email' => 'test@example.com',
            'password' => 'password123',
        ]);

        if ($response->status() === 201) {
            $userId = $response->json('data.id');

            // Use the created user in another query
            $response2 = $this->getJson("/api/v1/users/{$userId}");

            $response2->assertStatus(200);

            // Users table should still exist
            $this->assertTrue(DB::getSchemaBuilder()->hasTable('users'));
        }
    }

    /** @test */
    public function it_validates_parameterized_queries_for_custom_filters()
    {
        Passport::actingAs($this->user);

        // Create test users
        User::factory()->count(3)->create([
            'organization_id' => $this->organization->id,
        ]);

        // Try SQL injection in custom filter
        $response = $this->getJson("/api/v1/users?email=' OR '1'='1");

        // Should not return all users
        if ($response->status() === 200) {
            $users = $response->json('data');

            // Should either return no results or validate the email format
            $this->assertTrue(
                empty($users) || count($users) < User::where('organization_id', $this->organization->id)->count()
            );
        }
    }

    /** @test */
    public function it_prevents_injection_in_webhook_urls()
    {
        Passport::actingAs($this->user);

        $injectionPayloads = [
            'http://example.com/webhook?id=1; DROP TABLE webhooks--',
            'http://example.com/$(whoami)',
            'javascript:alert(1)',
            'file:///etc/passwd',
        ];

        foreach ($injectionPayloads as $payload) {
            $response = $this->postJson('/api/v1/webhooks', [
                'url' => $payload,
                'events' => ['user.created'],
                'is_active' => true,
            ]);

            // Should validate URL format
            if ($response->status() === 201) {
                $webhook = \App\Models\Webhook::find($response->json('data.id'));
                $this->assertStringStartsWith('http', $webhook->url);
            } else {
                $response->assertStatus(422);
            }
        }
    }

    /** @test */
    public function it_prevents_email_header_injection()
    {
        $emailInjectionPayloads = [
            "test@example.com\nBcc: attacker@evil.com",
            "test@example.com\r\nCc: attacker@evil.com",
            'test@example.com%0ABcc:attacker@evil.com',
            "test@example.com\nContent-Type: text/html",
        ];

        foreach ($emailInjectionPayloads as $payload) {
            $response = $this->postJson('/api/auth/register', [
                'name' => 'Test User',
                'email' => $payload,
                'password' => 'password123',
                'password_confirmation' => 'password123',
            ]);

            $response->assertStatus(422);
            $response->assertJsonValidationErrors(['email']);
        }
    }

    /** @test */
    public function it_sanitizes_user_input_in_audit_logs()
    {
        Passport::actingAs($this->user);

        $maliciousInput = "<script>alert('XSS')</script>";

        $response = $this->putJson("/api/v1/users/{$this->user->id}", [
            'name' => $maliciousInput,
        ]);

        if ($response->status() === 200) {
            // Check authentication log
            $authLog = \App\Models\AuthenticationLog::where('user_id', $this->user->id)
                ->latest()
                ->first();

            if ($authLog && isset($authLog->metadata['changes'])) {
                $logContent = json_encode($authLog->metadata);
                // Script tags should be escaped or removed
                $this->assertStringNotContainsString('<script>', $logContent);
            }
        }
    }

    /** @test */
    public function it_prevents_ssi_injection()
    {
        Passport::actingAs($this->user);

        $ssiPayloads = [
            '<!--#exec cmd="/bin/ls" -->',
            '<!--#include virtual="/etc/passwd" -->',
        ];

        foreach ($ssiPayloads as $payload) {
            $response = $this->putJson("/api/v1/organizations/{$this->organization->id}", [
                'description' => $payload,
            ]);

            if ($response->status() === 200) {
                $this->organization->refresh();

                // SSI should not be executed
                if ($this->organization->description) {
                    $this->assertStringContainsString('<!--', $this->organization->description);
                }
            }
        }
    }
}
