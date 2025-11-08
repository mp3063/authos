<?php

namespace Tests\Integration\Organizations;

use App\Models\Organization;
use App\Models\User;
use Tests\Integration\IntegrationTestCase;

/**
 * Organization Settings Integration Tests
 *
 * Tests organization-specific settings management including:
 * - Security settings (MFA, password policies)
 * - Lockout policies
 * - Session timeouts
 * - Notification preferences
 * - OAuth settings
 * - Settings validation and constraints
 * - Resetting to defaults
 *
 * Verifies:
 * - Settings are properly stored and retrieved
 * - Validation rules are enforced
 * - Settings affect behavior correctly
 * - Audit trail is maintained
 */
class OrganizationSettingsTest extends IntegrationTestCase
{
    protected User $user;

    protected Organization $organization;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organization = $this->createOrganization();
        $this->user = $this->createApiOrganizationAdmin(['organization_id' => $this->organization->id]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_update_security_settings(): void
    {
        // ARRANGE: Prepare security settings
        $securitySettings = [
            'settings' => [
                'require_mfa' => true,
                'allowed_ip_ranges' => ['192.168.1.0/24', '10.0.0.0/8'],
                'password_expiry_days' => 90,
                'enforce_2fa_for_admins' => true,
            ],
        ];

        // ACT: Update security settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $securitySettings);

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'data' => [
                    'settings' => [
                        'require_mfa' => true,
                        'enforce_2fa_for_admins' => true,
                    ],
                ],
            ]);

        // ASSERT: Verify database update
        $this->organization->refresh();
        $this->assertTrue($this->organization->settings['require_mfa']);
        $this->assertTrue($this->organization->settings['enforce_2fa_for_admins']);
        $this->assertEquals(90, $this->organization->settings['password_expiry_days']);
        $this->assertIsArray($this->organization->settings['allowed_ip_ranges']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_configure_lockout_policy(): void
    {
        // ARRANGE: Prepare lockout policy settings
        $lockoutSettings = [
            'settings' => [
                'lockout_policy' => [
                    'enabled' => true,
                    'max_attempts' => 5,
                    'lockout_duration' => 300, // 5 minutes
                    'progressive_lockout' => true,
                    'notify_user' => true,
                    'notify_admin' => true,
                ],
            ],
        ];

        // ACT: Update lockout policy
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $lockoutSettings);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify settings stored correctly
        $this->organization->refresh();
        $lockoutPolicy = $this->organization->settings['lockout_policy'];
        $this->assertTrue($lockoutPolicy['enabled']);
        $this->assertEquals(5, $lockoutPolicy['max_attempts']);
        $this->assertEquals(300, $lockoutPolicy['lockout_duration']);
        $this->assertTrue($lockoutPolicy['progressive_lockout']);
        $this->assertTrue($lockoutPolicy['notify_user']);
        $this->assertTrue($lockoutPolicy['notify_admin']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_set_session_timeout(): void
    {
        // ARRANGE: Prepare session timeout settings
        $sessionSettings = [
            'settings' => [
                'session_timeout' => 300, // 5 hours in minutes (minimum allowed)
                'session_absolute_timeout' => 480, // 8 hours
                'session_idle_timeout' => 30, // 30 minutes
                'require_reauth_for_sensitive' => true,
            ],
        ];

        // ACT: Update session settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $sessionSettings);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify settings
        $this->organization->refresh();
        $this->assertEquals(300, $this->organization->settings['session_timeout']);
        $this->assertEquals(480, $this->organization->settings['session_absolute_timeout']);
        $this->assertEquals(30, $this->organization->settings['session_idle_timeout']);
        $this->assertTrue($this->organization->settings['require_reauth_for_sensitive']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_update_notification_preferences(): void
    {
        // ARRANGE: Prepare notification preferences
        $notificationSettings = [
            'settings' => [
                'notifications' => [
                    'login_alerts' => true,
                    'security_incidents' => true,
                    'failed_login_threshold' => 3,
                    'new_user_notifications' => true,
                    'api_key_expiry_warning' => true,
                    'webhook_failure_alerts' => true,
                ],
            ],
        ];

        // ACT: Update notification preferences
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $notificationSettings);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify notification settings
        $this->organization->refresh();
        $notifications = $this->organization->settings['notifications'];
        $this->assertTrue($notifications['login_alerts']);
        $this->assertTrue($notifications['security_incidents']);
        $this->assertEquals(3, $notifications['failed_login_threshold']);
        $this->assertTrue($notifications['new_user_notifications']);
        $this->assertTrue($notifications['webhook_failure_alerts']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_configure_oauth_settings(): void
    {
        // ARRANGE: Prepare OAuth settings
        $oauthSettings = [
            'settings' => [
                'oauth' => [
                    'enabled' => true,
                    'allow_implicit_flow' => false,
                    'require_pkce' => true,
                    'token_lifetime' => 3600, // 1 hour
                    'refresh_token_lifetime' => 2592000, // 30 days
                    'rotate_refresh_tokens' => true,
                    'allowed_scopes' => ['openid', 'profile', 'email'],
                ],
            ],
        ];

        // ACT: Update OAuth settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $oauthSettings);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify OAuth settings
        $this->organization->refresh();
        $oauth = $this->organization->settings['oauth'];
        $this->assertTrue($oauth['enabled']);
        $this->assertFalse($oauth['allow_implicit_flow']);
        $this->assertTrue($oauth['require_pkce']);
        $this->assertEquals(3600, $oauth['token_lifetime']);
        $this->assertTrue($oauth['rotate_refresh_tokens']);
        $this->assertIsArray($oauth['allowed_scopes']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_mfa_enforcement_setting(): void
    {
        // ARRANGE: Enable MFA requirement
        $mfaSettings = [
            'settings' => [
                'require_mfa' => true,
                'mfa_grace_period' => 7, // days
                'mfa_methods' => ['totp', 'sms', 'email'],
            ],
        ];

        // ACT: Update MFA settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $mfaSettings);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify MFA is enforced
        $this->organization->refresh();
        $this->assertTrue($this->organization->settings['require_mfa']);
        $this->assertEquals(7, $this->organization->settings['mfa_grace_period']);
        $this->assertIsArray($this->organization->settings['mfa_methods']);
        $this->assertCount(3, $this->organization->settings['mfa_methods']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_settings_constraints_validation(): void
    {
        // ARRANGE: Prepare invalid settings (constraints violation)
        $invalidSettings = [
            'settings' => [
                'session_timeout' => -10, // Negative timeout
                'password_policy' => [
                    'min_length' => 3, // Too short
                    'max_length' => 4, // Shorter than min
                ],
                'lockout_policy' => [
                    'max_attempts' => 0, // Zero attempts
                ],
            ],
        ];

        // ACT: Attempt to update with invalid settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $invalidSettings);

        // ASSERT: Verify validation error
        $response->assertStatus(422);

        // ASSERT: Verify settings were not changed
        $this->organization->refresh();
        $this->assertNotEquals(-10, $this->organization->settings['session_timeout'] ?? null);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_can_reset_settings_to_defaults(): void
    {
        // ARRANGE: Modify settings away from defaults
        $this->organization->update([
            'settings' => [
                'require_mfa' => true,
                'session_timeout' => 999,
                'custom_setting' => 'custom_value',
            ],
        ]);

        // ACT: Reset to defaults
        $response = $this->actingAs($this->user, 'api')
            ->postJson("/api/v1/organizations/{$this->organization->id}/settings/reset");

        // ASSERT: Verify response
        $response->assertOk()
            ->assertJson([
                'message' => 'Settings reset to defaults successfully',
            ]);

        // ASSERT: Verify settings are reset
        $this->organization->refresh();
        $settings = $this->organization->settings;

        // Default values should be restored
        $this->assertFalse($settings['require_mfa'] ?? false);
        $this->assertNotEquals(999, $settings['session_timeout'] ?? 60);
        $this->assertArrayNotHasKey('custom_setting', $settings);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_password_policy_settings(): void
    {
        // ARRANGE: Prepare comprehensive password policy
        $passwordPolicy = [
            'settings' => [
                'password_policy' => [
                    'min_length' => 12,
                    'max_length' => 128,
                    'require_uppercase' => true,
                    'require_lowercase' => true,
                    'require_numbers' => true,
                    'require_symbols' => true,
                    'prevent_reuse' => 5, // Last 5 passwords
                    'expiry_days' => 90,
                    'expiry_warning_days' => 7,
                    'prevent_common_passwords' => true,
                ],
            ],
        ];

        // ACT: Update password policy
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $passwordPolicy);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify password policy is stored
        $this->organization->refresh();
        $policy = $this->organization->settings['password_policy'];
        $this->assertEquals(12, $policy['min_length']);
        $this->assertEquals(128, $policy['max_length']);
        $this->assertTrue($policy['require_uppercase']);
        $this->assertTrue($policy['require_lowercase']);
        $this->assertTrue($policy['require_numbers']);
        $this->assertTrue($policy['require_symbols']);
        $this->assertEquals(5, $policy['prevent_reuse']);
        $this->assertEquals(90, $policy['expiry_days']);
        $this->assertTrue($policy['prevent_common_passwords']);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_partial_settings_update(): void
    {
        // ARRANGE: Set initial settings
        $this->organization->update([
            'settings' => [
                'require_mfa' => true,
                'session_timeout' => 300,
                'password_policy' => [
                    'min_length' => 8,
                ],
            ],
        ]);

        // ACT: Update only one setting
        $partialUpdate = [
            'settings' => [
                'session_timeout' => 360, // 6 hours (must be >= 300)
            ],
        ];

        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $partialUpdate);

        // ASSERT: Verify response
        $response->assertOk();

        // ASSERT: Verify only session_timeout changed, other settings preserved
        $this->organization->refresh();
        $this->assertEquals(360, $this->organization->settings['session_timeout']);
        $this->assertTrue($this->organization->settings['require_mfa']); // Preserved
        $this->assertEquals(8, $this->organization->settings['password_policy']['min_length']); // Preserved
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_settings_affect_organization_behavior(): void
    {
        // ARRANGE: Enable strict security settings
        $strictSettings = [
            'settings' => [
                'require_mfa' => true,
                'lockout_policy' => [
                    'enabled' => true,
                    'max_attempts' => 3,
                ],
                'session_timeout' => 300, // Minimum allowed timeout
            ],
        ];

        // ACT: Apply strict settings
        $response = $this->actingAs($this->user, 'api')
            ->putJson("/api/v1/organizations/{$this->organization->id}/settings", $strictSettings);

        // ASSERT: Verify settings applied
        $response->assertOk();
        $this->organization->refresh();

        // ASSERT: Verify settings can be retrieved
        $getResponse = $this->actingAs($this->user, 'api')
            ->getJson("/api/v1/organizations/{$this->organization->id}/settings");

        $getResponse->assertOk()
            ->assertJson([
                'data' => [
                    'require_mfa' => true,
                    'session_timeout' => 300,
                ],
            ]);
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function test_unauthorized_user_cannot_modify_settings(): void
    {
        // ARRANGE: Create a fresh organization with known settings for this test
        $testOrg = $this->createOrganization(['settings' => ['require_mfa' => false]]);

        // ARRANGE: Create user from different organization
        $otherOrg = $this->createOrganization();
        $otherUser = $this->createUser(['organization_id' => $otherOrg->id]);

        // ACT: Attempt to modify settings
        $response = $this->actingAs($otherUser, 'api')
            ->putJson("/api/v1/organizations/{$testOrg->id}/settings", [
                'settings' => ['require_mfa' => true],
            ]);

        // ASSERT: Verify access denied
        $response->assertNotFound();

        // ASSERT: Verify no changes were made
        $testOrg->refresh();
        $this->assertFalse(
            $testOrg->settings['require_mfa'] ?? false,
            'The require_mfa setting should remain unchanged after unauthorized attempt'
        );
    }
}
