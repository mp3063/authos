# Authentication Integration Tests

## Purpose
Test complete authentication flows including registration, login, MFA, password reset, social login, and logout.

## What Belongs Here
- Registration flow tests
- Login flow tests (with/without MFA)
- Password reset flow tests
- Social authentication flow tests (5 providers)
- Logout flow tests
- Session management tests

## Test Naming Convention
```php
public function test_user_can_register_with_valid_credentials()
public function test_login_requires_mfa_when_enabled()
public function test_password_reset_flow_completes_successfully()
public function test_social_login_creates_new_user_account()
```

## Required Annotations
```php
/**
 * @test
 * @group integration
 * @group auth
 */
```

## Example Test Structure
```php
public function test_complete_registration_flow()
{
    // ARRANGE
    $userData = [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => 'SecurePassword123!',
    ];

    // ACT: Submit registration
    $response = $this->postJson('/api/v1/auth/register', $userData);

    // ASSERT: Registration successful
    $response->assertCreated();

    // ASSERT: User created in database
    $this->assertDatabaseHas('users', [
        'email' => 'test@example.com',
    ]);

    // ASSERT: Authentication logged
    $this->assertAuthenticationLogged([
        'event_type' => 'registration',
    ]);
}
```
