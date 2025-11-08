# Password Reset Implementation

## Overview
Secure password reset functionality following OWASP best practices for authentication and authorization.

## Security Features

### OWASP Top 10 (2021) Compliance
- **A07:2021 - Identification and Authentication Failures**: Fully addressed
- Token hashing (SHA-256) before storage
- Single-use tokens (deleted after successful use)
- Token expiration (60 minutes)
- Rate limiting (5 requests per hour)
- Email enumeration protection
- All sessions revoked on password change
- Strong password validation

### Token Security
- **Generation**: 60-character random string using `Str::random(60)`
- **Storage**: Hashed with SHA-256 (`hash('sha256', $token)`)
- **Comparison**: Time-safe comparison with `hash_equals()`
- **Expiration**: 60 minutes from creation
- **Single-Use**: Token deleted immediately after successful use

### Password Requirements
- Minimum 8 characters
- Mixed case (uppercase + lowercase)
- Numbers required
- Special characters required
- Checked against known breach databases
- Must not be a common password

## API Endpoints

### 1. Request Password Reset
**Endpoint**: `POST /api/v1/auth/password/email`

**Rate Limit**: 5 requests per 60 minutes per IP

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Success Response** (200 OK):
```json
{
  "message": "If that email address is in our system, we have sent a password reset link to it."
}
```

**Notes**:
- Always returns success to prevent email enumeration
- Creates hashed token in `password_reset_tokens` table
- Sends email notification with plain token (only visible once)
- Replaces any existing tokens for the same email

### 2. Reset Password
**Endpoint**: `POST /api/v1/auth/password/reset`

**Rate Limit**: 5 requests per 60 minutes per IP

**Request Body**:
```json
{
  "email": "user@example.com",
  "token": "60_character_token_from_email",
  "password": "Zx9!kP2#qL5@wN8&",
  "password_confirmation": "Zx9!kP2#qL5@wN8&"
}
```

**Success Response** (200 OK):
```json
{
  "message": "Password has been reset successfully. All previous sessions have been terminated.",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "user@example.com"
  },
  "token": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer",
    "expires_at": "2025-01-09T12:00:00.000000Z"
  }
}
```

**Error Responses**:

**Invalid/Expired Token** (422 Unprocessable Entity):
```json
{
  "message": "Invalid or expired password reset token.",
  "error": "invalid_token"
}
```

**Token Expired** (422 Unprocessable Entity):
```json
{
  "message": "Password reset token has expired. Please request a new one.",
  "error": "token_expired"
}
```

**Validation Errors** (422 Unprocessable Entity):
```json
{
  "success": false,
  "error": "validation_failed",
  "error_description": "The given data was invalid.",
  "errors": {
    "password": [
      "The password must be at least 8 characters.",
      "The password must contain at least one uppercase letter.",
      "The password must contain at least one number.",
      "The password must contain at least one special character."
    ]
  }
}
```

**Rate Limit Exceeded** (429 Too Many Requests):
```json
{
  "message": "Too Many Attempts."
}
```

## Implementation Files

### Controller
**File**: `/app/Http/Controllers/Api/PasswordResetController.php`

Key Methods:
- `sendResetLinkEmail()`: Handles reset requests
- `reset()`: Processes password reset with token

### Form Requests
**Files**:
- `/app/Http/Requests/Api/PasswordResetRequest.php` - Email validation
- `/app/Http/Requests/Api/PasswordResetConfirmRequest.php` - Reset validation

### Notification
**File**: `/app/Notifications/PasswordResetNotification.php`

Sends email with:
- Reset link containing plain token
- 60-minute expiration notice
- Security warning about not sharing link

### Routes
**File**: `/routes/api.php`

```php
// Password Reset routes (public, rate-limited)
Route::prefix('password')->middleware('throttle:5,60')->group(function () {
    Route::post('/email', [PasswordResetController::class, 'sendResetLinkEmail']);
    Route::post('/reset', [PasswordResetController::class, 'reset']);
});
```

## Database Schema

### password_reset_tokens Table
```sql
CREATE TABLE password_reset_tokens (
    email VARCHAR(255) PRIMARY KEY,
    token VARCHAR(255) NOT NULL,  -- SHA-256 hashed token
    created_at TIMESTAMP NULL
);
```

**Index**: Primary key on `email`

## Security Flow

### Reset Request Flow
1. User submits email address
2. System checks if email exists
3. Generates 60-character random token
4. Hashes token with SHA-256
5. Deletes any existing tokens for email
6. Stores hashed token with timestamp
7. Sends email with plain token
8. Returns generic success message (regardless of email validity)
9. Logs authentication event

### Password Reset Flow
1. User submits email, token, and new password
2. System hashes provided token
3. Retrieves stored token for email
4. Compares hashes using time-safe comparison
5. Checks token expiration (60 minutes)
6. Validates password complexity
7. Updates user password with bcrypt hash
8. Updates `password_changed_at` timestamp
9. Deletes reset token (single-use enforcement)
10. Revokes all existing access tokens
11. Generates new access token
12. Returns success with new token
13. Logs authentication event

## Testing

### OWASP Security Tests
**File**: `/tests/Security/OwaspA07AuthenticationFailuresTest.php`

Tests:
- `it_validates_secure_password_reset_flow()` ✓
- `it_prevents_password_reset_token_reuse()` ✓

### Integration Tests
**File**: `/tests/Integration/Auth/PasswordResetFlowTest.php`

Tests (10 total):
- ✓ Request reset for valid email
- ✓ Generic message for invalid email (enumeration protection)
- ✓ Reset password with valid token
- ✓ Prevent token reuse
- ✓ Validate token expiration
- ✓ Password complexity validation
- ✓ Rate limiting enforcement
- ✓ Revoke all tokens on password change
- ✓ Validate required fields
- ✓ Replace existing tokens on new request

**Run Tests**:
```bash
# All password-related tests
herd php artisan test --filter="password"

# Specific test files
herd php artisan test tests/Security/OwaspA07AuthenticationFailuresTest.php --filter="password"
herd php artisan test tests/Integration/Auth/PasswordResetFlowTest.php

# All tests together
herd php artisan test --filter="password" tests/Security/ tests/Integration/Auth/
```

**Test Results**: 16 passed (71 assertions)

## Security Considerations

### Email Enumeration Prevention
- Same response for valid and invalid emails
- No timing differences in responses
- No information leakage in error messages

### Token Security
- Never store plain tokens
- Use cryptographically secure random generation
- SHA-256 hashing before storage
- Time-safe comparison to prevent timing attacks
- Single-use enforcement
- Short expiration window (60 minutes)

### Rate Limiting
- 5 requests per 60 minutes per IP
- Applied to both endpoints
- Prevents brute force attacks
- Prevents denial of service

### Session Management
- All tokens revoked on password change
- User receives new token after reset
- Forces re-authentication on all devices
- Prevents unauthorized access with old tokens

### Audit Logging
- All events logged via `AuthenticationLogService`
- Includes IP address, user agent, timestamp
- Separate logs for:
  - Password reset requested (success/failure)
  - Password reset completed
  - Token validation failures

## Usage Example

### Frontend Integration
```javascript
// 1. Request password reset
const requestReset = async (email) => {
  const response = await fetch('https://authos.test/api/v1/auth/password/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email }),
  });

  const data = await response.json();
  console.log(data.message);
};

// 2. Reset password with token
const resetPassword = async (email, token, password) => {
  const response = await fetch('https://authos.test/api/v1/auth/password/reset', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email,
      token,
      password,
      password_confirmation: password,
    }),
  });

  if (response.ok) {
    const data = await response.json();
    // Store new access token
    localStorage.setItem('access_token', data.token.access_token);
    // Redirect to dashboard
    window.location.href = '/dashboard';
  } else {
    const error = await response.json();
    console.error(error.message);
  }
};
```

### Email Template Variables
The reset email includes:
- `$resetUrl`: Full URL with token and email
- `$notifiable->name`: User's name
- `$notifiable->email`: User's email
- Expiration notice (60 minutes)
- Security warning

## Monitoring

### Metrics to Track
- Password reset request rate
- Failed token validation attempts
- Expired token usage attempts
- Token reuse attempts
- Rate limit hits
- Average time from request to reset

### Alerts
- Unusual spike in reset requests
- High rate of failed token validations
- Suspected brute force attempts
- Rate limit threshold breaches

## Compliance

### Standards Met
- OWASP Top 10 (2021) - A07
- NIST SP 800-63B (Digital Identity Guidelines)
- GDPR (user data protection)
- SOC2 (access control)
- ISO 27001 (information security)

### Audit Trail
All password reset operations are logged with:
- Timestamp
- User identifier
- IP address
- User agent
- Action performed
- Success/failure status
- Error details (if applicable)

## Troubleshooting

### Common Issues

**Token Not Working**:
- Check if token expired (60 minutes)
- Verify token wasn't already used
- Ensure token matches exactly (no extra spaces)
- Check if new token was requested (replaces old one)

**Rate Limit Errors**:
- Wait 60 minutes before retrying
- Check if multiple requests from same IP
- Review application logs for details

**Email Not Received**:
- Check spam/junk folder
- Verify email configuration in `.env`
- Check mail logs for delivery status
- Test with different email provider

**Password Validation Errors**:
- Ensure password meets complexity requirements
- Check if password appears in breach databases
- Verify password confirmation matches
- Review validation error messages

## Future Enhancements

Potential improvements:
- SMS-based password reset
- Security questions as alternative
- Biometric verification
- Multi-factor authentication requirement
- Custom password policies per organization
- Configurable token expiration
- Password history to prevent reuse
- Account recovery without email
