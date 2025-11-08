<?php

namespace App\Events\Auth;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a login attempt is initiated
 *
 * This event is dispatched BEFORE credential verification to allow
 * security checks like IP blocking and account lockout to abort the login.
 */
class LoginAttempted
{
    use Dispatchable, SerializesModels;

    /**
     * Create a new event instance
     *
     * @param string $email The email address attempting to login
     * @param string $ipAddress The IP address of the request
     * @param string|null $userAgent The user agent string
     * @param string|null $clientId The OAuth client ID (if applicable)
     * @param array<string, mixed> $metadata Additional metadata (scopes, etc.)
     */
    public function __construct(
        public readonly string $email,
        public readonly string $ipAddress,
        public readonly ?string $userAgent,
        public readonly ?string $clientId = null,
        public readonly array $metadata = []
    ) {
    }

    /**
     * Create event from HTTP request
     */
    public static function fromRequest(Request $request): self
    {
        return new self(
            email: $request->input('email'),
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            clientId: $request->input('client_id'),
            metadata: [
                'scopes' => $request->input('scope', 'openid profile email'),
                'grant_type' => $request->input('grant_type', 'password'),
            ]
        );
    }
}
