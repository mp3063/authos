<?php

namespace App\Events\Auth;

use App\Models\User;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a login attempt fails
 *
 * This event triggers security responses like failed login recording,
 * intrusion detection, and progressive account lockout.
 */
class LoginFailed
{
    use Dispatchable, SerializesModels;

    /**
     * Create a new event instance
     *
     * @param string $email The email address that failed to login
     * @param string $ipAddress The IP address of the request
     * @param string|null $userAgent The user agent string
     * @param string $reason The reason for failure (invalid_credentials, account_inactive, etc.)
     * @param User|null $user The user model if found, null if email doesn't exist
     * @param string|null $clientId The OAuth client ID (if applicable)
     * @param array<string, mixed> $metadata Additional metadata
     */
    public function __construct(
        public readonly string $email,
        public readonly string $ipAddress,
        public readonly ?string $userAgent,
        public readonly string $reason,
        public readonly ?User $user = null,
        public readonly ?string $clientId = null,
        public readonly array $metadata = []
    ) {
    }

    /**
     * Create event from HTTP request
     */
    public static function fromRequest(
        Request $request,
        string $reason,
        ?User $user = null
    ): self {
        return new self(
            email: $request->input('email'),
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            reason: $reason,
            user: $user,
            clientId: $request->input('client_id'),
            metadata: [
                'endpoint' => $request->path(),
                'method' => $request->method(),
            ]
        );
    }
}
