<?php

namespace App\Events\Auth;

use App\Models\User;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a login succeeds
 *
 * This event triggers post-login actions like session regeneration,
 * clearing failed attempts, and logging successful authentication.
 */
class LoginSuccessful
{
    use Dispatchable, SerializesModels;

    /**
     * Create a new event instance
     *
     * @param User $user The authenticated user
     * @param string $ipAddress The IP address of the request
     * @param string|null $userAgent The user agent string
     * @param string|null $clientId The OAuth client ID (if applicable)
     * @param array<string> $scopes The granted OAuth scopes
     * @param array<string, mixed> $metadata Additional metadata
     */
    public function __construct(
        public readonly User $user,
        public readonly string $ipAddress,
        public readonly ?string $userAgent,
        public readonly ?string $clientId = null,
        public readonly array $scopes = [],
        public readonly array $metadata = []
    ) {
    }

    /**
     * Create event from HTTP request
     *
     * @param array<string> $scopes
     */
    public static function fromRequest(
        User $user,
        Request $request,
        array $scopes = []
    ): self {
        return new self(
            user: $user,
            ipAddress: $request->ip(),
            userAgent: $request->userAgent(),
            clientId: $request->input('client_id'),
            scopes: $scopes,
            metadata: [
                'endpoint' => $request->path(),
                'method' => $request->method(),
            ]
        );
    }
}
