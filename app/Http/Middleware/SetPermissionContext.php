<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Spatie\Permission\PermissionRegistrar;
use Symfony\Component\HttpFoundation\Response;

class SetPermissionContext
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user) {
            $user->setPermissionsTeamId($user->organization_id);
            app(PermissionRegistrar::class)->setPermissionsTeamId($user->organization_id);
        }

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        app(PermissionRegistrar::class)->setPermissionsTeamId(null);
    }
}
