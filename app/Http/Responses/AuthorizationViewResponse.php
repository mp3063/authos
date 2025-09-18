<?php

namespace App\Http\Responses;

use Illuminate\Http\Response;
use Laravel\Passport\Contracts\AuthorizationViewResponse as AuthorizationViewResponseContract;

class AuthorizationViewResponse implements AuthorizationViewResponseContract
{
    /**
     * The view parameters.
     */
    protected array $parameters = [];

    /**
     * Specify the parameters that should be passed to the view.
     *
     * @param  array<string, mixed>  $parameters
     */
    public function withParameters(array $parameters = []): static
    {
        $this->parameters = $parameters;

        return $this;
    }

    /**
     * Create an HTTP response that represents the object.
     */
    public function toResponse($request): Response
    {
        return response()->view('passport.authorize', $this->parameters);
    }
}
