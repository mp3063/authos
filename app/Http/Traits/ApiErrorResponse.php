<?php

namespace App\Http\Traits;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Validation\ValidationException;
use Throwable;

trait ApiErrorResponse
{
    /**
     * Create a standardized error response.
     */
    public function errorResponse(
        string $message,
        int $statusCode = Response::HTTP_BAD_REQUEST,
        ?string $errorCode = null,
        ?array $details = null,
        ?Throwable $exception = null
    ): JsonResponse {
        $error = [
            'code' => $errorCode ?? $this->getErrorCodeFromStatus($statusCode),
            'message' => $message,
        ];

        if ($details !== null) {
            $error['details'] = $details;
        }

        $response = [
            'success' => false,
            'error' => $error,
            // Include top-level message for backward compatibility with tests
            'message' => $message,
        ];

        // Add debug information in development
        if (app()->environment(['local', 'development']) && $exception) {
            $response['debug'] = [
                'exception' => get_class($exception),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => collect($exception->getTrace())->take(5)->map(function ($trace) {
                    return collect($trace)->only(['file', 'line', 'function', 'class', 'type']);
                })->all(),
            ];
        }

        return response()->json($response, $statusCode, [
            'Content-Type' => 'application/json',
        ]);
    }

    /**
     * Create a validation error response.
     */
    public function validationErrorResponse(ValidationException $exception): JsonResponse
    {
        $response = [
            'success' => false,
            'error' => [
                'code' => 'validation_failed',
                'message' => 'The given data was invalid',
                'details' => [
                    'validation_errors' => $exception->errors(),
                ],
            ],
            // Include Laravel's expected format for compatibility with test assertions
            'errors' => $exception->errors(),
        ];

        // Add debug information in development
        if (app()->environment(['local', 'development'])) {
            $response['debug'] = [
                'exception' => get_class($exception),
                'file' => $exception->getFile(),
                'line' => $exception->getLine(),
                'trace' => collect($exception->getTrace())->take(5)->map(function ($trace) {
                    return collect($trace)->only(['file', 'line', 'function', 'class', 'type']);
                })->all(),
            ];
        }

        return response()->json($response, Response::HTTP_UNPROCESSABLE_ENTITY, [
            'Content-Type' => 'application/json',
        ]);
    }

    /**
     * Create an authentication error response.
     */
    public function authenticationErrorResponse(?string $message = null): JsonResponse
    {
        return $this->errorResponse(
            message: $message ?? 'Authentication required',
            statusCode: Response::HTTP_UNAUTHORIZED,
            errorCode: 'authentication_required'
        );
    }

    /**
     * Create an authorization error response.
     */
    public function authorizationErrorResponse(?string $message = null): JsonResponse
    {
        return $this->errorResponse(
            message: $message ?? 'Insufficient permissions',
            statusCode: Response::HTTP_FORBIDDEN,
            errorCode: 'insufficient_permissions'
        );
    }

    /**
     * Create a not found error response.
     */
    public function notFoundErrorResponse(string $resource = 'Resource'): JsonResponse
    {
        return $this->errorResponse(
            message: "{$resource} not found",
            statusCode: Response::HTTP_NOT_FOUND,
            errorCode: 'resource_not_found'
        );
    }

    /**
     * Create a rate limit error response.
     */
    public function rateLimitErrorResponse(?int $retryAfter = null): JsonResponse
    {
        $headers = [];
        if ($retryAfter !== null) {
            $headers['Retry-After'] = $retryAfter;
        }

        $response = $this->errorResponse(
            message: 'Too many requests',
            statusCode: Response::HTTP_TOO_MANY_REQUESTS,
            errorCode: 'rate_limit_exceeded',
            details: $retryAfter ? ['retry_after_seconds' => $retryAfter] : null
        );

        if (! empty($headers)) {
            foreach ($headers as $key => $value) {
                $response->header($key, $value);
            }
        }

        return $response;
    }

    /**
     * Create a server error response.
     */
    public function serverErrorResponse(
        ?string $message = null,
        ?Throwable $exception = null
    ): JsonResponse {
        return $this->errorResponse(
            message: $message ?? 'Internal server error',
            statusCode: Response::HTTP_INTERNAL_SERVER_ERROR,
            errorCode: 'internal_server_error',
            exception: $exception
        );
    }

    /**
     * Create a service unavailable error response.
     */
    protected function serviceUnavailableErrorResponse(?string $message = null): JsonResponse
    {
        return $this->errorResponse(
            message: $message ?? 'Service temporarily unavailable',
            statusCode: Response::HTTP_SERVICE_UNAVAILABLE,
            errorCode: 'service_unavailable'
        );
    }

    /**
     * Create a conflict error response.
     */
    protected function conflictErrorResponse(string $message, ?array $details = null): JsonResponse
    {
        return $this->errorResponse(
            message: $message,
            statusCode: Response::HTTP_CONFLICT,
            errorCode: 'resource_conflict',
            details: $details
        );
    }

    /**
     * Get appropriate error code from HTTP status code.
     */
    private function getErrorCodeFromStatus(int $statusCode): string
    {
        return match ($statusCode) {
            Response::HTTP_BAD_REQUEST => 'bad_request',
            Response::HTTP_UNAUTHORIZED => 'authentication_required',
            Response::HTTP_FORBIDDEN => 'insufficient_permissions',
            Response::HTTP_NOT_FOUND => 'resource_not_found',
            Response::HTTP_METHOD_NOT_ALLOWED => 'method_not_allowed',
            Response::HTTP_UNPROCESSABLE_ENTITY => 'validation_failed',
            Response::HTTP_TOO_MANY_REQUESTS => 'rate_limit_exceeded',
            Response::HTTP_INTERNAL_SERVER_ERROR => 'internal_server_error',
            Response::HTTP_SERVICE_UNAVAILABLE => 'service_unavailable',
            Response::HTTP_CONFLICT => 'resource_conflict',
            default => 'unknown_error',
        };
    }
}
