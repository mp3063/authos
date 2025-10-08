<?php

namespace App\Http\Controllers\Api\Traits;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\JsonResource;
use Symfony\Component\HttpFoundation\Response;

/**
 * Standardized API response formatting trait
 */
trait ApiResponse
{
    /**
     * Return successful response
     */
    protected function successResponse($data = null, ?string $message = null, int $status = Response::HTTP_OK): JsonResponse
    {
        $response = [
            'success' => true,
        ];

        if ($data !== null) {
            // Handle API Resources (check AnonymousResourceCollection first as it extends JsonResource)
            if ($data instanceof JsonResource) {
                $response['data'] = $data->resolve();
            } else {
                $response['data'] = $data;
            }
        }

        if ($message) {
            $response['message'] = $message;
        }

        return response()->json($response, $status);
    }

    /**
     * Return error response
     */
    protected function errorResponse(string $message, int $status = Response::HTTP_BAD_REQUEST, array $errors = []): JsonResponse
    {
        // For validation errors, use flat structure for test compatibility
        if ($status === Response::HTTP_UNPROCESSABLE_ENTITY || $this->getErrorCode($status) === 'validation_failed') {
            $response = [
                'success' => false,
                'error' => 'validation_failed',
                'error_description' => $message,
                'errors' => $errors,
            ];
        } else {
            // For other errors, keep nested structure
            $response = [
                'success' => false,
                'error' => [
                    'message' => $message,
                    'code' => $this->getErrorCode($status),
                ],
            ];

            if (! empty($errors)) {
                $response['error']['details'] = $errors;
            }
        }

        return response()->json($response, $status);
    }

    /**
     * Return validation error response
     */
    protected function validationErrorResponse($errors, string $message = 'The given data was invalid.'): JsonResponse
    {
        // Convert MessageBag to array if needed
        if (is_object($errors) && method_exists($errors, 'toArray')) {
            $errors = $errors->toArray();
        }

        $response = [
            'success' => false,
            'error' => 'validation_failed',
            'error_description' => $message,
            'errors' => $errors,
        ];

        return response()->json($response, Response::HTTP_UNPROCESSABLE_ENTITY);
    }

    /**
     * Return unauthorized error response
     */
    protected function unauthorizedResponse(string $message = 'Unauthorized'): JsonResponse
    {
        return $this->errorResponse($message, Response::HTTP_UNAUTHORIZED);
    }

    /**
     * Return forbidden error response
     */
    protected function forbiddenResponse(string $message = 'Insufficient permissions'): JsonResponse
    {
        return $this->errorResponse($message, Response::HTTP_FORBIDDEN);
    }

    /**
     * Return not found error response
     */
    protected function notFoundResponse(string $message = 'Resource not found'): JsonResponse
    {
        return $this->errorResponse($message, Response::HTTP_NOT_FOUND);
    }

    /**
     * Return server error response
     */
    protected function serverErrorResponse(string $message = 'Internal server error'): JsonResponse
    {
        return $this->errorResponse($message, Response::HTTP_INTERNAL_SERVER_ERROR);
    }

    /**
     * Return paginated response
     */
    protected function paginatedResponse(LengthAwarePaginator $paginator, ?string $message = null, ?string $resourceClass = null): JsonResponse
    {
        $data = $paginator->items();

        // Transform data using resource class if provided
        if ($resourceClass && class_exists($resourceClass)) {
            $data = $resourceClass::collection($data)->resolve();
        }

        $response = [
            'success' => true,
            'data' => $data,
            'meta' => [
                'pagination' => [
                    'current_page' => $paginator->currentPage(),
                    'last_page' => $paginator->lastPage(),
                    'per_page' => $paginator->perPage(),
                    'total' => $paginator->total(),
                    'from' => $paginator->firstItem(),
                    'to' => $paginator->lastItem(),
                ],
                'current_page' => $paginator->currentPage(),
                'last_page' => $paginator->lastPage(),
                'per_page' => $paginator->perPage(),
                'total' => $paginator->total(),
                'from' => $paginator->firstItem(),
                'to' => $paginator->lastItem(),
                'path' => $paginator->path(),
                'next_page_url' => $paginator->nextPageUrl(),
                'prev_page_url' => $paginator->previousPageUrl(),
            ],
            'links' => [
                'first' => $paginator->url(1),
                'last' => $paginator->url($paginator->lastPage()),
                'prev' => $paginator->previousPageUrl(),
                'next' => $paginator->nextPageUrl(),
            ],
        ];

        if ($message) {
            $response['message'] = $message;
        }

        return response()->json($response);
    }

    /**
     * Return collection response
     */
    protected function collectionResponse($data, ?string $message = null, ?string $resourceClass = null): JsonResponse
    {
        // Transform data using resource class if provided
        if ($resourceClass && class_exists($resourceClass)) {
            $data = $resourceClass::collection($data);
        }

        return $this->successResponse($data, $message);
    }

    /**
     * Return resource response (single item)
     */
    protected function resourceResponse($data, string $resourceClass, ?string $message = null, int $status = Response::HTTP_OK): JsonResponse
    {
        if (class_exists($resourceClass)) {
            $data = new $resourceClass($data);
        }

        return $this->successResponse($data, $message, $status);
    }

    /**
     * Return created resource response
     */
    protected function createdResourceResponse($data, string $resourceClass, ?string $message = null): JsonResponse
    {
        return $this->resourceResponse(
            $data,
            $resourceClass,
            $message ?? 'Resource created successfully',
            Response::HTTP_CREATED
        );
    }

    /**
     * Return updated resource response
     */
    protected function updatedResourceResponse($data, string $resourceClass, ?string $message = null): JsonResponse
    {
        return $this->resourceResponse(
            $data,
            $resourceClass,
            $message ?? 'Resource updated successfully'
        );
    }

    /**
     * Return resource created response
     */
    protected function createdResponse($data, string $message = 'Resource created successfully'): JsonResponse
    {
        return $this->successResponse($data, $message, Response::HTTP_CREATED);
    }

    /**
     * Return resource updated response
     */
    protected function updatedResponse($data = null, string $message = 'Resource updated successfully'): JsonResponse
    {
        return $this->successResponse($data, $message);
    }

    /**
     * Return resource deleted response
     */
    protected function deletedResponse(string $message = 'Resource deleted successfully'): JsonResponse
    {
        return $this->successResponse(null, $message);
    }

    /**
     * Return no content response
     */
    protected function noContentResponse(): JsonResponse
    {
        return response()->json(null, Response::HTTP_NO_CONTENT);
    }

    /**
     * Get error code based on HTTP status
     */
    protected function getErrorCode(int $status): string
    {
        return match ($status) {
            Response::HTTP_BAD_REQUEST => 'bad_request',
            Response::HTTP_UNAUTHORIZED => 'unauthorized',
            Response::HTTP_FORBIDDEN => 'forbidden',
            Response::HTTP_NOT_FOUND => 'not_found',
            Response::HTTP_UNPROCESSABLE_ENTITY => 'validation_failed',
            Response::HTTP_TOO_MANY_REQUESTS => 'rate_limit_exceeded',
            Response::HTTP_INTERNAL_SERVER_ERROR => 'server_error',
            default => 'unknown_error',
        };
    }
}
