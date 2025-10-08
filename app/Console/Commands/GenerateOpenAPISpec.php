<?php

declare(strict_types=1);

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

class GenerateOpenAPISpec extends Command
{
    protected $signature = 'openapi:generate
                          {--validate : Validate the generated spec}
                          {--output=public/openapi.json : Output file path}';

    protected $description = 'Generate OpenAPI 3.1.0 specification from routes';

    private array $schemas = [];

    public function handle(): int
    {
        $this->info('Generating OpenAPI specification...');

        $spec = $this->generateSpec();

        $outputPath = base_path($this->option('output'));
        $directory = dirname($outputPath);

        if (! file_exists($directory)) {
            mkdir($directory, 0755, true);
        }

        file_put_contents(
            $outputPath,
            json_encode($spec, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );

        $this->info("OpenAPI spec generated: $outputPath");

        if ($this->option('validate')) {
            return $this->validateSpec($spec);
        }

        return self::SUCCESS;
    }

    private function generateSpec(): array
    {
        return [
            'openapi' => '3.1.0',
            'info' => [
                'title' => 'AuthOS API',
                'version' => '1.0.0',
                'description' => 'Enterprise authentication service - Auth0 alternative with OAuth 2.0, OpenID Connect, MFA, SSO, and social authentication.',
                'contact' => [
                    'name' => 'AuthOS Support',
                    'url' => 'https://authos.dev',
                    'email' => 'support@authos.dev',
                ],
                'license' => [
                    'name' => 'MIT',
                    'url' => 'https://opensource.org/licenses/MIT',
                ],
            ],
            'servers' => [
                [
                    'url' => 'http://authos.test/api',
                    'description' => 'Local development',
                ],
                [
                    'url' => 'https://api.authos.dev',
                    'description' => 'Production',
                ],
            ],
            'paths' => $this->generatePaths(),
            'components' => [
                'securitySchemes' => $this->getSecuritySchemes(),
                'schemas' => $this->generateSchemas(),
            ],
            'security' => [
                ['bearerAuth' => []],
            ],
            'tags' => $this->getTags(),
        ];
    }

    private function generatePaths(): array
    {
        $paths = [];
        $routes = Route::getRoutes();

        foreach ($routes as $route) {
            $uri = $route->uri();

            // Only process API routes
            if (! str_starts_with($uri, 'api/')) {
                continue;
            }

            // Remove 'api/' prefix
            $path = '/'.ltrim(substr($uri, 4), '/');

            // Convert Laravel route params to OpenAPI format
            $path = preg_replace('/\{([^}]+)}/', '{$1}', $path);

            $methods = $route->methods();

            foreach ($methods as $method) {
                $method = strtolower($method);

                if ($method === 'head') {
                    continue;
                }

                $paths[$path][$method] = $this->generateOperation($route, $method);
            }
        }

        return $paths;
    }

    private function generateOperation($route, string $method): array
    {
        $action = $route->getActionName();
        $uri = $route->uri();

        // Extract controller and method
        [$controller, $controllerMethod] = $this->extractControllerInfo($action);

        $operation = [
            'summary' => $this->generateSummary($uri, $method, $controllerMethod),
            'operationId' => $this->generateOperationId($uri, $method),
            'tags' => $this->extractTags($uri),
            'parameters' => $this->extractParameters($route, $uri),
            'responses' => $this->generateResponses($method, $uri),
        ];

        // Add request body for mutations
        if (in_array($method, ['post', 'put', 'patch'])) {
            $operation['requestBody'] = $this->generateRequestBody($uri, $method);
        }

        // Add security based on middleware
        $middleware = $route->middleware();
        if (in_array('auth:api', $middleware)) {
            $operation['security'] = [['bearerAuth' => []]];
        } else {
            $operation['security'] = [];
        }

        return $operation;
    }

    private function extractControllerInfo(string $action): array
    {
        if (str_contains($action, '@')) {
            [$controller, $method] = explode('@', $action);

            return [$controller, $method];
        }

        return ['Closure', 'handle'];
    }

    private function generateSummary(string $uri, string $method, ?string $controllerMethod): string
    {
        // Generate human-readable summary
        $summaries = [
            'post /v1/auth/register' => 'Register a new user',
            'post /v1/auth/login' => 'Login with credentials',
            'post /v1/auth/logout' => 'Logout current user',
            'post /v1/auth/refresh' => 'Refresh access token',
            'get /v1/auth/user' => 'Get authenticated user',
            'post /v1/auth/mfa/verify' => 'Verify MFA code',
            'get /v1/users' => 'List users',
            'post /v1/users' => 'Create a new user',
            'get /v1/users/{id}' => 'Get user by ID',
            'put /v1/users/{id}' => 'Update user',
            'delete /v1/users/{id}' => 'Delete user',
            'get /v1/organizations' => 'List organizations',
            'post /v1/organizations' => 'Create organization',
            'get /v1/organizations/{id}' => 'Get organization',
            'put /v1/organizations/{id}' => 'Update organization',
            'delete /v1/organizations/{id}' => 'Delete organization',
            'get /v1/applications' => 'List applications',
            'post /v1/applications' => 'Create application',
            'get /v1/applications/{id}' => 'Get application',
            'put /v1/applications/{id}' => 'Update application',
            'delete /v1/applications/{id}' => 'Delete application',
        ];

        $key = strtolower($method).' '.$uri;

        return $summaries[$key] ?? Str::title(str_replace(['-', '_'], ' ', $controllerMethod ?? $method));
    }

    private function generateOperationId(string $uri, string $method): string
    {
        $parts = array_filter(explode('/', $uri));
        $parts = array_map(fn ($p) => str_replace(['{', '}'], '', $p), $parts);

        return $method.implode('', array_map('ucfirst', $parts));
    }

    private function extractTags(string $uri): array
    {
        if (str_contains($uri, '/v1/auth')) {
            return ['Authentication'];
        }
        if (str_contains($uri, '/v1/users')) {
            return ['Users'];
        }
        if (str_contains($uri, '/v1/organizations')) {
            return ['Organizations'];
        }
        if (str_contains($uri, '/v1/applications')) {
            return ['Applications'];
        }
        if (str_contains($uri, '/v1/profile')) {
            return ['Profile'];
        }
        if (str_contains($uri, '/v1/mfa')) {
            return ['MFA'];
        }
        if (str_contains($uri, '/v1/sso')) {
            return ['SSO'];
        }
        if (str_contains($uri, '/v1/enterprise')) {
            return ['Enterprise'];
        }
        if (str_contains($uri, '/v1/oauth')) {
            return ['OAuth'];
        }

        return ['General'];
    }

    private function extractParameters($route, string $uri): array
    {
        $parameters = [];

        // Path parameters
        preg_match_all('/\{([^}]+)}/', $uri, $matches);
        foreach ($matches[1] as $param) {
            $parameters[] = [
                'name' => $param,
                'in' => 'path',
                'required' => true,
                'schema' => ['type' => 'string'],
                'description' => ucfirst(str_replace('_', ' ', $param)),
            ];
        }

        // Query parameters for GET requests
        if (in_array('GET', $route->methods())) {
            $commonQueryParams = [
                ['name' => 'page', 'in' => 'query', 'required' => false, 'schema' => ['type' => 'integer', 'default' => 1]],
                ['name' => 'per_page', 'in' => 'query', 'required' => false, 'schema' => ['type' => 'integer', 'default' => 15]],
                ['name' => 'sort', 'in' => 'query', 'required' => false, 'schema' => ['type' => 'string']],
                ['name' => 'filter', 'in' => 'query', 'required' => false, 'schema' => ['type' => 'string']],
            ];

            if (str_contains($uri, 'index') || ! str_contains($uri, '{')) {
                $parameters = array_merge($parameters, $commonQueryParams);
            }
        }

        return $parameters;
    }

    private function generateRequestBody(string $uri, string $method): array
    {
        $schemaName = $this->getRequestSchemaName($uri, $method);

        return [
            'required' => true,
            'content' => [
                'application/json' => [
                    'schema' => ['$ref' => "#/components/schemas/$schemaName"],
                ],
            ],
        ];
    }

    private function getRequestSchemaName(string $uri, string $method): string
    {
        if (str_contains($uri, '/auth/register')) {
            return 'RegisterRequest';
        }
        if (str_contains($uri, '/auth/login')) {
            return 'LoginRequest';
        }
        if (str_contains($uri, '/users')) {
            return $method === 'post' ? 'CreateUserRequest' : 'UpdateUserRequest';
        }
        if (str_contains($uri, '/organizations')) {
            return $method === 'post' ? 'CreateOrganizationRequest' : 'UpdateOrganizationRequest';
        }
        if (str_contains($uri, '/applications')) {
            return $method === 'post' ? 'CreateApplicationRequest' : 'UpdateApplicationRequest';
        }

        return 'GenericRequest';
    }

    private function generateResponses(string $method, string $uri): array
    {
        $responses = [
            '200' => [
                'description' => 'Successful response',
                'content' => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/SuccessResponse'],
                    ],
                ],
            ],
            '401' => [
                'description' => 'Unauthorized',
                'content' => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/ErrorResponse'],
                    ],
                ],
            ],
            '422' => [
                'description' => 'Validation error',
                'content' => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/ValidationErrorResponse'],
                    ],
                ],
            ],
            '500' => [
                'description' => 'Server error',
                'content' => [
                    'application/json' => [
                        'schema' => ['$ref' => '#/components/schemas/ErrorResponse'],
                    ],
                ],
            ],
        ];

        if ($method === 'delete') {
            $responses['204'] = ['description' => 'No content'];
        }

        if ($method === 'post' && str_contains($uri, '/auth/login')) {
            $responses['200']['content']['application/json']['schema'] = ['$ref' => '#/components/schemas/LoginResponse'];
        }

        return $responses;
    }

    private function getSecuritySchemes(): array
    {
        return [
            'bearerAuth' => [
                'type' => 'http',
                'scheme' => 'bearer',
                'bearerFormat' => 'JWT',
                'description' => 'OAuth 2.0 access token',
            ],
            'oauth2' => [
                'type' => 'oauth2',
                'flows' => [
                    'authorizationCode' => [
                        'authorizationUrl' => '/oauth/authorize',
                        'tokenUrl' => '/oauth/token',
                        'scopes' => [
                            'openid' => 'OpenID Connect',
                            'profile' => 'User profile',
                            'email' => 'Email address',
                            'sso' => 'Single sign-on',
                        ],
                    ],
                ],
            ],
        ];
    }

    private function generateSchemas(): array
    {
        return [
            'SuccessResponse' => [
                'type' => 'object',
                'properties' => [
                    'success' => ['type' => 'boolean', 'example' => true],
                    'data' => ['type' => 'object'],
                    'message' => ['type' => 'string'],
                ],
            ],
            'ErrorResponse' => [
                'type' => 'object',
                'properties' => [
                    'success' => ['type' => 'boolean', 'example' => false],
                    'error' => ['type' => 'string'],
                    'message' => ['type' => 'string'],
                ],
            ],
            'ValidationErrorResponse' => [
                'type' => 'object',
                'properties' => [
                    'success' => ['type' => 'boolean', 'example' => false],
                    'message' => ['type' => 'string'],
                    'errors' => [
                        'type' => 'object',
                        'additionalProperties' => [
                            'type' => 'array',
                            'items' => ['type' => 'string'],
                        ],
                    ],
                ],
            ],
            'LoginRequest' => [
                'type' => 'object',
                'required' => ['email', 'password'],
                'properties' => [
                    'email' => ['type' => 'string', 'format' => 'email'],
                    'password' => ['type' => 'string', 'format' => 'password'],
                ],
            ],
            'LoginResponse' => [
                'type' => 'object',
                'properties' => [
                    'success' => ['type' => 'boolean', 'example' => true],
                    'data' => [
                        'type' => 'object',
                        'properties' => [
                            'access_token' => ['type' => 'string'],
                            'token_type' => ['type' => 'string', 'example' => 'Bearer'],
                            'expires_in' => ['type' => 'integer'],
                            'user' => ['$ref' => '#/components/schemas/User'],
                        ],
                    ],
                ],
            ],
            'RegisterRequest' => [
                'type' => 'object',
                'required' => ['name', 'email', 'password'],
                'properties' => [
                    'name' => ['type' => 'string'],
                    'email' => ['type' => 'string', 'format' => 'email'],
                    'password' => ['type' => 'string', 'format' => 'password', 'minLength' => 8],
                ],
            ],
            'User' => [
                'type' => 'object',
                'properties' => [
                    'id' => ['type' => 'string', 'format' => 'uuid'],
                    'name' => ['type' => 'string'],
                    'email' => ['type' => 'string', 'format' => 'email'],
                    'email_verified_at' => ['type' => 'string', 'format' => 'date-time', 'nullable' => true],
                    'mfa_enabled' => ['type' => 'boolean'],
                    'created_at' => ['type' => 'string', 'format' => 'date-time'],
                    'updated_at' => ['type' => 'string', 'format' => 'date-time'],
                ],
            ],
            'Organization' => [
                'type' => 'object',
                'properties' => [
                    'id' => ['type' => 'string', 'format' => 'uuid'],
                    'name' => ['type' => 'string'],
                    'slug' => ['type' => 'string'],
                    'settings' => ['type' => 'object'],
                    'created_at' => ['type' => 'string', 'format' => 'date-time'],
                    'updated_at' => ['type' => 'string', 'format' => 'date-time'],
                ],
            ],
            'Application' => [
                'type' => 'object',
                'properties' => [
                    'id' => ['type' => 'string', 'format' => 'uuid'],
                    'name' => ['type' => 'string'],
                    'client_id' => ['type' => 'string'],
                    'redirect_uris' => ['type' => 'array', 'items' => ['type' => 'string']],
                    'created_at' => ['type' => 'string', 'format' => 'date-time'],
                    'updated_at' => ['type' => 'string', 'format' => 'date-time'],
                ],
            ],
            'CreateUserRequest' => [
                'type' => 'object',
                'required' => ['name', 'email', 'password'],
                'properties' => [
                    'name' => ['type' => 'string'],
                    'email' => ['type' => 'string', 'format' => 'email'],
                    'password' => ['type' => 'string', 'format' => 'password'],
                    'organization_id' => ['type' => 'string', 'format' => 'uuid'],
                ],
            ],
            'UpdateUserRequest' => [
                'type' => 'object',
                'properties' => [
                    'name' => ['type' => 'string'],
                    'email' => ['type' => 'string', 'format' => 'email'],
                ],
            ],
            'CreateOrganizationRequest' => [
                'type' => 'object',
                'required' => ['name'],
                'properties' => [
                    'name' => ['type' => 'string'],
                    'slug' => ['type' => 'string'],
                    'settings' => ['type' => 'object'],
                ],
            ],
            'UpdateOrganizationRequest' => [
                'type' => 'object',
                'properties' => [
                    'name' => ['type' => 'string'],
                    'settings' => ['type' => 'object'],
                ],
            ],
            'CreateApplicationRequest' => [
                'type' => 'object',
                'required' => ['name', 'redirect_uris'],
                'properties' => [
                    'name' => ['type' => 'string'],
                    'redirect_uris' => ['type' => 'array', 'items' => ['type' => 'string']],
                    'organization_id' => ['type' => 'string', 'format' => 'uuid'],
                ],
            ],
            'UpdateApplicationRequest' => [
                'type' => 'object',
                'properties' => [
                    'name' => ['type' => 'string'],
                    'redirect_uris' => ['type' => 'array', 'items' => ['type' => 'string']],
                ],
            ],
            'GenericRequest' => [
                'type' => 'object',
                'additionalProperties' => true,
            ],
        ];
    }

    private function getTags(): array
    {
        return [
            ['name' => 'Authentication', 'description' => 'User authentication and authorization'],
            ['name' => 'Users', 'description' => 'User management operations'],
            ['name' => 'Organizations', 'description' => 'Organization management operations'],
            ['name' => 'Applications', 'description' => 'OAuth application management'],
            ['name' => 'Profile', 'description' => 'User profile management'],
            ['name' => 'MFA', 'description' => 'Multi-factor authentication'],
            ['name' => 'SSO', 'description' => 'Single sign-on operations'],
            ['name' => 'OAuth', 'description' => 'OAuth 2.0 endpoints'],
            ['name' => 'Enterprise', 'description' => 'Enterprise features'],
            ['name' => 'General', 'description' => 'General API operations'],
        ];
    }

    private function validateSpec(array $spec): int
    {
        $this->info('Validating OpenAPI specification...');

        $errors = [];

        if (empty($spec['paths'])) {
            $errors[] = 'No paths found in specification';
        }

        if (empty($spec['components']['schemas'])) {
            $errors[] = 'No schemas defined';
        }

        if (! empty($errors)) {
            $this->error('Validation failed:');
            foreach ($errors as $error) {
                $this->error('  - '.$error);
            }

            return self::FAILURE;
        }

        $this->info('✓ OpenAPI specification is valid');
        $this->info("  Paths: {$this->countPaths($spec['paths'])}");
        $this->info('  Schemas: '.count($spec['components']['schemas']));

        return self::SUCCESS;
    }

    private function countPaths(array $paths): int
    {
        $count = 0;
        foreach ($paths as $operations) {
            $count += count($operations);
        }

        return $count;
    }
}
