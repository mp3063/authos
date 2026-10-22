<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Events\DomainVerifiedEvent;
use App\Http\Controllers\Api\Traits\ApiControllerHelpers;
use App\Http\Requests\Enterprise\CustomDomainRequest;
use App\Models\CustomDomain;
use App\Services\DomainVerificationService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

class DomainController extends BaseController
{
    use ApiControllerHelpers;

    public function __construct(
        private readonly DomainVerificationService $domainService
    ) {
        $this->middleware('auth:api');
    }

    public function index(Request $request): JsonResponse
    {
        $this->authorize('viewAny', CustomDomain::class);

        try {
            $user = $this->getAuthenticatedUser();

            $domains = CustomDomain::query()
                ->when(! $user->isSuperAdmin(), fn ($query) => $query->where('organization_id', $user->organization_id))
                ->orderBy('created_at', 'desc')
                ->paginate($request->input('per_page', 15));

            return $this->paginatedResponse($domains, 'Domains retrieved successfully');
        } catch (Exception $e) {
            report($e);

            return $this->errorResponse('Failed to retrieve domains', 500);
        }
    }

    public function store(CustomDomainRequest $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();
            $organization = $user->organization;

            // Check if custom domains feature is enabled
            if (! ($organization->settings['enterprise_features']['custom_domains_enabled'] ?? true)) {
                return response()->json([
                    'success' => false,
                    'error' => 'feature_disabled',
                    'message' => 'Custom domains are disabled for this organization',
                ], 403);
            }

            $domainData = $this->domainService->addDomain($organization->id, $request->input('domain'));

            return $this->createdResponse($domainData, 'Domain added successfully');
        } catch (Exception $e) {
            if (str_contains($e->getMessage(), 'already exists')) {
                return $this->validationErrorResponse(['domain' => ['Domain already exists']], 'Domain already exists');
            }

            report($e);

            return $this->errorResponse('Failed to add domain', 500);
        }
    }

    public function verify(int $domainId): JsonResponse
    {
        $domain = $this->findAuthorizedDomain($domainId, 'update');

        if (! $domain) {
            return $this->notFoundResponse('Domain not found');
        }

        try {
            $result = $this->domainService->verifyDomain($domainId);

            $domain = $domain->fresh();
            if ($domain && $domain->isVerified()) {
                DomainVerifiedEvent::dispatch($domain);
            }

            return $this->successResponse($result, $result['message'] ?? 'Domain verification completed');
        } catch (Exception $e) {
            report($e);

            return $this->errorResponse('Failed to verify domain', 500);
        }
    }

    public function destroy(int $domainId): JsonResponse
    {
        $domain = $this->findAuthorizedDomain($domainId, 'delete');

        if (! $domain) {
            return $this->notFoundResponse('Domain not found');
        }

        try {
            $this->domainService->removeDomain($domain);

            return $this->deletedResponse('Domain deleted successfully');
        } catch (Exception $e) {
            report($e);

            return $this->errorResponse('Failed to delete domain', 500);
        }
    }

    private function findAuthorizedDomain(int $domainId, string $ability): ?CustomDomain
    {
        $user = $this->getAuthenticatedUser();

        $domain = CustomDomain::query()
            ->when(! $user->isSuperAdmin(), fn ($query) => $query
                ->whereNotNull('organization_id')
                ->where('organization_id', $user->organization_id))
            ->find($domainId);

        $this->authorize($ability, $domain ?? new CustomDomain(['organization_id' => $user->organization_id]));

        return $domain;
    }
}
