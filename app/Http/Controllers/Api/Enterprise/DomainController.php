<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Events\DomainVerifiedEvent;
use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\CustomDomainRequest;
use App\Models\CustomDomain;
use App\Services\DomainVerificationService;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DomainController extends BaseApiController
{
    public function __construct(
        private readonly DomainVerificationService $domainService
    ) {
        $this->middleware('auth:api');
    }

    public function index(Request $request): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $domains = CustomDomain::where('organization_id', $user->organization_id)
                ->orderBy('created_at', 'desc')
                ->paginate($request->input('per_page', 15));

            return $this->paginatedResponse($domains, 'Domains retrieved successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
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
                return $this->validationErrorResponse($e->getMessage(), ['domain' => [$e->getMessage()]]);
            }

            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function verify(int $domainId): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            // Verify domain belongs to user's organization
            $domain = CustomDomain::where('id', $domainId)
                ->where('organization_id', $user->organization_id)
                ->firstOrFail();

            $result = $this->domainService->verifyDomain($domainId);

            $domain = $domain->fresh();
            if ($domain && $domain->isVerified()) {
                DomainVerifiedEvent::dispatch($domain);
            }

            return $this->successResponse($result, $result['message'] ?? 'Domain verification completed');
        } catch (ModelNotFoundException $e) {
            return $this->notFoundResponse('Domain not found');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function destroy(int $domainId): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $domain = CustomDomain::where('id', $domainId)
                ->where('organization_id', $user->organization_id)
                ->firstOrFail();

            $this->domainService->removeDomain($domain);

            return $this->deletedResponse('Domain deleted successfully');
        } catch (ModelNotFoundException $e) {
            return $this->notFoundResponse('Domain not found');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
