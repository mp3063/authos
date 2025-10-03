<?php

namespace App\Http\Controllers\Api\Enterprise;

use App\Http\Controllers\Api\BaseApiController;
use App\Http\Requests\Enterprise\CustomDomainRequest;
use App\Models\CustomDomain;
use App\Services\DomainVerificationService;
use Exception;
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

            $domain = $this->domainService->createDomain($organization, $request->input('domain'));
            $instructions = $this->domainService->getVerificationInstructions($domain);

            return $this->createdResponse($instructions, 'Domain added successfully');
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function verify(int $domainId): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $domain = CustomDomain::where('id', $domainId)
                ->where('organization_id', $user->organization_id)
                ->firstOrFail();

            $verified = $this->domainService->verifyDomain($domain);

            if ($verified) {
                return $this->successResponse([
                    'verified' => true,
                    'domain' => $domain->fresh(),
                ], 'Domain verified successfully');
            }

            return $this->errorResponse('Verification failed. Please ensure DNS records are correctly configured.', 400);
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
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
