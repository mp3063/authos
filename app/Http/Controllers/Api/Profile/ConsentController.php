<?php

namespace App\Http\Controllers\Api\Profile;

use App\Http\Controllers\Api\BaseApiController;
use App\Models\DataSubjectRequest;
use App\Models\UserConsent;
use App\Services\Compliance\ConsentTrackingService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ConsentController extends BaseApiController
{
    public function __construct(
        private readonly ConsentTrackingService $consentService,
    ) {
        $this->middleware('auth:api');
    }

    public function recordConsent(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'consent_type' => ['required', 'string', 'in:terms,privacy,marketing,data_processing'],
            'terms_version' => ['sometimes', 'string', 'max:32'],
        ]);

        try {
            $user = $this->getAuthenticatedUser();

            $consent = $this->consentService->recordConsent(
                $user,
                $validated['consent_type'],
                $validated['terms_version'] ?? null,
                $request->ip(),
            );

            return response()->json([
                'success' => true,
                'data' => ['consent' => $consent->only(['id', 'consent_type', 'terms_version', 'given_at'])],
                'message' => 'Consent recorded',
            ], 201);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function withdrawConsent(string $type): JsonResponse
    {
        if (! in_array($type, ['terms', 'privacy', 'marketing', 'data_processing'], true)) {
            return response()->json([
                'success' => false,
                'error' => 'invalid_consent_type',
            ], 400);
        }

        try {
            $user = $this->getAuthenticatedUser();
            $this->consentService->withdrawConsent($user, $type);

            return response()->json([
                'success' => true,
                'message' => 'Consent withdrawn',
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function listConsents(): JsonResponse
    {
        try {
            $user = $this->getAuthenticatedUser();

            $consents = UserConsent::query()
                ->where('user_id', $user->id)
                ->orderBy('consent_type')
                ->get(['id', 'consent_type', 'terms_version', 'given_at', 'withdrawn_at'])
                ->map(fn (UserConsent $c): array => [
                    'id' => $c->id,
                    'consent_type' => $c->consent_type,
                    'terms_version' => $c->terms_version,
                    'given_at' => $c->given_at?->toISOString(),
                    'withdrawn_at' => $c->withdrawn_at?->toISOString(),
                    'is_active' => $c->isActive(),
                ])
                ->all();

            return response()->json([
                'success' => true,
                'data' => ['consents' => $consents],
            ]);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }

    public function createDataRequest(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'request_type' => ['required', 'string', 'in:access,rectification,deletion,portability,restriction'],
            'notes' => ['sometimes', 'string', 'max:2000'],
        ]);

        try {
            $user = $this->getAuthenticatedUser();

            if ($user->organization_id === null) {
                return response()->json([
                    'success' => false,
                    'error' => 'no_organization',
                    'message' => 'User must belong to an organization to file a data subject request',
                ], 422);
            }

            $dsr = DataSubjectRequest::query()->create([
                'organization_id' => $user->organization_id,
                'user_id' => $user->id,
                'request_type' => $validated['request_type'],
                'status' => DataSubjectRequest::STATUS_PENDING,
                'requested_at' => now(),
                'notes' => $validated['notes'] ?? null,
            ]);

            return response()->json([
                'success' => true,
                'data' => ['request' => $dsr->only(['id', 'request_type', 'status', 'requested_at'])],
                'message' => 'Data subject request submitted',
            ], 201);
        } catch (Exception $e) {
            return $this->errorResponse($e->getMessage(), 500);
        }
    }
}
