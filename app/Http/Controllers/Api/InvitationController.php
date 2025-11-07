<?php

namespace App\Http\Controllers\Api;

use App\Http\Resources\InvitationResource;
use App\Models\Invitation;
use App\Services\InvitationService;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class InvitationController extends BaseApiController
{
    public function __construct(protected InvitationService $invitationService) {}

    /**
     * Send a new invitation to join an organization
     */
    public function store(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'email' => 'required|email|max:255',
            'role' => 'required|string|max:50',
            'metadata' => 'sometimes|array',
        ]);

        try {
            $invitation = $this->invitationService->sendInvitation(
                $organizationId,
                $request->email,
                $request->user(), // Pass user instance instead of ID
                $request->role,
                $request->get('metadata', []),
                true // Prevent duplicates for individual API calls
            );

            return $this->createdResourceResponse(
                $invitation->load(['organization', 'inviter']),
                InvitationResource::class,
                'Invitation sent successfully'
            );

        } catch (ValidationException $e) {
            return $this->validationErrorResponse($e->errors(), $e->getMessage());
        } catch (Exception $e) {
            return $this->errorResponse('Failed to send invitation: '.$e->getMessage());
        }
    }

    /**
     * List invitations for an organization
     */
    public function index(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'status' => 'sometimes|string|in:all,pending,expired,accepted',
            'per_page' => 'sometimes|integer|min:1|max:100',
        ]);

        try {
            $invitations = $this->invitationService->getOrganizationInvitations(
                $organizationId,
                $request->user(),
                $request->get('status', 'all')
            );

            $perPage = $request->get('per_page', 15);
            $page = $request->get('page', 1);

            // Manual pagination
            $total = $invitations->count();
            $paginatedInvitations = $invitations->forPage($page, $perPage)->values();

            return $this->successResponse(
                InvitationResource::collection($paginatedInvitations)->resolve(),
                null,
                200
            );

        } catch (Exception $e) {
            return $this->errorResponse('Failed to retrieve invitations: '.$e->getMessage(), 403);
        }
    }

    /**
     * View invitation details (public endpoint)
     */
    public function show(string $token): JsonResponse
    {
        $invitation = Invitation::where('token', $token)
            ->with(['organization', 'inviter'])
            ->first();

        if (! $invitation) {
            return response()->json([
                'message' => 'Invitation not found',
            ], 404);
        }

        if (! $invitation->isPending()) {
            $status = $invitation->isExpired() ? 'expired' : 'accepted';

            return response()->json([
                'message' => "This invitation has {$status}",
                'status' => $status,
            ], 400);
        }

        return response()->json([
            'invitation' => [
                'token' => $invitation->token,
                'email' => $invitation->email,
                'role' => $invitation->role,
                'organization' => [
                    'name' => $invitation->organization->name,
                    'slug' => $invitation->organization->slug,
                ],
                'inviter_name' => $invitation->inviter->name,
                'expires_at' => $invitation->expires_at->toISOString(),
            ],
        ]);
    }

    /**
     * Accept an invitation (public endpoint)
     */
    public function accept(Request $request, string $token): JsonResponse
    {
        if (! $request->user()) {
            return $this->errorResponse('Unauthenticated.', 401);
        }

        try {
            $accepted = $this->invitationService->acceptInvitationAsExistingUser(
                $token,
                $request->user()
            );

            if ($accepted) {
                return response()->json([
                    'message' => 'Invitation accepted successfully',
                ]);
            }

            return response()->json([
                'message' => 'Failed to accept invitation',
            ], 400);

        } catch (Exception $e) {
            return response()->json([
                'error' => $e->getMessage(),
            ], 400);
        }
    }

    /**
     * Decline an invitation (public endpoint)
     */
    public function decline(Request $request, string $token): JsonResponse
    {
        $request->validate([
            'reason' => 'sometimes|string|max:500',
        ]);

        try {
            $declined = $this->invitationService->declineInvitation(
                $token,
                $request->get('reason')
            );

            if ($declined) {
                return response()->json([
                    'message' => 'Invitation declined',
                ]);
            }

            return response()->json([
                'message' => 'Failed to decline invitation',
            ], 400);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to decline invitation',
            ], 400);
        }
    }

    /**
     * Cancel an invitation
     */
    public function destroy(Request $request, int $organizationId, int $invitationId): JsonResponse
    {
        try {
            $cancelled = $this->invitationService->cancelInvitation(
                $invitationId,
                $request->user()
            );

            if ($cancelled) {
                return response()->json([
                    'message' => 'Invitation cancelled successfully',
                ]);
            }

            return response()->json([
                'message' => 'Failed to cancel invitation',
            ], 400);

        } catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
            return response()->json([
                'message' => 'Invitation not found',
            ], 404);
        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to cancel invitation',
            ], 400);
        }
    }

    /**
     * Resend an invitation
     */
    public function resend(Request $request, int $organizationId, int $invitationId): JsonResponse
    {
        try {
            $invitation = $this->invitationService->resendInvitation(
                $invitationId,
                $request->user()
            );

            return response()->json([
                'message' => 'Invitation resent successfully',
                'invitation' => (new InvitationResource($invitation->load(['organization', 'inviter'])))->resolve(),
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to resend invitation',
            ], 400);
        }
    }

    /**
     * Bulk invite multiple users
     */
    public function bulkInvite(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'invitations' => 'required|array|min:1|max:50',
            'invitations.*.email' => 'required|email|max:255',
            'invitations.*.role' => 'required|string|max:50',
            'invitations.*.metadata' => 'sometimes|array',
        ]);

        try {
            $serviceResults = $this->invitationService->bulkInvite(
                $organizationId,
                $request->invitations,
                $request->user()
            );

            $successCount = count($serviceResults['successful']);
            $errorCount = count($serviceResults['failed']);

            return response()->json([
                'message' => "Bulk invite completed. {$successCount} sent, {$errorCount} failed.",
                'data' => [
                    'invited_count' => $successCount,
                    'failed_count' => $errorCount,
                    'invitations' => array_merge($serviceResults['successful'], $serviceResults['failed']),
                ],
            ], 201);

        } catch (ValidationException $e) {
            return $this->validationErrorResponse($e->errors(), $e->getMessage());
        } catch (Exception $e) {
            return $this->errorResponse('Bulk invite failed: '.$e->getMessage());
        }
    }
}
