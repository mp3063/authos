<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Invitation;
use App\Models\Organization;
use App\Services\InvitationService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Validation\ValidationException;
use Exception;

class InvitationController extends Controller
{
    protected InvitationService $invitationService;

    public function __construct(InvitationService $invitationService)
    {
        $this->invitationService = $invitationService;
    }

    /**
     * Send a new invitation to join an organization
     */
    public function store(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'email' => 'required|email|max:255',
            'role' => 'required|string|max:50',
            'metadata' => 'sometimes|array'
        ]);

        try {
            $invitation = $this->invitationService->sendInvitation(
                $organizationId,
                $request->email,
                $request->user()->id,
                $request->role,
                $request->get('metadata', [])
            );

            return response()->json([
                'message' => 'Invitation sent successfully',
                'invitation' => $invitation->load(['organization', 'inviter'])
            ], 201);

        } catch (ValidationException $e) {
            return response()->json([
                'message' => 'Validation failed',
                'errors' => $e->errors()
            ], 422);
        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to send invitation',
                'error' => $e->getMessage()
            ], 400);
        }
    }

    /**
     * List invitations for an organization
     */
    public function index(Request $request, int $organizationId): JsonResponse
    {
        $request->validate([
            'status' => 'sometimes|string|in:all,pending,expired,accepted',
            'per_page' => 'sometimes|integer|min:1|max:100'
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

            return response()->json([
                'data' => $paginatedInvitations,
                'meta' => [
                    'total' => $total,
                    'per_page' => $perPage,
                    'current_page' => $page,
                    'last_page' => ceil($total / $perPage)
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to retrieve invitations',
                'error' => $e->getMessage()
            ], 403);
        }
    }

    /**
     * View invitation details (public endpoint)
     */
    public function show(string $token): JsonResponse
    {
        $invitation = Invitation::where('token', $token)
            ->with(['organization'])
            ->first();

        if (!$invitation) {
            return response()->json([
                'message' => 'Invitation not found'
            ], 404);
        }

        if (!$invitation->isPending()) {
            $status = $invitation->isExpired() ? 'expired' : 'accepted';
            return response()->json([
                'message' => "This invitation has {$status}",
                'status' => $status
            ], 400);
        }

        return response()->json([
            'invitation' => [
                'token' => $invitation->token,
                'email' => $invitation->email,
                'role' => $invitation->role,
                'organization' => [
                    'name' => $invitation->organization->name,
                    'slug' => $invitation->organization->slug
                ],
                'inviter_name' => $invitation->inviter->name,
                'expires_at' => $invitation->expires_at->toISOString()
            ]
        ]);
    }

    /**
     * Accept an invitation (public endpoint)
     */
    public function accept(Request $request, string $token): JsonResponse
    {
        if (!$request->user()) {
            return response()->json([
                'message' => 'Authentication required to accept invitation'
            ], 401);
        }

        try {
            $accepted = $this->invitationService->acceptInvitation(
                $token,
                $request->user()
            );

            if ($accepted) {
                return response()->json([
                    'message' => 'Invitation accepted successfully'
                ]);
            }

            return response()->json([
                'message' => 'Failed to accept invitation'
            ], 400);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to accept invitation',
                'error' => $e->getMessage()
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
                    'message' => 'Invitation cancelled successfully'
                ]);
            }

            return response()->json([
                'message' => 'Failed to cancel invitation'
            ], 400);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to cancel invitation',
                'error' => $e->getMessage()
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
                'invitation' => $invitation->load(['organization', 'inviter'])
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Failed to resend invitation',
                'error' => $e->getMessage()
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
            'invitations.*.metadata' => 'sometimes|array'
        ]);

        try {
            $results = $this->invitationService->bulkInvite(
                $organizationId,
                $request->invitations,
                $request->user()->id
            );

            $successCount = count(array_filter($results, fn($r) => $r['status'] === 'success'));
            $errorCount = count($results) - $successCount;

            return response()->json([
                'message' => "Bulk invite completed. {$successCount} sent, {$errorCount} failed.",
                'results' => $results,
                'summary' => [
                    'total' => count($results),
                    'successful' => $successCount,
                    'failed' => $errorCount
                ]
            ]);

        } catch (Exception $e) {
            return response()->json([
                'message' => 'Bulk invite failed',
                'error' => $e->getMessage()
            ], 400);
        }
    }
}
