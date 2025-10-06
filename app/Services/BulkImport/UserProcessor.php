<?php

namespace App\Services\BulkImport;

use App\Models\Invitation;
use App\Models\User;
use App\Services\BulkImport\DTOs\ImportOptions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class UserProcessor
{
    public function __construct(
        private readonly ImportOptions $options
    ) {}

    /**
     * Process a single user record
     */
    public function process(array $record): array
    {
        try {
            $user = $this->createOrUpdateUser($record);

            // Assign role if specified
            if (! empty($record['role'])) {
                $this->assignRole($user, $record['role']);
            }

            // Send invitation if requested
            if ($this->options->sendInvitations && ! $user->wasRecentlyCreated) {
                $this->sendInvitation($user);
            }

            return [
                'success' => true,
                'user_id' => $user->id,
                'action' => $user->wasRecentlyCreated ? 'created' : 'updated',
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Create or update a user
     */
    private function createOrUpdateUser(array $record): User
    {
        $email = $record['email'];
        $existingUser = User::where('email', $email)
            ->when($this->options->organizationId, function ($query) {
                $query->where('organization_id', $this->options->organizationId);
            })
            ->first();

        // Update existing user
        if ($existingUser && $this->options->updateExisting) {
            $updateData = [
                'name' => $record['name'],
            ];

            // Only update password if provided
            if (! empty($record['password'])) {
                $updateData['password'] = $record['password'];
            }

            $existingUser->update($updateData);

            return $existingUser;
        }

        // Create new user
        if (! $existingUser) {
            $userData = [
                'email' => $email,
                'name' => $record['name'],
                'organization_id' => $record['organization_id'] ?? $this->options->organizationId,
                'is_active' => true,
            ];

            // Handle password
            if (! empty($record['password'])) {
                $userData['password'] = $record['password'];
            } elseif ($this->options->autoGeneratePasswords) {
                $userData['password'] = Str::random(16);
            }

            // Set email as verified if importing
            $userData['email_verified_at'] = now();

            return User::create($userData);
        }

        // If we get here, user exists but updating is not allowed
        throw new \RuntimeException("User with email {$email} already exists");
    }

    /**
     * Assign role to user
     */
    private function assignRole(User $user, string $roleName): void
    {
        try {
            // Set organization context
            $user->setPermissionsTeamId($user->organization_id);

            // Check if user already has the role
            if (! $user->hasRole($roleName)) {
                // Use the organization-aware role assignment
                $user->assignOrganizationRole($roleName, $user->organization_id);
            }
        } catch (\Exception $e) {
            throw new \RuntimeException('Failed to assign role: '.$e->getMessage());
        }
    }

    /**
     * Send invitation to user
     */
    private function sendInvitation(User $user): void
    {
        try {
            // Create invitation record
            Invitation::create([
                'email' => $user->email,
                'organization_id' => $user->organization_id,
                'invited_by' => auth()->id(),
                'token' => Str::random(32),
                'expires_at' => now()->addDays(7),
                'role' => 'User', // Default role
            ]);

            // Note: Actual email sending would be handled by an event listener
            // or notification system in production
        } catch (\Exception $e) {
            // Don't fail the import if invitation fails
            logger()->warning("Failed to send invitation to {$user->email}: ".$e->getMessage());
        }
    }

    /**
     * Process records in batches for better performance
     */
    public function processBatch(array $records): array
    {
        $results = [
            'successful' => 0,
            'failed' => 0,
            'created' => 0,
            'updated' => 0,
            'errors' => [],
        ];

        DB::beginTransaction();

        try {
            foreach ($records as $record) {
                $result = $this->process($record['data']);

                if ($result['success']) {
                    $results['successful']++;
                    if ($result['action'] === 'created') {
                        $results['created']++;
                    } else {
                        $results['updated']++;
                    }
                } else {
                    $results['failed']++;
                    $results['errors'][] = [
                        'row' => $record['row'],
                        'error' => $result['error'],
                    ];
                }
            }

            DB::commit();
        } catch (\Exception $e) {
            DB::rollBack();
            throw new \RuntimeException('Batch processing failed: '.$e->getMessage());
        }

        return $results;
    }
}
