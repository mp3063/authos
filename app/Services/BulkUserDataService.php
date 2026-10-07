<?php

namespace App\Services;

use App\Exports\UsersExport;
use App\Imports\UsersImport;
use App\Models\Organization;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Storage;
use League\Csv\Writer;
use Maatwebsite\Excel\Facades\Excel;
use SplTempFileObject;

class BulkUserDataService
{
    public function __construct(protected InvitationService $invitationService) {}

    /**
     * Export users to CSV or Excel format
     */
    public function exportUsers(Organization $organization, string $format = 'csv', array $filters = []): string
    {
        $result = $this->exportUsersExtended($organization, ['format' => $format] + $filters);

        return $result['download_url'];
    }

    /**
     * Export users to CSV or Excel format (extended method)
     */
    public function exportUsersExtended(Organization $organization, array $options): array
    {
        $format = $options['format'] ?? 'csv';
        $includeRoles = $options['include_roles'] ?? true;
        $includeApplications = $options['include_applications'] ?? true;
        $includeActivity = $options['include_activity'] ?? false;

        // Build user query - filter by organization
        $query = User::where('organization_id', $organization->id);

        // Optionally filter by applications if specified
        if (! empty($options['application_ids'])) {
            $query->whereHas('applications', function ($subQuery) use ($options) {
                $subQuery->whereIn('application_id', $options['application_ids']);
            });
        }

        if (! empty($options['date_from']) && ! empty($options['date_to'])) {
            $query->whereBetween('created_at', [
                Carbon::parse($options['date_from'])->startOfDay(),
                Carbon::parse($options['date_to'])->endOfDay(),
            ]);
        }

        // Load relationships
        $with = [];
        if ($includeRoles) {
            $with[] = 'roles';
            $with[] = 'customRoles';
        }
        if ($includeApplications) {
            $with[] = 'applications';
        }

        $users = $query->with($with)->get();

        // Generate filename
        $filename = sprintf(
            'users_export_%s_%s.%s',
            $organization->slug,
            now()->format('Y-m-d_H-i-s'),
            $format
        );

        // Export using Laravel Excel or CSV
        $exportPath = 'exports/'.$filename;

        if ($format === 'xlsx') {
            Excel::store(new UsersExport($users, $includeRoles, $includeApplications, $includeActivity), $exportPath);
        } else {
            $this->generateCsvExport($users, $organization, $exportPath, $includeRoles, $includeApplications);
        }

        $downloadUrl = Storage::url($exportPath);

        return [
            'download_url' => $downloadUrl,
            'filename' => $filename,
            'users_count' => $users->count(),
            'format' => $format,
            'expires_at' => now()->addHours(24), // Files expire in 24 hours
        ];
    }

    /**
     * Import users from CSV or Excel file
     */
    public function importUsers(UploadedFile $file, Organization $organization, string $defaultRole): array
    {
        return $this->importUsersExtended($file, $organization, ['default_role' => $defaultRole], auth()->user() ?? User::first());
    }

    /**
     * Import users from CSV or Excel file (extended method)
     */
    public function importUsersExtended(
        UploadedFile $file,
        Organization $organization,
        array $options,
        User $currentUser
    ): array {
        $sendInvitations = $options['send_invitations'] ?? false;
        $defaultRole = $options['default_role'] ?? 'user';
        $updateExisting = $options['update_existing'] ?? false;

        $import = new UsersImport(
            $organization,
            $currentUser,
            $sendInvitations,
            $defaultRole,
            $updateExisting,
            $this->invitationService
        );

        Excel::import($import, $file);

        return $import->getResults();
    }

    /**
     * Generate CSV export
     */
    private function generateCsvExport(Collection $users, Organization $organization, string $exportPath, bool $includeRoles, bool $includeApplications): void
    {
        $csv = Writer::createFromFileObject(new SplTempFileObject);

        // Headers
        $headers = ['ID', 'Name', 'Email', 'Created At', 'Last Login', 'MFA Enabled', 'Status'];
        if ($includeRoles) {
            $headers[] = 'Roles';
            $headers[] = 'Custom Roles';
        }
        if ($includeApplications) {
            $headers[] = 'Applications';
        }

        $csv->insertOne($headers);

        // Data rows
        foreach ($users as $user) {
            $row = [
                $user->id,
                $user->name,
                $user->email,
                $user->created_at->format('Y-m-d H:i:s'),
                $user->last_login_at ? $user->last_login_at->format('Y-m-d H:i:s') : 'Never',
                $user->hasMfaEnabled() ? 'Yes' : 'No',
                $user->is_active ? 'Active' : 'Inactive',
            ];

            if ($includeRoles) {
                $row[] = $user->roles->pluck('name')->join(', ');
                $row[] = $user->customRoles->pluck('name')->join(', ');
            }

            if ($includeApplications) {
                $row[] = $user->applications->where('organization_id', $organization->id)->pluck('name')->join(', ');
            }

            $csv->insertOne($row);
        }

        $csvContent = $csv->toString();
        Storage::put($exportPath, $csvContent);
    }
}
