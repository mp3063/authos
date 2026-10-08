<?php

namespace App\Policies;

use App\Models\ScheduledComplianceReport;
use App\Models\User;
use App\Policies\Concerns\ChecksOrganizationPermissions;

class ScheduledComplianceReportPolicy
{
    use ChecksOrganizationPermissions;

    /**
     * Determine whether the user can view any models.
     */
    public function viewAny(User $user): bool
    {
        return $this->permits($user, 'auth_logs.read', $user->organization_id);
    }

    /**
     * Determine whether the user can view the model.
     */
    public function view(User $user, ScheduledComplianceReport $scheduledComplianceReport): bool
    {
        return $this->permits($user, 'auth_logs.read', $scheduledComplianceReport->organization_id);
    }

    /**
     * Determine whether the user can create models.
     */
    public function create(User $user): bool
    {
        return $this->permits($user, 'auth_logs.export', $user->organization_id);
    }

    /**
     * Determine whether the user can update the model.
     */
    public function update(User $user, ScheduledComplianceReport $scheduledComplianceReport): bool
    {
        return $this->permits($user, 'auth_logs.export', $scheduledComplianceReport->organization_id);
    }

    /**
     * Determine whether the user can delete the model.
     */
    public function delete(User $user, ScheduledComplianceReport $scheduledComplianceReport): bool
    {
        return $this->permits($user, 'auth_logs.export', $scheduledComplianceReport->organization_id);
    }

    /**
     * Determine whether the user can bulk delete models.
     */
    public function deleteAny(User $user): bool
    {
        return $this->permits($user, 'auth_logs.export', $user->organization_id);
    }

    /**
     * Determine whether the user can restore the model.
     */
    public function restore(User $user, ScheduledComplianceReport $scheduledComplianceReport): bool
    {
        return $this->delete($user, $scheduledComplianceReport);
    }

    /**
     * Determine whether the user can permanently delete the model.
     */
    public function forceDelete(User $user): bool
    {
        return $user->isSuperAdmin();
    }
}
