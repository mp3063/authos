<?php

namespace App\Models\Concerns;

use App\Models\AuditExport;
use App\Models\AuthenticationLog;
use App\Models\ComplianceReport;
use App\Models\DataSubjectRequest;
use App\Models\ScheduledComplianceReport;
use App\Models\SecurityIncident;
use App\Models\User;
use App\Models\UserConsent;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasManyThrough;

trait HasComplianceRecords
{
    public function auditExports(): HasMany
    {
        return $this->hasMany(AuditExport::class);
    }

    public function securityIncidents(): HasManyThrough
    {
        return $this->hasManyThrough(SecurityIncident::class, User::class);
    }

    public function securityIncidentsDirect(): HasMany
    {
        return $this->hasMany(SecurityIncident::class);
    }

    public function complianceReports(): HasMany
    {
        return $this->hasMany(ComplianceReport::class);
    }

    public function scheduledComplianceReports(): HasMany
    {
        return $this->hasMany(ScheduledComplianceReport::class);
    }

    public function userConsents(): HasMany
    {
        return $this->hasMany(UserConsent::class);
    }

    public function dataSubjectRequests(): HasMany
    {
        return $this->hasMany(DataSubjectRequest::class);
    }

    public function authenticationLogs(): HasManyThrough
    {
        return $this->hasManyThrough(AuthenticationLog::class, User::class);
    }
}
