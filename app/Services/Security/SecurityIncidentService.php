<?php

namespace App\Services\Security;

use App\Models\SecurityIncident;
use App\Models\User;
use Illuminate\Support\Facades\Log;

class SecurityIncidentService
{
    /**
     * Create a security incident
     */
    public function createIncident(array $data): SecurityIncident
    {
        $incident = SecurityIncident::create([
            'type' => $data['type'],
            'severity' => $data['severity'],
            'ip_address' => $data['ip_address'],
            'user_agent' => $data['user_agent'] ?? null,
            'user_id' => $data['user_id'] ?? null,
            'endpoint' => $data['endpoint'] ?? null,
            'description' => $data['description'],
            'metadata' => $data['metadata'] ?? null,
            'status' => 'open',
            'detected_at' => now(),
        ]);

        $logLevel = match ($data['severity']) {
            'critical' => 'critical',
            'high' => 'error',
            'medium' => 'warning',
            default => 'info',
        };

        Log::channel('security')->{$logLevel}('Security incident detected', [
            'incident_id' => $incident->id,
            'type' => $incident->type,
            'severity' => $incident->severity,
            'ip_address' => $incident->ip_address,
        ]);

        // Notify admins for critical incidents
        if ($incident->severity === 'critical') {
            $this->notifyAdmins($incident);
        }

        return $incident;
    }

    /**
     * Resolve an incident
     */
    public function resolveIncident(int $incidentId, string $resolution, User $resolvedBy): bool
    {
        $incident = SecurityIncident::find($incidentId);

        if (! $incident) {
            return false;
        }

        $incident->update([
            'status' => 'resolved',
            'resolved_at' => now(),
            'resolution_notes' => $resolution,
        ]);

        Log::channel('security')->info('Security incident resolved', [
            'incident_id' => $incidentId,
            'resolved_by' => $resolvedBy->id,
        ]);

        return true;
    }

    /**
     * Get open incidents
     */
    public function getOpenIncidents(?string $severity = null)
    {
        $query = SecurityIncident::where('status', 'open');

        if ($severity) {
            $query->where('severity', $severity);
        }

        return $query->orderBy('detected_at', 'desc')->get();
    }

    /**
     * Get incident metrics for dashboard
     */
    public function getIncidentMetrics(): array
    {
        return [
            'total_open' => SecurityIncident::where('status', 'open')->count(),
            'critical_open' => SecurityIncident::where('status', 'open')
                ->where('severity', 'critical')->count(),
            'high_open' => SecurityIncident::where('status', 'open')
                ->where('severity', 'high')->count(),
            'incidents_today' => SecurityIncident::where('detected_at', '>=', now()->subDay())->count(),
            'incidents_this_week' => SecurityIncident::where('detected_at', '>=', now()->subWeek())->count(),
            'by_type' => SecurityIncident::where('detected_at', '>=', now()->subWeek())
                ->groupBy('type')
                ->selectRaw('type, count(*) as count')
                ->pluck('count', 'type'),
        ];
    }

    /**
     * Notify admins about critical incidents
     */
    protected function notifyAdmins(SecurityIncident $incident): void
    {
        // Get all super admins
        $admins = User::role('Super Admin')->get();

        // In production, send actual notifications
        // For now, just log
        Log::channel('security')->critical('CRITICAL SECURITY INCIDENT - Admin notification required', [
            'incident_id' => $incident->id,
            'type' => $incident->type,
            'ip_address' => $incident->ip_address,
            'description' => $incident->description,
        ]);
    }

    /**
     * Record action taken for incident
     */
    public function recordAction(int $incidentId, string $action): bool
    {
        $incident = SecurityIncident::find($incidentId);

        if (! $incident) {
            return false;
        }

        $incident->update(['action_taken' => $action]);

        return true;
    }
}
