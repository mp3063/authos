<?php

namespace App\Services\Database;

use App\Models\Organization;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * Optimized audit and security log queries
 */
class AuditQueryService
{
    /**
     * Get security events with optimized filtering
     */
    public function getSecurityEvents(Organization $organization, array $filters = []): array
    {
        $startDate = isset($filters['start_date'])
            ? Carbon::parse($filters['start_date'])->startOfDay()
            : Carbon::now()->subDays(7)->startOfDay();

        $endDate = isset($filters['end_date'])
            ? Carbon::parse($filters['end_date'])->endOfDay()
            : Carbon::now()->endOfDay();

        $query = '
            SELECT 
                al.id,
                al.event,
                al.ip_address,
                al.user_agent,
                al.created_at,
                u.name as user_name,
                u.email as user_email,
                u.id as user_id,
                a.name as application_name,
                a.id as application_id,
                al.metadata,
                al.risk_score
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id
            LEFT JOIN applications a ON al.application_id = a.id
            WHERE u.organization_id = ?
                AND al.created_at BETWEEN ? AND ?
        ';

        $params = [$organization->id, $startDate, $endDate];

        // Add event filter
        if (! empty($filters['events'])) {
            $eventPlaceholders = str_repeat('?,', count($filters['events']) - 1).'?';
            $query .= " AND al.event IN ($eventPlaceholders)";
            $params = array_merge($params, $filters['events']);
        }

        // Add risk level filter
        if (! empty($filters['min_risk_score'])) {
            $query .= ' AND al.risk_score >= ?';
            $params[] = $filters['min_risk_score'];
        }

        // Add IP address filter
        if (! empty($filters['ip_address'])) {
            $query .= ' AND al.ip_address = ?';
            $params[] = $filters['ip_address'];
        }

        // Add user filter
        if (! empty($filters['user_id'])) {
            $query .= ' AND u.id = ?';
            $params[] = $filters['user_id'];
        }

        $query .= ' ORDER BY al.created_at DESC, al.risk_score DESC LIMIT ?';
        $params[] = $filters['limit'] ?? 1000;

        $results = DB::select($query, $params);

        return array_map(function ($row) {
            return [
                'id' => (int) $row->id,
                'event' => $row->event,
                'ip_address' => $row->ip_address,
                'user_agent' => $row->user_agent,
                'created_at' => $row->created_at,
                'user' => [
                    'id' => (int) $row->user_id,
                    'name' => $row->user_name,
                    'email' => $row->user_email,
                ],
                'application' => $row->application_id ? [
                    'id' => (int) $row->application_id,
                    'name' => $row->application_name,
                ] : null,
                'metadata' => json_decode($row->metadata, true) ?? [],
                'risk_score' => (float) $row->risk_score,
                'severity' => $this->calculateSeverity($row->event, $row->risk_score),
            ];
        }, $results);
    }

    /**
     * Get failed login attempts with pattern analysis
     */
    public function getFailedLoginAnalysis(Organization $organization, int $hours = 24): array
    {
        $startTime = Carbon::now()->subHours($hours);

        $results = DB::select('
            SELECT 
                al.ip_address,
                al.user_agent,
                u.email as target_email,
                u.name as target_name,
                u.id as user_id,
                COUNT(*) as attempt_count,
                MIN(al.created_at) as first_attempt,
                MAX(al.created_at) as latest_attempt,
                COUNT(DISTINCT u.id) as unique_targets,
                AVG(al.risk_score) as avg_risk_score,
                GROUP_CONCAT(DISTINCT a.name SEPARATOR ", ") as targeted_applications
            FROM authentication_logs al
            JOIN users u ON al.user_id = u.id
            LEFT JOIN applications a ON al.application_id = a.id
            WHERE u.organization_id = ?
                AND al.event = "login_failed"
                AND al.created_at >= ?
            GROUP BY al.ip_address, al.user_agent, u.id, u.email, u.name
            HAVING attempt_count >= 3
            ORDER BY attempt_count DESC, avg_risk_score DESC, latest_attempt DESC
        ', [$organization->id, $startTime]);

        // Group by IP address for pattern analysis
        $ipPatterns = [];
        foreach ($results as $row) {
            $ip = $row->ip_address;
            if (! isset($ipPatterns[$ip])) {
                $ipPatterns[$ip] = [
                    'ip_address' => $ip,
                    'total_attempts' => 0,
                    'unique_targets' => 0,
                    'unique_user_agents' => [],
                    'targeted_users' => [],
                    'first_attempt' => null,
                    'latest_attempt' => null,
                    'attack_pattern' => 'unknown',
                ];
            }

            $ipPatterns[$ip]['total_attempts'] += $row->attempt_count;
            $ipPatterns[$ip]['unique_targets'] = max($ipPatterns[$ip]['unique_targets'], $row->unique_targets);
            $ipPatterns[$ip]['unique_user_agents'][] = $row->user_agent;
            $ipPatterns[$ip]['targeted_users'][] = [
                'user_id' => (int) $row->user_id,
                'email' => $row->target_email,
                'name' => $row->target_name,
                'attempts' => (int) $row->attempt_count,
            ];

            if (! $ipPatterns[$ip]['first_attempt'] || $row->first_attempt < $ipPatterns[$ip]['first_attempt']) {
                $ipPatterns[$ip]['first_attempt'] = $row->first_attempt;
            }
            if (! $ipPatterns[$ip]['latest_attempt'] || $row->latest_attempt > $ipPatterns[$ip]['latest_attempt']) {
                $ipPatterns[$ip]['latest_attempt'] = $row->latest_attempt;
            }
        }

        // Analyze attack patterns
        foreach ($ipPatterns as &$pattern) {
            $pattern['unique_user_agents'] = array_unique($pattern['unique_user_agents']);
            $pattern['unique_user_agent_count'] = count($pattern['unique_user_agents']);

            // Determine attack pattern
            if ($pattern['unique_targets'] > 5 && $pattern['unique_user_agent_count'] == 1) {
                $pattern['attack_pattern'] = 'credential_stuffing';
            } elseif ($pattern['unique_targets'] == 1 && $pattern['total_attempts'] > 10) {
                $pattern['attack_pattern'] = 'brute_force';
            } elseif ($pattern['unique_user_agent_count'] > 3) {
                $pattern['attack_pattern'] = 'distributed';
            } else {
                $pattern['attack_pattern'] = 'targeted';
            }

            $pattern['risk_level'] = $this->calculateRiskLevel($pattern);
        }

        return array_values($ipPatterns);
    }

    /**
     * Get user behavior anomalies
     */
    public function getUserBehaviorAnomalies(Organization $organization, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days);

        $results = DB::select('
            SELECT 
                u.id,
                u.name,
                u.email,
                COUNT(DISTINCT al.ip_address) as unique_ips,
                COUNT(DISTINCT al.user_agent) as unique_agents,
                COUNT(DISTINCT DATE(al.created_at)) as active_days,
                COUNT(*) as total_events,
                COUNT(CASE WHEN al.event = "login_failed" THEN 1 END) as failed_attempts,
                COUNT(CASE WHEN al.event = "login_success" THEN 1 END) as successful_logins,
                COUNT(DISTINCT al.application_id) as applications_accessed,
                MIN(al.created_at) as first_activity,
                MAX(al.created_at) as latest_activity,
                AVG(al.risk_score) as avg_risk_score,
                STDDEV(al.risk_score) as risk_score_variance
            FROM users u
            JOIN authentication_logs al ON u.id = al.user_id
            WHERE u.organization_id = ?
                AND al.created_at >= ?
            GROUP BY u.id, u.name, u.email
            HAVING unique_ips > 5 OR unique_agents > 3 OR failed_attempts > 20 OR avg_risk_score > 3.0
            ORDER BY avg_risk_score DESC, unique_ips DESC
        ', [$organization->id, $startDate]);

        return array_map(function ($row) {
            $anomalyScore = 0;
            $anomalies = [];

            // Check for various anomalies
            if ($row->unique_ips > 10) {
                $anomalyScore += 3;
                $anomalies[] = 'multiple_ip_addresses';
            }
            if ($row->unique_agents > 5) {
                $anomalyScore += 2;
                $anomalies[] = 'multiple_user_agents';
            }
            if ($row->failed_attempts > 50) {
                $anomalyScore += 4;
                $anomalies[] = 'excessive_failed_attempts';
            }
            if ($row->avg_risk_score > 4.0) {
                $anomalyScore += 3;
                $anomalies[] = 'high_risk_activities';
            }
            if ($row->risk_score_variance > 2.0) {
                $anomalyScore += 2;
                $anomalies[] = 'inconsistent_behavior';
            }

            return [
                'user' => [
                    'id' => (int) $row->id,
                    'name' => $row->name,
                    'email' => $row->email,
                ],
                'metrics' => [
                    'unique_ips' => (int) $row->unique_ips,
                    'unique_agents' => (int) $row->unique_agents,
                    'active_days' => (int) $row->active_days,
                    'total_events' => (int) $row->total_events,
                    'failed_attempts' => (int) $row->failed_attempts,
                    'successful_logins' => (int) $row->successful_logins,
                    'applications_accessed' => (int) $row->applications_accessed,
                    'avg_risk_score' => round((float) $row->avg_risk_score, 2),
                    'risk_score_variance' => round((float) $row->risk_score_variance, 2),
                ],
                'analysis' => [
                    'anomaly_score' => $anomalyScore,
                    'anomalies' => $anomalies,
                    'risk_level' => $this->calculateUserRiskLevel($anomalyScore),
                    'first_activity' => $row->first_activity,
                    'latest_activity' => $row->latest_activity,
                ],
            ];
        }, $results);
    }

    /**
     * Get application access audit trail
     */
    public function getApplicationAccessAudit(Organization $organization, ?int $applicationId = null, int $days = 30): array
    {
        $startDate = Carbon::now()->subDays($days);

        $query = '
            SELECT 
                a.id as app_id,
                a.name as app_name,
                u.id as user_id,
                u.name as user_name,
                u.email as user_email,
                ua.granted_at,
                ua.granted_by,
                ua.last_login_at,
                ua.login_count,
                granter.name as granted_by_name,
                COUNT(al.id) as auth_events_count
            FROM applications a
            JOIN user_applications ua ON a.id = ua.application_id
            JOIN users u ON ua.user_id = u.id
            LEFT JOIN users granter ON ua.granted_by = granter.id
            LEFT JOIN authentication_logs al ON u.id = al.user_id 
                AND a.id = al.application_id 
                AND al.created_at >= ?
            WHERE a.organization_id = ?
        ';

        $params = [$startDate, $organization->id];

        if ($applicationId) {
            $query .= ' AND a.id = ?';
            $params[] = $applicationId;
        }

        $query .= '
            GROUP BY a.id, a.name, u.id, u.name, u.email, ua.granted_at, ua.granted_by, ua.last_login_at, ua.login_count, granter.name
            ORDER BY ua.granted_at DESC
        ';

        $results = DB::select($query, $params);

        return array_map(function ($row) {
            return [
                'application' => [
                    'id' => (int) $row->app_id,
                    'name' => $row->app_name,
                ],
                'user' => [
                    'id' => (int) $row->user_id,
                    'name' => $row->user_name,
                    'email' => $row->user_email,
                ],
                'access_details' => [
                    'granted_at' => $row->granted_at,
                    'granted_by' => $row->granted_by ? [
                        'id' => (int) $row->granted_by,
                        'name' => $row->granted_by_name,
                    ] : null,
                    'last_login_at' => $row->last_login_at,
                    'total_login_count' => (int) $row->login_count,
                    'recent_auth_events' => (int) $row->auth_events_count,
                ],
            ];
        }, $results);
    }

    /**
     * Calculate event severity
     */
    private function calculateSeverity(string $event, float $riskScore): string
    {
        $highRiskEvents = ['login_failed', 'mfa_failed', 'suspicious_activity'];
        $mediumRiskEvents = ['logout', 'password_changed', 'mfa_challenge_sent'];

        if (in_array($event, $highRiskEvents) || $riskScore >= 4.0) {
            return 'high';
        } elseif (in_array($event, $mediumRiskEvents) || $riskScore >= 2.0) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Calculate risk level for IP patterns
     */
    private function calculateRiskLevel(array $pattern): string
    {
        $score = 0;

        if ($pattern['total_attempts'] > 100) {
            $score += 3;
        } elseif ($pattern['total_attempts'] > 50) {
            $score += 2;
        } elseif ($pattern['total_attempts'] > 20) {
            $score += 1;
        }

        if ($pattern['unique_targets'] > 10) {
            $score += 3;
        } elseif ($pattern['unique_targets'] > 5) {
            $score += 2;
        } elseif ($pattern['unique_targets'] > 2) {
            $score += 1;
        }

        if ($pattern['unique_user_agent_count'] > 5) {
            $score += 2;
        } elseif ($pattern['unique_user_agent_count'] > 3) {
            $score += 1;
        }

        if ($score >= 6) {
            return 'critical';
        } elseif ($score >= 4) {
            return 'high';
        } elseif ($score >= 2) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    /**
     * Calculate user risk level
     */
    private function calculateUserRiskLevel(int $anomalyScore): string
    {
        if ($anomalyScore >= 8) {
            return 'critical';
        } elseif ($anomalyScore >= 5) {
            return 'high';
        } elseif ($anomalyScore >= 3) {
            return 'medium';
        } else {
            return 'low';
        }
    }
}
