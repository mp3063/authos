<?php

namespace App\Filament\Widgets;

use App\Models\Application;
use App\Models\User;
use Filament\Facades\Filament;
use Filament\Widgets\Widget;
use Illuminate\Support\Facades\Cache;

class ApplicationAccessMatrix extends Widget
{
    protected string $view = 'filament.widgets.application-access-matrix';

    protected static ?string $heading = 'Application Access Matrix';

    protected static ?int $sort = 3;

    protected int|string|array $columnSpan = 'full';

    protected static bool $isLazy = true;

    public function getViewData(): array
    {
        $user = Filament::auth()->user();

        // Only show for organization owners/admins
        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return [
                'users' => collect(),
                'applications' => collect(),
                'accessMatrix' => [],
                'hasPermission' => false,
            ];
        }

        $organizationId = $user->organization_id;
        $cacheKey = "access_matrix_{$organizationId}";

        $data = Cache::remember($cacheKey, 300, function () use ($organizationId) {
            // Get organization applications
            $applications = Application::where('organization_id', $organizationId)
                ->where('is_active', true)
                ->orderBy('name')
                ->get();

            // Get users who have access to any application in this organization
            $users = User::whereHas('applications', function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId);
            })->with(['applications' => function ($query) use ($organizationId) {
                $query->where('organization_id', $organizationId)
                    ->withPivot(['last_login_at', 'login_count', 'created_at']);
            }])
                ->orderBy('name')
                ->get();

            // Build access matrix
            $accessMatrix = [];
            foreach ($users as $user) {
                $accessMatrix[$user->id] = [];
                foreach ($applications as $app) {
                    $userApp = $user->applications->firstWhere('id', $app->id);
                    $accessMatrix[$user->id][$app->id] = [
                        'hasAccess' => $userApp !== null,
                        'lastLogin' => $userApp?->pivot?->last_login_at,
                        'loginCount' => $userApp?->pivot?->login_count ?? 0,
                        'grantedAt' => $userApp?->pivot?->created_at,
                    ];
                }
            }

            return [
                'users' => $users,
                'applications' => $applications,
                'accessMatrix' => $accessMatrix,
            ];
        });

        return array_merge($data, ['hasPermission' => true]);
    }

    public function grantAccess(int $userId, int $applicationId): void
    {
        $user = Filament::auth()->user();

        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return;
        }

        $targetUser = User::find($userId);
        $application = Application::find($applicationId);

        if ($targetUser && $application && $application->organization_id === $user->organization_id) {
            $targetUser->applications()->syncWithoutDetaching([
                $applicationId => [
                    'created_at' => now(),
                    'updated_at' => now(),
                ],
            ]);

            // Clear cache
            Cache::forget("access_matrix_{$user->organization_id}");

            // Refresh the component
            $this->dispatch('$refresh');
        }
    }

    public function revokeAccess(int $userId, int $applicationId): void
    {
        $user = Filament::auth()->user();

        if (! $user->isOrganizationOwner() && ! $user->isOrganizationAdmin()) {
            return;
        }

        $targetUser = User::find($userId);
        $application = Application::find($applicationId);

        if ($targetUser && $application && $application->organization_id === $user->organization_id) {
            $targetUser->applications()->detach($applicationId);

            // Clear cache
            Cache::forget("access_matrix_{$user->organization_id}");

            // Refresh the component
            $this->dispatch('$refresh');
        }
    }

    public function getAccessStats(): array
    {
        $data = $this->getViewData();

        if (! $data['hasPermission']) {
            return [];
        }

        $totalUsers = $data['users']->count();
        $totalApplications = $data['applications']->count();
        $totalPossibleAccess = $totalUsers * $totalApplications;
        $totalGrantedAccess = 0;
        $activeUsers = 0;

        foreach ($data['accessMatrix'] as $userId => $userAccess) {
            $hasAnyAccess = false;
            foreach ($userAccess as $appId => $access) {
                if ($access['hasAccess']) {
                    $totalGrantedAccess++;
                    $hasAnyAccess = true;
                }
            }
            if ($hasAnyAccess) {
                $activeUsers++;
            }
        }

        $accessRate = $totalPossibleAccess > 0 ? round(($totalGrantedAccess / $totalPossibleAccess) * 100, 1) : 0;

        return [
            'totalUsers' => $totalUsers,
            'totalApplications' => $totalApplications,
            'totalGrantedAccess' => $totalGrantedAccess,
            'totalPossibleAccess' => $totalPossibleAccess,
            'accessRate' => $accessRate,
            'activeUsers' => $activeUsers,
        ];
    }

    protected function getPollingInterval(): ?string
    {
        return '2min';
    }
}
