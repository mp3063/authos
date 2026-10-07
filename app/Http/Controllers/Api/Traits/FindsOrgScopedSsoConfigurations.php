<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\SSOConfiguration;
use App\Models\User;

trait FindsOrgScopedSsoConfigurations
{
    protected function findOrgScopedSsoConfiguration(User $user, int $configId): SSOConfiguration
    {
        return SSOConfiguration::query()
            ->when(! $user->isSuperAdmin(), fn ($query) => $query->whereHas(
                'application',
                fn ($applicationQuery) => $applicationQuery->where('organization_id', $user->organization_id)
            ))
            ->findOrFail($configId);
    }
}
