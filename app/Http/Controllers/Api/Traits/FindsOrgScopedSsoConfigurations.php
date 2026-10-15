<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Application;
use App\Models\SSOConfiguration;
use App\Models\User;

trait FindsOrgScopedSsoConfigurations
{
    protected function findOrgScopedSsoConfiguration(User $user, int $configId, string $ability): SSOConfiguration
    {
        $ssoConfig = SSOConfiguration::query()
            ->when(! $user->isSuperAdmin(), fn ($query) => $query->whereHas(
                'application',
                fn ($applicationQuery) => $applicationQuery
                    ->whereNotNull('organization_id')
                    ->where('organization_id', $user->organization_id)
            ))
            ->find($configId);

        $this->authorize($ability, $ssoConfig ?? $this->blankSsoConfigurationFor($user));

        abort_if($ssoConfig === null, 404);

        return $ssoConfig;
    }

    private function blankSsoConfigurationFor(User $user): SSOConfiguration
    {
        return (new SSOConfiguration)->setRelation(
            'application',
            (new Application)->forceFill(['organization_id' => $user->organization_id])
        );
    }
}
