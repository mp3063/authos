<?php

namespace App\Filament\Concerns;

use App\Models\User;
use Filament\Facades\Filament;

trait ForcesCallerOrganization
{
    /**
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    protected function forceCallerOrganization(array $data): array
    {
        $user = Filament::auth()->user();

        if ($user instanceof User && ! $user->isSuperAdmin()) {
            $data['organization_id'] = $user->organization_id;
        }

        return $data;
    }
}
