<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Application;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;

trait FindsOrgScopedApplications
{
    protected function findApplicationWithOrgScope(string $id, string $ability = 'view'): Application
    {
        $application = $this->orgScoped(Application::query(), auth()->user())->findOrFail($id);

        $this->authorize($ability, $application);

        return $application;
    }

    protected function findUserWithOrgScope(string $id, ?string $ability = null): User
    {
        $caller = auth()->user();
        $user = (string) $caller->id === $id ? $caller : $this->orgScoped(User::query(), $caller)->findOrFail($id);

        if ($ability !== null) {
            $this->authorize($ability, $user);
        }

        return $user;
    }

    private function orgScoped(Builder $query, User $caller): Builder
    {
        if (! $caller->isSuperAdmin()) {
            $query->whereNotNull('organization_id')->where('organization_id', $caller->organization_id);
        }

        return $query;
    }
}
