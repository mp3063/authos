<?php

namespace App\Http\Controllers\Api\Traits;

use App\Models\Webhook;

trait FindsOrgScopedWebhooks
{
    /**
     * @param  array<int|string, mixed>  $with
     */
    protected function findWebhookWithOrgScope(string $id, string $ability, array $with = []): ?Webhook
    {
        $user = $this->getAuthenticatedUser();

        $webhook = Webhook::query()
            ->with($with)
            ->when(! $user->isSuperAdmin(), fn ($query) => $query
                ->whereNotNull('organization_id')
                ->where('organization_id', $user->organization_id))
            ->find($id);

        $this->authorize($ability, $webhook ?? new Webhook(['organization_id' => $user->organization_id]));

        return $webhook;
    }
}
