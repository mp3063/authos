<?php

namespace App\Filament\Resources\WebhookResource\Pages;

use App\Filament\Resources\WebhookResource;
use App\Models\Webhook;
use Filament\Actions;
use Filament\Facades\Filament;
use Filament\Resources\Components\Tab;
use Filament\Resources\Pages\ListRecords;
use Illuminate\Database\Eloquent\Builder;

class ListWebhooks extends ListRecords
{
    protected static string $resource = WebhookResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        $user = Filament::auth()->user();
        $query = Webhook::query();

        // Apply organization scoping
        if (! $user->isSuperAdmin() && $user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return [
            'all' => Tab::make('All Webhooks')
                ->badge((clone $query)->count()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', true))
                ->badge((clone $query)->where('is_active', true)->count())
                ->badgeColor('success'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', false))
                ->badge((clone $query)->where('is_active', false)->count())
                ->badgeColor('gray'),

            'failing' => Tab::make('Failing')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('failure_count', '>', 0))
                ->badge((clone $query)->where('failure_count', '>', 0)->count())
                ->badgeColor('danger'),
        ];
    }
}
