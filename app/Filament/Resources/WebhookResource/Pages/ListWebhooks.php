<?php

namespace App\Filament\Resources\WebhookResource\Pages;

use App\Filament\Resources\WebhookResource;
use App\Models\Webhook;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
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
        $allCount = Webhook::query()->count();
        $activeCount = Webhook::query()->where('is_active', true)->count();
        $inactiveCount = Webhook::query()->where('is_active', false)->count();
        $failingCount = Webhook::query()->where('failure_count', '>', 0)->count();

        return [
            'all' => Tab::make('All Webhooks')
                ->badge($allCount),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('is_active', true))
                ->badge($activeCount)
                ->badgeColor('success'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('is_active', false))
                ->badge($inactiveCount)
                ->badgeColor('gray'),

            'failing' => Tab::make('Failing')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('failure_count', '>', 0))
                ->badge($failingCount)
                ->badgeColor('danger'),
        ];
    }
}
