<?php

namespace App\Filament\Resources\WebhookResource\Pages;

use App\Filament\Resources\WebhookResource;
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
        $allCount = WebhookResource::getEloquentQuery()->count();
        $activeCount = WebhookResource::getEloquentQuery()->where('is_active', true)->count();
        $inactiveCount = WebhookResource::getEloquentQuery()->where('is_active', false)->count();
        $failingCount = WebhookResource::getEloquentQuery()->where('failure_count', '>', 0)->count();

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
