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
        return [
            'all' => Tab::make('All Webhooks')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', true))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', true)->count())
                ->badgeColor('success'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', false))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', false)->count())
                ->badgeColor('gray'),

            'failing' => Tab::make('Failing')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('failure_count', '>', 0))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('failure_count', '>', 0)->count())
                ->badgeColor('danger'),
        ];
    }
}
