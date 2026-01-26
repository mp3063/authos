<?php

namespace App\Filament\Resources\ApplicationGroupResource\Pages;

use App\Filament\Resources\ApplicationGroupResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListApplicationGroups extends ListRecords
{
    protected static string $resource = ApplicationGroupResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Groups')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'root' => Tab::make('Root Groups')
                ->modifyQueryUsing(fn (Builder $q) => $q->whereNull('parent_id'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->whereNull('parent_id')->count())
                ->badgeColor('info'),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', true))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', true)->count())
                ->badgeColor('success'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', false))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', false)->count())
                ->badgeColor('gray'),
        ];
    }
}
