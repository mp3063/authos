<?php

namespace App\Filament\Resources\CustomRoleResource\Pages;

use App\Filament\Resources\CustomRoleResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListCustomRoles extends ListRecords
{
    protected static string $resource = CustomRoleResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Roles')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', true))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', true)->count())
                ->badgeColor('success'),

            'system' => Tab::make('System')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_system', true))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_system', true)->count())
                ->badgeColor('warning'),

            'user-defined' => Tab::make('User-Defined')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_system', false))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_system', false)->count())
                ->badgeColor('info'),
        ];
    }
}
