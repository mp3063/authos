<?php

namespace App\Filament\Resources\SSOConfigurationResource\Pages;

use App\Filament\Resources\SSOConfigurationResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListSSOConfigurations extends ListRecords
{
    protected static string $resource = SSOConfigurationResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Configurations')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'oidc' => Tab::make('OIDC')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('provider', 'oidc'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('provider', 'oidc')->count())
                ->badgeColor('info'),

            'saml' => Tab::make('SAML')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('provider', 'saml'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('provider', 'saml')->count())
                ->badgeColor('warning'),

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
