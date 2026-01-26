<?php

namespace App\Filament\Resources\IpBlocklistResource\Pages;

use App\Filament\Resources\IpBlocklistResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListIpBlocklist extends ListRecords
{
    protected static string $resource = IpBlocklistResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\CreateAction::make(),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', true)->where(function ($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                }))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', true)->where(function ($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })->count())
                ->badgeColor('success'),

            'expired' => Tab::make('Expired')
                ->modifyQueryUsing(fn (Builder $q) => $q->whereNotNull('expires_at')->where('expires_at', '<', now()))
                ->badge(fn () => static::getResource()::getEloquentQuery()->whereNotNull('expires_at')->where('expires_at', '<', now())->count())
                ->badgeColor('warning'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $q) => $q->where('is_active', false))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', false)->count())
                ->badgeColor('gray'),
        ];
    }
}
