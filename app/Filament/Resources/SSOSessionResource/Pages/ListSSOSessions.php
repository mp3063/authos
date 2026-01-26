<?php

namespace App\Filament\Resources\SSOSessionResource\Pages;

use App\Filament\Resources\SSOSessionResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListSSOSessions extends ListRecords
{
    protected static string $resource = SSOSessionResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Sessions')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $query) => $query->active())
                ->badge(fn () => static::getResource()::getEloquentQuery()->active()->count())
                ->badgeColor('success'),

            'expired' => Tab::make('Expired')
                ->modifyQueryUsing(fn (Builder $query) => $query->where(function (Builder $q) {
                    $q->where('expires_at', '<=', now())
                        ->orWhereNotNull('logged_out_at');
                }))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where(function (Builder $q) {
                    $q->where('expires_at', '<=', now())
                        ->orWhereNotNull('logged_out_at');
                })->count())
                ->badgeColor('gray'),
        ];
    }
}
