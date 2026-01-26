<?php

namespace App\Filament\Resources\SecurityIncidentResource\Pages;

use App\Filament\Resources\SecurityIncidentResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListSecurityIncidents extends ListRecords
{
    protected static string $resource = SecurityIncidentResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Incidents')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'open' => Tab::make('Open')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'open'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'open')->count())
                ->badgeColor('danger'),

            'critical' => Tab::make('Critical')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('severity', 'critical'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('severity', 'critical')->count())
                ->badgeColor('danger'),

            'today' => Tab::make('Today')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereDate('detected_at', today()))
                ->badge(fn () => static::getResource()::getEloquentQuery()->whereDate('detected_at', today())->count()),

            'resolved' => Tab::make('Resolved')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'resolved'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'resolved')->count())
                ->badgeColor('success'),
        ];
    }
}
