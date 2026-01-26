<?php

namespace App\Filament\Resources\MigrationJobResource\Pages;

use App\Filament\Resources\MigrationJobResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListMigrationJobs extends ListRecords
{
    protected static string $resource = MigrationJobResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Jobs')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'pending'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'pending')->count())
                ->badgeColor('warning'),

            'running' => Tab::make('Running')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'running'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'running')->count())
                ->badgeColor('info'),

            'completed' => Tab::make('Completed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'completed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'completed')->count())
                ->badgeColor('success'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'failed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'failed')->count())
                ->badgeColor('danger'),
        ];
    }
}
