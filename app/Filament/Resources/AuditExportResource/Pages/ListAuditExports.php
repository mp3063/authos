<?php

namespace App\Filament\Resources\AuditExportResource\Pages;

use App\Filament\Resources\AuditExportResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListAuditExports extends ListRecords
{
    protected static string $resource = AuditExportResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Exports')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'completed' => Tab::make('Completed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'completed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'completed')->count())
                ->badgeColor('success'),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereIn('status', ['pending', 'processing']))
                ->badge(fn () => static::getResource()::getEloquentQuery()->whereIn('status', ['pending', 'processing'])->count())
                ->badgeColor('warning'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', 'failed'))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('status', 'failed')->count())
                ->badgeColor('danger'),
        ];
    }
}
