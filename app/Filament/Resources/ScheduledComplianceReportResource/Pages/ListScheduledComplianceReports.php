<?php

namespace App\Filament\Resources\ScheduledComplianceReportResource\Pages;

use App\Filament\Resources\ScheduledComplianceReportResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListScheduledComplianceReports extends ListRecords
{
    protected static string $resource = ScheduledComplianceReportResource::class;

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
                ->modifyQueryUsing(fn (Builder $query) => $query->where('is_active', true))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', true)->count())
                ->badgeColor('success'),

            'due' => Tab::make('Due Now')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('is_active', true)->where('next_run_at', '<=', now()))
                ->badge(fn () => static::getResource()::getEloquentQuery()
                    ->where('is_active', true)->where('next_run_at', '<=', now())->count())
                ->badgeColor('warning'),

            'inactive' => Tab::make('Inactive')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('is_active', false))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('is_active', false)->count())
                ->badgeColor('gray'),
        ];
    }
}
