<?php

namespace App\Filament\Resources\BulkImportJobResource\Pages;

use App\Filament\Resources\BulkImportJobResource;
use App\Models\BulkImportJob;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListBulkImportJobs extends ListRecords
{
    protected static string $resource = BulkImportJobResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Jobs')
                ->badge(fn () => $this->getTabBadgeCount()),

            'pending' => Tab::make('Pending')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', BulkImportJob::STATUS_PENDING))
                ->badge(fn () => $this->getTabBadgeCount('pending'))
                ->badgeColor('warning'),

            'processing' => Tab::make('Processing')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', BulkImportJob::STATUS_PROCESSING))
                ->badge(fn () => $this->getTabBadgeCount('processing'))
                ->badgeColor('info'),

            'completed' => Tab::make('Completed')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereIn('status', [
                    BulkImportJob::STATUS_COMPLETED,
                    BulkImportJob::STATUS_COMPLETED_WITH_ERRORS,
                ]))
                ->badge(fn () => $this->getTabBadgeCount('completed'))
                ->badgeColor('success'),

            'failed' => Tab::make('Failed')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('status', BulkImportJob::STATUS_FAILED))
                ->badge(fn () => $this->getTabBadgeCount('failed'))
                ->badgeColor('danger'),
        ];
    }

    protected function getTabBadgeCount(?string $type = null): int
    {
        try {
            $query = static::getResource()::getEloquentQuery();

            return match ($type) {
                'pending' => $query->where('status', BulkImportJob::STATUS_PENDING)->count(),
                'processing' => $query->where('status', BulkImportJob::STATUS_PROCESSING)->count(),
                'completed' => $query->whereIn('status', [
                    BulkImportJob::STATUS_COMPLETED,
                    BulkImportJob::STATUS_COMPLETED_WITH_ERRORS,
                ])->count(),
                'failed' => $query->where('status', BulkImportJob::STATUS_FAILED)->count(),
                default => $query->count(),
            };
        } catch (\Exception) {
            return 0;
        }
    }
}
