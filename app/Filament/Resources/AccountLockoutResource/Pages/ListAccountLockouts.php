<?php

namespace App\Filament\Resources\AccountLockoutResource\Pages;

use App\Filament\Resources\AccountLockoutResource;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListAccountLockouts extends ListRecords
{
    protected static string $resource = AccountLockoutResource::class;

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Lockouts')
                ->badge(fn () => $this->getTabBadgeCount()),

            'active' => Tab::make('Active')
                ->modifyQueryUsing(fn (Builder $query) => $query
                    ->whereNull('unlocked_at')
                    ->where(function (Builder $q) {
                        $q->whereNull('unlock_at')
                            ->orWhere('unlock_at', '>', now());
                    })
                )
                ->badge(fn () => $this->getTabBadgeCount('active'))
                ->badgeColor('danger'),

            'expired' => Tab::make('Expired')
                ->modifyQueryUsing(fn (Builder $query) => $query
                    ->whereNotNull('unlock_at')
                    ->where('unlock_at', '<', now())
                    ->whereNull('unlocked_at')
                )
                ->badge(fn () => $this->getTabBadgeCount('expired'))
                ->badgeColor('gray'),

            'unlocked' => Tab::make('Unlocked')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereNotNull('unlocked_at'))
                ->badge(fn () => $this->getTabBadgeCount('unlocked'))
                ->badgeColor('success'),
        ];
    }

    protected function getTabBadgeCount(?string $type = null): int
    {
        try {
            $query = static::getResource()::getEloquentQuery();

            return match ($type) {
                'active' => $query
                    ->whereNull('unlocked_at')
                    ->where(function (Builder $q) {
                        $q->whereNull('unlock_at')
                            ->orWhere('unlock_at', '>', now());
                    })
                    ->count(),
                'expired' => $query
                    ->whereNotNull('unlock_at')
                    ->where('unlock_at', '<', now())
                    ->whereNull('unlocked_at')
                    ->count(),
                'unlocked' => $query
                    ->whereNotNull('unlocked_at')
                    ->count(),
                default => $query->count(),
            };
        } catch (\Exception $e) {
            return 0;
        }
    }
}
