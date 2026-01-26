<?php

namespace App\Filament\Resources\FailedLoginAttemptResource\Pages;

use App\Filament\Resources\FailedLoginAttemptResource;
use App\Models\FailedLoginAttempt;
use Filament\Actions;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListFailedLoginAttempts extends ListRecords
{
    protected static string $resource = FailedLoginAttemptResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('export')
                ->label('Export')
                ->icon('heroicon-o-arrow-down-tray')
                ->color('gray')
                ->action(function () {
                    Notification::make()
                        ->title('Export started')
                        ->body('Failed login attempts are being exported.')
                        ->info()
                        ->send();
                }),

            Actions\Action::make('clear_old_entries')
                ->label('Clear Old Entries')
                ->icon('heroicon-o-trash')
                ->color('danger')
                ->requiresConfirmation()
                ->modalDescription('This will delete failed login attempts older than 30 days. This action cannot be undone.')
                ->action(function () {
                    $count = FailedLoginAttempt::where('attempted_at', '<', now()->subDays(30))->delete();
                    Notification::make()
                        ->title('Old entries cleared')
                        ->body("Deleted {$count} failed login attempts older than 30 days.")
                        ->success()
                        ->send();
                })
                ->visible(fn () => auth()->user()?->hasRole('Super Admin')),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All')
                ->badge(fn () => static::getResource()::getEloquentQuery()->count()),

            'last_hour' => Tab::make('Last Hour')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('attempted_at', '>=', now()->subHour()))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('attempted_at', '>=', now()->subHour())->count())
                ->badgeColor(function () {
                    $count = static::getResource()::getEloquentQuery()->where('attempted_at', '>=', now()->subHour())->count();

                    if ($count > 50) {
                        return 'danger';
                    }

                    if ($count > 10) {
                        return 'warning';
                    }

                    return 'primary';
                }),

            'today' => Tab::make('Today')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereDate('attempted_at', today()))
                ->badge(fn () => static::getResource()::getEloquentQuery()->whereDate('attempted_at', today())->count()),

            'this_week' => Tab::make('This Week')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('attempted_at', '>=', now()->startOfWeek()))
                ->badge(fn () => static::getResource()::getEloquentQuery()->where('attempted_at', '>=', now()->startOfWeek())->count()),
        ];
    }
}
