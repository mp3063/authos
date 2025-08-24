<?php

namespace App\Filament\Resources\AuthenticationLogResource\Pages;

use App\Filament\Resources\AuthenticationLogResource;
use Filament\Actions;
use Filament\Resources\Pages\ListRecords;
use Filament\Schemas\Components\Tabs\Tab;
use Illuminate\Database\Eloquent\Builder;

class ListAuthenticationLogs extends ListRecords
{
    protected static string $resource = AuthenticationLogResource::class;

    protected function getHeaderActions(): array
    {
        return [
            Actions\Action::make('export_logs')
                ->label('Export Logs')
                ->icon('heroicon-o-arrow-down-tray')
                ->color('gray')
                ->action(function () {
                    \Filament\Notifications\Notification::make()
                        ->title('Export started')
                        ->body('Authentication logs are being exported.')
                        ->info()
                        ->send();
                }),
                
            Actions\Action::make('clear_old_logs')
                ->label('Clear Old Logs')
                ->icon('heroicon-o-trash')
                ->color('danger')
                ->requiresConfirmation()
                ->modalDescription('This will delete logs older than 90 days.')
                ->action(function () {
                    $count = \App\Models\AuthenticationLog::where('created_at', '<', now()->subDays(90))->delete();
                    \Filament\Notifications\Notification::make()
                        ->title('Old logs cleared')
                        ->body("Deleted {$count} log entries older than 90 days.")
                        ->success()
                        ->send();
                })
                ->visible(fn () => auth()->user()->can('delete authentication logs')),
        ];
    }

    public function getTabs(): array
    {
        return [
            'all' => Tab::make('All Events')
                ->badge(\App\Models\AuthenticationLog::count()),
                
            'today' => Tab::make('Today')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereDate('created_at', today()))
                ->badge(\App\Models\AuthenticationLog::whereDate('created_at', today())->count()),
                
            'successful_logins' => Tab::make('Successful Logins')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('event', 'login'))
                ->badge(\App\Models\AuthenticationLog::where('event', 'login')->whereDate('created_at', today())->count()),
                
            'failed_attempts' => Tab::make('Failed Attempts')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereIn('event', ['failed_login', 'failed_mfa']))
                ->badge(\App\Models\AuthenticationLog::whereIn('event', ['failed_login', 'failed_mfa'])->whereDate('created_at', today())->count())
                ->badgeColor('danger'),
                
            'mfa_events' => Tab::make('MFA Events')
                ->modifyQueryUsing(fn (Builder $query) => $query->whereIn('event', ['mfa_challenge', 'mfa_success', 'failed_mfa']))
                ->badge(\App\Models\AuthenticationLog::whereIn('event', ['mfa_challenge', 'mfa_success', 'failed_mfa'])->whereDate('created_at', today())->count()),
                
            'suspicious' => Tab::make('Suspicious Activity')
                ->modifyQueryUsing(fn (Builder $query) => $query->where('event', 'suspicious_activity'))
                ->badge(\App\Models\AuthenticationLog::where('event', 'suspicious_activity')->whereDate('created_at', today())->count())
                ->badgeColor('warning'),
        ];
    }
}