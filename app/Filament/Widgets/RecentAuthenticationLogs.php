<?php

namespace App\Filament\Widgets;

use App\Models\AuthenticationLog;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;
use Filament\Widgets\TableWidget as BaseWidget;

class RecentAuthenticationLogs extends BaseWidget
{
    // protected static ?string $heading = 'Recent Authentication Events';

    protected static ?int $sort = 3;

    protected int|string|array $columnSpan = 'full';

    public function table(Table $table): Table
    {
        return $table
            ->query(
                AuthenticationLog::query()
                    ->with(['user', 'application'])
                    ->latest()
                    ->limit(10)
            )
            ->columns([
                TextColumn::make('created_at')
                    ->label('Time')
                    ->dateTime('H:i:s')
                    ->sortable(),

                TextColumn::make('event')
                    ->badge()
                    ->color(fn ($record) => $record->getEventBadgeColor())
                    ->icon(fn ($record) => $record->getEventIcon()),

                TextColumn::make('user.name')
                    ->label('User')
                    ->placeholder('System')
                    ->limit(20),

                TextColumn::make('application.name')
                    ->label('Application')
                    ->placeholder('N/A')
                    ->badge()
                    ->limit(15),

                TextColumn::make('ip_address')
                    ->label('IP')
                    ->copyable()
                    ->icon('heroicon-o-globe-alt'),

                TextColumn::make('user_agent')
                    ->label('Device')
                    ->formatStateUsing(function ($state) {
                        if (! $state) {
                            return 'Unknown';
                        }

                        // Simple user agent parsing
                        if (str_contains($state, 'Mobile') || str_contains($state, 'Android') || str_contains($state, 'iPhone')) {
                            return 'Mobile';
                        } elseif (str_contains($state, 'Chrome')) {
                            return 'Chrome';
                        } elseif (str_contains($state, 'Firefox')) {
                            return 'Firefox';
                        } elseif (str_contains($state, 'Safari')) {
                            return 'Safari';
                        } else {
                            return 'Unknown';
                        }
                    })
                    ->badge()
                    ->color('gray'),
            ])
            ->paginated(false)
            ->poll('30s');
    }
}
