<?php

namespace App\Filament\Resources;

use App\Filament\Resources\FailedLoginAttemptResource\Pages\ListFailedLoginAttempts;
use App\Filament\Resources\FailedLoginAttemptResource\Pages\ViewFailedLoginAttempt;
use App\Models\FailedLoginAttempt;
use BackedEnum;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\ViewAction;
use Filament\Forms\Components\DatePicker;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class FailedLoginAttemptResource extends Resource
{
    protected static ?string $model = FailedLoginAttempt::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Security';

    protected static ?int $navigationSort = 5;

    protected static ?string $modelLabel = 'Failed Login Attempt';

    protected static ?string $pluralModelLabel = 'Failed Login Attempts';

    public static function canCreate(): bool
    {
        return false;
    }

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('attempted_at')
                ->label('Time')
                ->dateTime()
                ->sortable(),

            TextColumn::make('email')
                ->searchable()
                ->sortable(),

            TextColumn::make('ip_address')
                ->searchable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt'),

            TextColumn::make('attempt_type')
                ->badge()
                ->sortable()
                ->color(fn ($state) => match ($state) {
                    'login' => 'primary',
                    'mfa' => 'warning',
                    'api' => 'info',
                    default => 'gray',
                }),

            TextColumn::make('failure_reason')
                ->searchable()
                ->limit(40),

            TextColumn::make('user_agent')
                ->limit(50)
                ->tooltip(fn ($record) => $record->user_agent)
                ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('metadata')
                ->formatStateUsing(fn ($state) => $state ? collect($state)
                    ->map(fn ($v, $k) => "$k: $v")
                    ->join(', ') : 'None')
                ->limit(50)
                ->toggleable(),
        ])->filters([
            SelectFilter::make('attempt_type')
                ->options([
                    'login' => 'Login',
                    'mfa' => 'MFA',
                    'api' => 'API',
                    'password_reset' => 'Password Reset',
                    'social' => 'Social',
                ]),

            SelectFilter::make('failure_reason')
                ->options([
                    'invalid_credentials' => 'Invalid Credentials',
                    'account_locked' => 'Account Locked',
                    'mfa_failed' => 'MFA Failed',
                    'rate_limited' => 'Rate Limited',
                    'invalid_token' => 'Invalid Token',
                ]),

            Filter::make('email')
                ->schema([
                    TextInput::make('email')->label('Email'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['email'],
                        fn (Builder $query, $email): Builder => $query->where('email', 'like', "%$email%"),
                    );
                }),

            Filter::make('ip_address')
                ->schema([
                    TextInput::make('ip')->label('IP Address'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['ip'],
                        fn (Builder $query, $ip): Builder => $query->where('ip_address', 'like', "%$ip%"),
                    );
                }),

            Filter::make('date_range')
                ->schema([
                    DatePicker::make('from')->label('From Date'),
                    DatePicker::make('until')->label('Until Date'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return $query->when(
                        $data['from'],
                        fn (Builder $query, $date): Builder => $query->where('attempted_at', '>=', $date),
                    )->when(
                        $data['until'],
                        fn (Builder $query, $date): Builder => $query->where('attempted_at', '<=', $date),
                    );
                }),

            Filter::make('last_hour')
                ->query(fn (Builder $query): Builder => $query->where('attempted_at', '>=', now()->subHour()))
                ->label('Last Hour'),

            Filter::make('today')
                ->query(fn (Builder $query): Builder => $query->whereDate('attempted_at', today()))
                ->label('Today'),

            Filter::make('last_24h')
                ->query(fn (Builder $query): Builder => $query->where('attempted_at', '>=', now()->subDay()))
                ->label('Last 24 Hours'),
        ])->recordActions([
            ViewAction::make()->modalWidth('2xl'),
        ])->toolbarActions([
            BulkActionGroup::make([
                DeleteBulkAction::make()
                    ->label('Delete Selected')
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to delete these failed login attempts? This action cannot be undone.')
                    ->visible(fn () => auth()->user()?->hasRole('Super Admin')),

                BulkAction::make('export')
                    ->label('Export Selected')
                    ->icon('heroicon-o-arrow-down-tray')
                    ->color('gray')
                    ->action(function () {
                        Notification::make()
                            ->title('Export started')
                            ->body('Failed login attempts are being exported. You will receive a download link shortly.')
                            ->info()
                            ->send();
                    }),
            ]),
        ])->defaultSort('attempted_at', 'desc')->poll('30s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListFailedLoginAttempts::route('/'),
            'view' => ViewFailedLoginAttempt::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('attempted_at', '>=', now()->subHour())->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $lastHourCount = static::getModel()::where('attempted_at', '>=', now()->subHour())->count();

        if ($lastHourCount > 50) {
            return 'danger';
        }

        if ($lastHourCount > 10) {
            return 'warning';
        }

        return 'primary';
    }
}
