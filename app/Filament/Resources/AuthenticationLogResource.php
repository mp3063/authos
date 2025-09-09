<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AuthenticationLogResource\Pages\ListAuthenticationLogs;
use App\Filament\Resources\AuthenticationLogResource\Pages\ViewAuthenticationLog;
use App\Models\AuthenticationLog;
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

class AuthenticationLogResource extends Resource
{
    protected static ?string $model = AuthenticationLog::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Security & Monitoring';

    protected static ?int $navigationSort = 1;

    protected static ?string $navigationLabel = 'Authentication Logs';

    protected static ?string $modelLabel = 'Authentication Log';

    protected static ?string $pluralModelLabel = 'Authentication Logs';

    public static function canCreate(): bool
    {
        return false;
    }

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([// This resource is read-only, no form needed
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('created_at')->label('Timestamp')->dateTime()->sortable()->searchable(),

            TextColumn::make('event')
                ->badge()
                ->color(fn ($record) => $record->getEventBadgeColor())
                ->icon(fn ($record) => $record->getEventIcon())
                ->searchable()
                ->sortable(),

            TextColumn::make('user.name')
                ->label('User')
                ->searchable()
                ->sortable()
                ->placeholder('System')
                ->url(fn ($record) => $record->user ? route('filament.admin.resources.users.view', $record->user) : null),

            TextColumn::make('user.email')->label('Email')->searchable()->placeholder('N/A')->toggleable(),

            TextColumn::make('application.name')
                ->label('Application')
                ->searchable()
                ->sortable()
                ->placeholder('N/A')
                ->badge()
                ->url(fn ($record) => $record->application ? route('filament.admin.resources.applications.view', $record->application) : null),

            TextColumn::make('ip_address')
                ->label('IP Address')
                ->searchable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt'),

            TextColumn::make('user_agent')
                ->label('User Agent')
                ->limit(50)
                ->tooltip(fn ($record) => $record->user_agent)
                ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('metadata')->label('Details')->formatStateUsing(fn ($state) => $state ? collect($state)
                ->map(fn ($v, $k) => "$k: $v")
                ->join(', ') : 'None')->limit(50)->tooltip(fn ($record) => $record->metadata ? collect($record->metadata)
                ->map(fn ($v, $k) => "$k: $v")
                ->join("\n") : null)->toggleable(),
        ])->filters([
            SelectFilter::make('event')->options([
                'login_success' => 'Login',
                'logout' => 'Logout',
                'login_failed' => 'Failed Login',
                'token_refresh' => 'Token Refresh',
                'mfa_challenge' => 'MFA Challenge',
                'mfa_success' => 'MFA Success',
                'failed_mfa' => 'Failed MFA',
                'password_reset' => 'Password Reset',
                'suspicious_activity' => 'Suspicious Activity',
            ])->multiple(),

            SelectFilter::make('user')->relationship('user', 'name')->searchable()->preload(),

            SelectFilter::make('application')->relationship('application', 'name')->searchable()->preload(),

            Filter::make('ip_address')->form([
                TextInput::make('ip')->label('IP Address'),
            ])->query(function (Builder $query, array $data): Builder {
                return $query->when(
                    $data['ip'], fn (Builder $query, $ip): Builder => $query->where('ip_address', 'like', "%{$ip}%"),
                );
            }),

            Filter::make('date_range')->form([
                DatePicker::make('from')->label('From Date'),
                DatePicker::make('until')->label('Until Date'),
            ])->query(function (Builder $query, array $data): Builder {
                return $query->when(
                    $data['from'], fn (Builder $query, $date): Builder => $query->whereDate('created_at', '>=', $date),
                )->when(
                    $data['until'], fn (Builder $query, $date): Builder => $query->whereDate('created_at', '<=', $date),
                );
            }),

            Filter::make('failed_attempts')
                ->query(fn (Builder $query): Builder => $query->whereIn('event', ['login_failed', 'failed_mfa']))
                ->label('Failed Attempts'),

            Filter::make('suspicious')
                ->query(fn (Builder $query): Builder => $query->where('event', 'suspicious_activity'))
                ->label('Suspicious Activity'),

            Filter::make('today')->query(fn (Builder $query): Builder => $query->whereDate('created_at', today()))->label('Today'),

            Filter::make('last_24h')
                ->query(fn (Builder $query): Builder => $query->where('created_at', '>=', now()->subDay()))
                ->label('Last 24 Hours'),

            Filter::make('last_week')
                ->query(fn (Builder $query): Builder => $query->where('created_at', '>=', now()->subWeek()))
                ->label('Last Week'),
        ])->recordActions([
            ViewAction::make()->modalWidth('2xl'),
        ])->toolbarActions([
            BulkActionGroup::make([
                DeleteBulkAction::make()
                    ->label('Delete Selected')
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to delete these log entries? This action cannot be undone.')
                    ->visible(fn () => auth()->user()->can('delete authentication logs')),

                BulkAction::make('export')->label('Export Selected')->icon('heroicon-o-arrow-down-tray')->color('gray')->action(function ($records) {
                    // Export functionality would be implemented here
                    Notification::make()
                        ->title('Export started')
                        ->body('Log entries are being exported. You will receive a download link shortly.')
                        ->info()
                        ->send();
                }),
            ]),
        ])->defaultSort('created_at', 'desc')->poll('30s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListAuthenticationLogs::route('/'),
            'view' => ViewAuthenticationLog::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('created_at', '>=', today())->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $suspiciousCount = static::getModel()::where('event', 'suspicious_activity')->where('created_at', '>=', today())->count();

        $failedCount = static::getModel()::whereIn('event', ['login_failed', 'failed_mfa'])->where('created_at', '>=', today())->count();

        if ($suspiciousCount > 0) {
            return 'danger';
        }

        if ($failedCount > 10) {
            return 'warning';
        }

        return 'primary';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['user', 'application']);
        $user = \Filament\Facades\Filament::auth()->user();

        // Super admins can see all authentication logs
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see logs from their organization
        if ($user->organization_id) {
            $query->whereHas('user', function ($subQuery) use ($user) {
                $subQuery->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }
}
