<?php

namespace App\Filament\Resources;

use App\Filament\Resources\SSOSessionResource\Pages\ListSSOSessions;
use App\Filament\Resources\SSOSessionResource\Pages\ViewSSOSession;
use App\Models\Application;
use App\Models\SSOSession;
use App\Models\User;
use BackedEnum;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use UnitEnum;

class SSOSessionResource extends Resource
{
    protected static ?string $model = SSOSession::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 2;

    protected static ?string $navigationLabel = 'SSO Sessions';

    protected static ?string $modelLabel = 'SSO Session';

    protected static ?string $pluralModelLabel = 'SSO Sessions';

    public static function canCreate(): bool
    {
        return false;
    }

    /**
     * @throws \Throwable
     */
    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            // This resource is read-only, no form needed
        ]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('user.name')
                ->label('User')
                ->searchable()
                ->sortable(),

            TextColumn::make('application.name')
                ->label('Application')
                ->badge()
                ->sortable(),

            TextColumn::make('ip_address')
                ->label('IP Address')
                ->searchable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt'),

            TextColumn::make('user_agent')
                ->label('User Agent')
                ->limit(30)
                ->toggleable()
                ->tooltip(fn ($record) => $record->user_agent),

            TextColumn::make('is_active')
                ->label('Status')
                ->badge()
                ->formatStateUsing(fn ($record) => $record->isActive() ? 'Active' : 'Inactive')
                ->color(fn ($record) => $record->isActive() ? 'success' : 'gray')
                ->sortable(query: function (Builder $query, string $direction): Builder {
                    return $query->orderByRaw(
                        'CASE WHEN expires_at > NOW() AND logged_out_at IS NULL THEN 0 ELSE 1 END '.$direction
                    );
                }),

            TextColumn::make('expires_at')
                ->label('Expires At')
                ->dateTime()
                ->sortable(),

            TextColumn::make('last_activity_at')
                ->label('Last Activity')
                ->dateTime()
                ->sortable(),

            TextColumn::make('logged_out_at')
                ->label('Logged Out At')
                ->dateTime()
                ->placeholder('Active')
                ->sortable(),

            TextColumn::make('created_at')
                ->label('Created')
                ->dateTime()
                ->toggleable(isToggledHiddenByDefault: true)
                ->sortable(),
        ])->filters([
            TernaryFilter::make('active')
                ->label('Active Status')
                ->queries(
                    true: fn (Builder $query) => $query->active(),
                    false: fn (Builder $query) => $query->where(function (Builder $q) {
                        $q->where('expires_at', '<=', now())
                            ->orWhereNotNull('logged_out_at');
                    }),
                    blank: fn (Builder $query) => $query,
                ),

            SelectFilter::make('application_id')
                ->label('Application')
                ->options(fn () => Application::pluck('name', 'id')->toArray())
                ->searchable(),
        ])->recordActions([
            ViewAction::make(),

            \Filament\Actions\Action::make('terminate')
                ->label('Terminate')
                ->icon('heroicon-o-x-circle')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('Terminate Session')
                ->modalDescription('Are you sure you want to terminate this SSO session? The user will be logged out of this application.')
                ->modalSubmitActionLabel('Terminate')
                ->visible(fn (SSOSession $record) => $record->isActive())
                ->action(function (SSOSession $record) {
                    /** @var User $authUser */
                    $authUser = Filament::auth()->user();
                    $record->logout($authUser);

                    Notification::make()
                        ->title('Session terminated')
                        ->body('The SSO session has been terminated successfully.')
                        ->success()
                        ->send();
                }),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('terminate')
                    ->label('Terminate Selected')
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->modalHeading('Terminate Sessions')
                    ->modalDescription('Are you sure you want to terminate the selected SSO sessions? Users will be logged out of their applications.')
                    ->modalSubmitActionLabel('Terminate All')
                    ->action(function (Collection $records) {
                        /** @var User $authUser */
                        $authUser = Filament::auth()->user();
                        $terminated = 0;

                        $records->each(function (SSOSession $record) use ($authUser, &$terminated) {
                            if ($record->isActive()) {
                                $record->logout($authUser);
                                $terminated++;
                            }
                        });

                        Notification::make()
                            ->title('Sessions terminated')
                            ->body("Terminated {$terminated} active session(s).")
                            ->success()
                            ->send();
                    }),
            ]),
        ])->defaultSort('last_activity_at', 'desc')->poll('30s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListSSOSessions::route('/'),
            'view' => ViewSSOSession::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->active()->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['user', 'application']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all SSO sessions
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see sessions from their organization
        if ($user && $user->organization_id) {
            $query->whereHas('user', function ($subQuery) use ($user) {
                $subQuery->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }
}
