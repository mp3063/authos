<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AccountLockoutResource\Pages\ListAccountLockouts;
use App\Filament\Resources\AccountLockoutResource\Pages\ViewAccountLockout;
use App\Models\AccountLockout;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
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
use Illuminate\Database\Eloquent\Collection;
use UnitEnum;

class AccountLockoutResource extends Resource
{
    protected static ?string $model = AccountLockout::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Security';

    protected static ?int $navigationSort = 3;

    protected static ?string $navigationLabel = 'Account Lockouts';

    protected static ?string $modelLabel = 'Account Lockout';

    protected static ?string $pluralModelLabel = 'Account Lockouts';

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
            TextColumn::make('locked_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('email')
                ->searchable()
                ->sortable(),

            TextColumn::make('user.name')
                ->label('User')
                ->searchable()
                ->placeholder('N/A')
                ->url(fn ($record) => $record->user ? route('filament.admin.resources.users.view', $record->user) : null),

            TextColumn::make('ip_address')
                ->searchable()
                ->copyable()
                ->copyMessage('IP copied')
                ->icon('heroicon-o-globe-alt'),

            TextColumn::make('lockout_type')
                ->badge()
                ->sortable(),

            TextColumn::make('attempt_count')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('reason')
                ->limit(40)
                ->toggleable(),

            TextColumn::make('unlock_at')
                ->label('Expires At')
                ->dateTime()
                ->sortable(),

            TextColumn::make('unlocked_at')
                ->label('Unlocked At')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('unlock_method')
                ->badge()
                ->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('status')
                ->label('Status')
                ->getStateUsing(fn ($record) => $record)
                ->formatStateUsing(function ($state) {
                    if ($state->unlocked_at) {
                        return 'Unlocked';
                    }
                    if ($state->unlock_at && $state->unlock_at->isPast()) {
                        return 'Expired';
                    }

                    return 'Active';
                })
                ->badge()
                ->color(function ($state) {
                    if ($state->unlocked_at) {
                        return 'success';
                    }
                    if ($state->unlock_at && $state->unlock_at->isPast()) {
                        return 'gray';
                    }

                    return 'danger';
                }),
        ])->filters([
            Filter::make('active_only')
                ->label('Active Only')
                ->query(fn (Builder $query): Builder => $query
                    ->whereNull('unlocked_at')
                    ->where(function (Builder $q) {
                        $q->whereNull('unlock_at')
                            ->orWhere('unlock_at', '>', now());
                    })
                ),

            Filter::make('expired')
                ->label('Expired')
                ->query(fn (Builder $query): Builder => $query
                    ->whereNotNull('unlock_at')
                    ->where('unlock_at', '<', now())
                    ->whereNull('unlocked_at')
                ),

            SelectFilter::make('lockout_type')
                ->options(function () {
                    return AccountLockout::query()
                        ->distinct()
                        ->whereNotNull('lockout_type')
                        ->pluck('lockout_type', 'lockout_type')
                        ->toArray();
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
                        fn (Builder $query, $date): Builder => $query->whereDate('locked_at', '>=', $date),
                    )->when(
                        $data['until'],
                        fn (Builder $query, $date): Builder => $query->whereDate('locked_at', '<=', $date),
                    );
                }),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                Action::make('unlock')
                    ->icon('heroicon-o-lock-open')
                    ->color('success')
                    ->visible(fn (AccountLockout $record) => $record->isActive())
                    ->requiresConfirmation()
                    ->modalHeading('Unlock Account')
                    ->modalDescription('Are you sure you want to unlock this account lockout?')
                    ->action(function (AccountLockout $record) {
                        $record->update([
                            'unlocked_at' => now(),
                            'unlock_method' => 'admin_manual',
                        ]);

                        Notification::make()
                            ->title('Account unlocked successfully')
                            ->success()
                            ->send();
                    }),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('bulk_unlock')
                    ->label('Unlock Selected')
                    ->icon('heroicon-o-lock-open')
                    ->color('success')
                    ->requiresConfirmation()
                    ->modalHeading('Bulk Unlock Accounts')
                    ->modalDescription('Are you sure you want to unlock all selected active lockouts?')
                    ->deselectRecordsAfterCompletion()
                    ->action(function (Collection $records) {
                        $unlocked = 0;

                        foreach ($records as $record) {
                            if ($record->isActive()) {
                                $record->update([
                                    'unlocked_at' => now(),
                                    'unlock_method' => 'admin_manual',
                                ]);
                                $unlocked++;
                            }
                        }

                        Notification::make()
                            ->title("Unlocked $unlocked account(s)")
                            ->success()
                            ->send();
                    }),

                DeleteBulkAction::make()
                    ->label('Delete Selected')
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to delete these lockout records? This action cannot be undone.'),
            ]),
        ])->defaultSort('locked_at', 'desc')->poll('30s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListAccountLockouts::route('/'),
            'view' => ViewAccountLockout::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getActiveLockoutCount();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $count = static::getActiveLockoutCount();

        if ($count > 10) {
            return 'danger';
        }

        if ($count > 0) {
            return 'warning';
        }

        return 'success';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['user']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all lockouts
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see lockouts from their organization
        if ($user && $user->organization_id) {
            $query->whereHas('user', function ($subQuery) use ($user) {
                $subQuery->where('organization_id', $user->organization_id);
            });
        }

        return $query;
    }

    protected static function getActiveLockoutCount(): int
    {
        try {
            return static::getModel()::whereNull('unlocked_at')
                ->where(function (Builder $query) {
                    $query->whereNull('unlock_at')
                        ->orWhere('unlock_at', '>', now());
                })
                ->count();
        } catch (\Exception $e) {
            return 0;
        }
    }
}
