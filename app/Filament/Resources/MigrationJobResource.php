<?php

namespace App\Filament\Resources;

use App\Filament\Resources\MigrationJobResource\Pages\ListMigrationJobs;
use App\Filament\Resources\MigrationJobResource\Pages\ViewMigrationJob;
use App\Models\MigrationJob;
use App\Models\Organization;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class MigrationJobResource extends Resource
{
    protected static ?string $model = MigrationJob::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'System';

    protected static ?int $navigationSort = 3;

    protected static ?string $navigationLabel = 'Migration Jobs';

    protected static ?string $modelLabel = 'Migration Job';

    protected static ?string $pluralModelLabel = 'Migration Jobs';

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
        /** @var User|null $authUser */
        $authUser = Filament::auth()->user();
        $isSuperAdmin = $authUser && $authUser->isSuperAdmin();

        return $table->columns([
            TextColumn::make('id')
                ->label('ID')
                ->sortable(),

            TextColumn::make('source')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'auth0' => 'info',
                    'okta' => 'warning',
                    'custom' => 'gray',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('status')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'pending' => 'warning',
                    'running' => 'info',
                    'completed' => 'success',
                    'failed' => 'danger',
                    'rolled_back' => 'gray',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->badge()
                ->searchable()
                ->sortable(),

            TextColumn::make('summary')
                ->label('Summary')
                ->state(fn (MigrationJob $record): string => $record->getSummary())
                ->limit(50)
                ->tooltip(fn (MigrationJob $record): string => $record->getSummary()),

            TextColumn::make('total_items')
                ->label('Total Items')
                ->sortable()
                ->numeric(),

            TextColumn::make('started_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('completed_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('error_message')
                ->label('Error')
                ->state(fn (MigrationJob $record): ?string => $record->error_message)
                ->limit(30)
                ->color('danger')
                ->tooltip(fn (MigrationJob $record): ?string => $record->error_message)
                ->placeholder('--'),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('status')
                ->options([
                    'pending' => 'Pending',
                    'running' => 'Running',
                    'completed' => 'Completed',
                    'failed' => 'Failed',
                ]),

            SelectFilter::make('source')
                ->options([
                    'auth0' => 'Auth0',
                    'okta' => 'Okta',
                    'custom' => 'Custom',
                ]),

            ...($isSuperAdmin ? [
                SelectFilter::make('organization_id')
                    ->label('Organization')
                    ->options(Organization::query()->pluck('name', 'id'))
                    ->searchable(),
            ] : []),
        ])->recordActions([
            ViewAction::make(),

            Action::make('retry')
                ->label('Retry')
                ->icon('heroicon-o-arrow-path')
                ->color('warning')
                ->visible(fn (MigrationJob $record): bool => $record->status === 'failed')
                ->requiresConfirmation()
                ->modalHeading('Retry Migration')
                ->modalDescription('Are you sure you want to retry this failed migration? The status will be reset to pending.')
                ->action(function (MigrationJob $record) {
                    $record->update([
                        'status' => 'pending',
                        'error_log' => null,
                    ]);

                    Notification::make()
                        ->title('Migration queued for retry')
                        ->body("Migration #{$record->id} has been reset to pending.")
                        ->success()
                        ->send();
                }),

            Action::make('rollback')
                ->label('Rollback')
                ->icon('heroicon-o-arrow-uturn-left')
                ->color('danger')
                ->visible(fn (MigrationJob $record): bool => $record->status === 'completed')
                ->requiresConfirmation()
                ->modalHeading('Rollback Migration')
                ->modalDescription('Are you sure you want to rollback this migration? This will delete all migrated data and cannot be undone.')
                ->action(function (MigrationJob $record) {
                    $record->rollback();

                    Notification::make()
                        ->title('Migration rolled back')
                        ->body("Migration #{$record->id} has been rolled back successfully.")
                        ->success()
                        ->send();
                }),

            DeleteAction::make(),
        ])->defaultSort('created_at', 'desc')->poll('15s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListMigrationJobs::route('/'),
            'view' => ViewMigrationJob::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('status', 'running')->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        $failedCount = static::getModel()::where('status', 'failed')->count();

        if ($failedCount > 0) {
            return 'danger';
        }

        $runningCount = static::getModel()::where('status', 'running')->count();

        if ($runningCount > 0) {
            return 'info';
        }

        return 'primary';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['organization']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all migration jobs
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see migration jobs from their organization
        if ($user && $user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }
}
