<?php

namespace App\Filament\Resources;

use App\Filament\Resources\BulkImportJobResource\Pages\ListBulkImportJobs;
use App\Filament\Resources\BulkImportJobResource\Pages\ViewBulkImportJob;
use App\Models\BulkImportJob;
use App\Models\Organization;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
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

class BulkImportJobResource extends Resource
{
    protected static ?string $model = BulkImportJob::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'System';

    protected static ?int $navigationSort = 2;

    protected static ?string $navigationLabel = 'Import/Export Jobs';

    protected static ?string $modelLabel = 'Import/Export Job';

    protected static ?string $pluralModelLabel = 'Import/Export Jobs';

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
            TextColumn::make('id')
                ->label('ID')
                ->sortable(),

            TextColumn::make('type')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'import' => 'primary',
                    'export' => 'success',
                    'users' => 'info',
                    default => 'gray',
                })
                ->formatStateUsing(fn (string $state): string => ucfirst($state))
                ->sortable(),

            TextColumn::make('status')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'pending' => 'warning',
                    'processing' => 'info',
                    'completed' => 'success',
                    'completed_with_errors' => 'warning',
                    'failed' => 'danger',
                    'cancelled' => 'gray',
                    default => 'gray',
                })
                ->formatStateUsing(fn (string $state): string => ucwords(str_replace('_', ' ', $state)))
                ->sortable(),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->badge()
                ->searchable()
                ->sortable(),

            TextColumn::make('total_records')
                ->label('Total')
                ->numeric()
                ->sortable(),

            TextColumn::make('processed_records')
                ->label('Processed')
                ->numeric()
                ->sortable(),

            TextColumn::make('successful_records')
                ->label('Successful')
                ->numeric()
                ->sortable()
                ->color('success'),

            TextColumn::make('failed_records')
                ->label('Failed')
                ->numeric()
                ->sortable()
                ->color('danger'),

            TextColumn::make('progress')
                ->label('Progress')
                ->state(fn (BulkImportJob $record): string => $record->getProgressPercentage() . '%')
                ->color(fn (BulkImportJob $record): string => match (true) {
                    $record->getProgressPercentage() >= 100 => 'success',
                    $record->getProgressPercentage() >= 50 => 'info',
                    $record->getProgressPercentage() > 0 => 'warning',
                    default => 'gray',
                })
                ->badge(),

            TextColumn::make('file_format')
                ->label('Format')
                ->badge()
                ->formatStateUsing(fn (?string $state): string => $state ? strtoupper($state) : 'N/A')
                ->color('info'),

            TextColumn::make('started_at')
                ->dateTime()
                ->sortable()
                ->toggleable(),

            TextColumn::make('completed_at')
                ->dateTime()
                ->sortable()
                ->toggleable(),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('status')
                ->options([
                    'pending' => 'Pending',
                    'processing' => 'Processing',
                    'completed' => 'Completed',
                    'completed_with_errors' => 'Completed with Errors',
                    'failed' => 'Failed',
                    'cancelled' => 'Cancelled',
                ]),

            SelectFilter::make('type')
                ->options([
                    'import' => 'Import',
                    'export' => 'Export',
                    'users' => 'Users',
                ]),

            SelectFilter::make('organization_id')
                ->label('Organization')
                ->options(fn () => Organization::pluck('name', 'id')->toArray())
                ->visible(fn (): bool => static::isSuperAdmin())
                ->searchable(),
        ])->recordActions([
            ViewAction::make(),

            Action::make('retry')
                ->label('Retry')
                ->icon('heroicon-o-arrow-path')
                ->color('info')
                ->requiresConfirmation()
                ->modalHeading('Retry Job')
                ->modalDescription('Are you sure you want to retry this failed job? The status will be reset to pending.')
                ->visible(fn (BulkImportJob $record): bool => $record->hasFailed())
                ->action(function (BulkImportJob $record) {
                    $record->update([
                        'status' => BulkImportJob::STATUS_PENDING,
                        'processed_records' => 0,
                        'successful_records' => 0,
                        'failed_records' => 0,
                        'errors' => null,
                        'started_at' => null,
                        'completed_at' => null,
                        'processing_time' => null,
                    ]);

                    Notification::make()
                        ->title('Job queued for retry')
                        ->body("Job #{$record->id} has been reset to pending.")
                        ->success()
                        ->send();
                }),

            Action::make('cancel')
                ->label('Cancel')
                ->icon('heroicon-o-x-circle')
                ->color('danger')
                ->requiresConfirmation()
                ->modalHeading('Cancel Job')
                ->modalDescription('Are you sure you want to cancel this job? This action cannot be undone.')
                ->visible(fn (BulkImportJob $record): bool => $record->isInProgress())
                ->action(function (BulkImportJob $record) {
                    $record->markAsCancelled();

                    Notification::make()
                        ->title('Job cancelled')
                        ->body("Job #{$record->id} has been cancelled.")
                        ->success()
                        ->send();
                }),
        ])->defaultSort('created_at', 'desc')->poll('15s')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListBulkImportJobs::route('/'),
            'view' => ViewBulkImportJob::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        try {
            $count = static::getModel()::where('status', BulkImportJob::STATUS_PROCESSING)->count();

            return $count > 0 ? (string) $count : null;
        } catch (\Exception) {
            return null;
        }
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'info';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['organization', 'createdBy']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all jobs
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see jobs from their organization
        if ($user && $user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    protected static function isSuperAdmin(): bool
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        return $user && $user->isSuperAdmin();
    }
}
