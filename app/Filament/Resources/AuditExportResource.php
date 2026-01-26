<?php

namespace App\Filament\Resources;

use App\Filament\Resources\AuditExportResource\Pages\ListAuditExports;
use App\Filament\Resources\AuditExportResource\Pages\ViewAuditExport;
use App\Models\AuditExport;
use App\Models\Organization;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\DeleteAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Resources\Resource;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use UnitEnum;

class AuditExportResource extends Resource
{
    protected static ?string $model = AuditExport::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Enterprise';

    protected static ?int $navigationSort = 4;

    protected static ?string $navigationLabel = 'Audit Exports';

    protected static ?string $modelLabel = 'Audit Export';

    protected static ?string $pluralModelLabel = 'Audit Exports';

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
            // Read-only resource, no form needed
        ]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        /** @var User|null $currentUser */
        $currentUser = Filament::auth()->user();
        $isSuperAdmin = $currentUser && $currentUser->isSuperAdmin();

        return $table->columns([
            TextColumn::make('id')
                ->label('ID')
                ->sortable(),

            TextColumn::make('type')
                ->badge()
                ->searchable()
                ->sortable(),

            TextColumn::make('status')
                ->badge()
                ->color(fn (string $state): string => match ($state) {
                    'pending' => 'warning',
                    'processing' => 'info',
                    'completed' => 'success',
                    'failed' => 'danger',
                    default => 'gray',
                })
                ->sortable(),

            TextColumn::make('organization.name')
                ->badge()
                ->searchable()
                ->sortable(),

            TextColumn::make('user.name')
                ->label('Requested By')
                ->searchable()
                ->sortable(),

            TextColumn::make('records_count')
                ->label('Records')
                ->numeric()
                ->sortable(),

            TextColumn::make('started_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('completed_at')
                ->dateTime()
                ->sortable(),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('status')
                ->options([
                    'completed' => 'Completed',
                    'pending' => 'Pending',
                    'processing' => 'Processing',
                    'failed' => 'Failed',
                ]),

            SelectFilter::make('type')
                ->options(function () {
                    return AuditExport::query()
                        ->distinct()
                        ->pluck('type', 'type')
                        ->toArray();
                }),

            SelectFilter::make('organization_id')
                ->label('Organization')
                ->options(fn () => Organization::pluck('name', 'id')->toArray())
                ->visible($isSuperAdmin),
        ])->recordActions([
            ViewAction::make(),

            Action::make('download')
                ->label('Download')
                ->icon('heroicon-o-arrow-down-tray')
                ->color('success')
                ->url(fn (AuditExport $record): ?string => $record->download_url)
                ->openUrlInNewTab()
                ->visible(fn (AuditExport $record): bool => $record->isCompleted() && ! empty($record->file_path)),

            DeleteAction::make(),
        ])->defaultSort('created_at', 'desc')->striped();
    }

    public static function getPages(): array
    {
        return [
            'index' => ListAuditExports::route('/'),
            'view' => ViewAuditExport::route('/{record}'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getModel()::where('status', 'completed')
            ->whereDate('created_at', today())
            ->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery()->with(['organization', 'user']);

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all audit exports
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Other users can only see exports from their organization
        if ($user && $user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }
}
