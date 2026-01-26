<?php

namespace App\Filament\Resources;

use App\Filament\Resources\ApplicationGroupResource\Pages\CreateApplicationGroup;
use App\Filament\Resources\ApplicationGroupResource\Pages\EditApplicationGroup;
use App\Filament\Resources\ApplicationGroupResource\Pages\ListApplicationGroups;
use App\Filament\Resources\ApplicationGroupResource\Pages\ViewApplicationGroup;
use App\Models\ApplicationGroup;
use App\Models\User;
use BackedEnum;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\CheckboxList;
use Filament\Forms\Components\KeyValue;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Components\Toggle;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\IconColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Filters\TernaryFilter;
use Filament\Tables\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use UnitEnum;

class ApplicationGroupResource extends Resource
{
    protected static ?string $model = ApplicationGroup::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'OAuth Management';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Group Details')->schema([
                TextInput::make('name')
                    ->required()
                    ->maxLength(255),

                Textarea::make('description')
                    ->rows(3)
                    ->columnSpanFull(),

                Select::make('organization_id')
                    ->label('Organization')
                    ->relationship('organization', 'name')
                    ->searchable()
                    ->preload()
                    ->required()
                    ->disabled(fn ($context) => $context === 'edit'),

                Select::make('parent_id')
                    ->label('Parent Group')
                    ->relationship('parent', 'name')
                    ->searchable()
                    ->preload()
                    ->nullable()
                    ->helperText('Leave empty for root group'),

                Toggle::make('is_active')
                    ->label('Active')
                    ->default(true),
            ])->columns(2),

            Section::make('Applications')->schema([
                CheckboxList::make('applications')
                    ->relationship('applications', 'name')
                    ->columns(2)
                    ->searchable()
                    ->bulkToggleable()
                    ->columnSpanFull(),
            ]),

            Section::make('Settings')->schema([
                KeyValue::make('settings')
                    ->columnSpanFull(),
            ])->collapsible(),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')
                ->searchable()
                ->sortable()
                ->weight('bold')
                ->description(fn (ApplicationGroup $record): string => $record->getFullPath()),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->badge()
                ->searchable()
                ->sortable()
                ->toggleable(),

            TextColumn::make('parent.name')
                ->label('Parent Group')
                ->placeholder('Root')
                ->sortable()
                ->toggleable(),

            IconColumn::make('is_active')
                ->label('Active')
                ->boolean()
                ->sortable(),

            TextColumn::make('applications_count')
                ->counts('applications')
                ->label('Applications')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('children_count')
                ->counts('children')
                ->label('Children')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('created_at')
                ->dateTime()
                ->sortable()
                ->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
            SelectFilter::make('organization')
                ->relationship('organization', 'name')
                ->searchable()
                ->preload()
                ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

            TernaryFilter::make('is_active')
                ->label('Active Status')
                ->boolean()
                ->trueLabel('Active only')
                ->falseLabel('Inactive only')
                ->native(false),

            TernaryFilter::make('root_groups')
                ->label('Root Groups')
                ->queries(
                    true: fn (Builder $query) => $query->whereNull('parent_id'),
                    false: fn (Builder $query) => $query->whereNotNull('parent_id'),
                    blank: fn (Builder $query) => $query,
                ),
        ])->recordActions([
            ViewAction::make(),
            EditAction::make(),
            DeleteAction::make()
                ->hidden(fn (ApplicationGroup $record): bool => $record->hasChildren()),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('activate')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->requiresConfirmation()
                    ->action(function (Collection $records) {
                        $records->each(fn (ApplicationGroup $record) => $record->update(['is_active' => true]));

                        Notification::make()
                            ->title('Groups activated successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),

                BulkAction::make('deactivate')
                    ->icon('heroicon-o-x-circle')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (Collection $records) {
                        $records->each(fn (ApplicationGroup $record) => $record->update(['is_active' => false]));

                        Notification::make()
                            ->title('Groups deactivated successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),

                BulkAction::make('delete')
                    ->icon('heroicon-o-trash')
                    ->color('danger')
                    ->requiresConfirmation()
                    ->action(function (Collection $records) {
                        $deleted = 0;
                        $skipped = 0;

                        foreach ($records as $record) {
                            if ($record->hasChildren()) {
                                $skipped++;
                            } else {
                                $record->delete();
                                $deleted++;
                            }
                        }

                        $message = "{$deleted} group(s) deleted.";
                        if ($skipped > 0) {
                            $message .= " {$skipped} group(s) skipped (have children).";
                        }

                        Notification::make()
                            ->title($message)
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),
            ]),
        ])->defaultSort('created_at', 'desc');
    }

    public static function getRelations(): array
    {
        return [];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListApplicationGroups::route('/'),
            'create' => CreateApplicationGroup::route('/create'),
            'view' => ViewApplicationGroup::route('/{record}'),
            'edit' => EditApplicationGroup::route('/{record}/edit'),
        ];
    }

    public static function getEloquentQuery(): Builder
    {
        $query = parent::getEloquentQuery();
        $user = Filament::auth()->user();

        if (! $user instanceof User) {
            return $query->whereRaw('1 = 0');
        }

        if ($user->isSuperAdmin()) {
            return $query;
        }

        if ($user->organization_id) {
            $query->where('organization_id', $user->organization_id);
        }

        return $query;
    }

    public static function getNavigationBadge(): ?string
    {
        $count = static::getEloquentQuery()->where('is_active', true)->count();

        return $count > 0 ? (string) $count : null;
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
    }
}
