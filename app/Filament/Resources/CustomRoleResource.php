<?php

namespace App\Filament\Resources;

use App\Filament\Resources\CustomRoleResource\Pages\CreateCustomRole;
use App\Filament\Resources\CustomRoleResource\Pages\EditCustomRole;
use App\Filament\Resources\CustomRoleResource\Pages\ListCustomRoles;
use App\Filament\Resources\CustomRoleResource\Pages\ViewCustomRole;
use App\Models\CustomRole;
use App\Models\User;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
use Filament\Facades\Filament;
use Filament\Forms\Components\CheckboxList;
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

class CustomRoleResource extends Resource
{
    protected static ?string $model = CustomRole::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 3;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        return $schema->schema([
            Section::make('Role Details')
                ->schema([
                    TextInput::make('name')
                        ->label('Role Name')
                        ->required()
                        ->maxLength(255)
                        ->unique(ignoreRecord: true)
                        ->helperText('Unique identifier for this role (e.g., content_manager)'),

                    TextInput::make('display_name')
                        ->label('Display Name')
                        ->maxLength(255)
                        ->helperText('Human-readable name shown in the UI'),

                    Textarea::make('description')
                        ->label('Description')
                        ->maxLength(500)
                        ->rows(2)
                        ->helperText('Brief description of this role\'s purpose')
                        ->columnSpanFull(),

                    Select::make('organization_id')
                        ->label('Organization')
                        ->relationship('organization', 'name')
                        ->searchable()
                        ->preload()
                        ->required()
                        ->disabled(fn ($context) => $context === 'edit')
                        ->helperText('Organization this role belongs to'),

                    Toggle::make('is_active')
                        ->label('Active')
                        ->default(true)
                        ->helperText('Inactive roles cannot be assigned to users'),

                    Toggle::make('is_default')
                        ->label('Default Role')
                        ->default(false)
                        ->helperText('Default roles are automatically assigned to new users'),

                    Toggle::make('is_system')
                        ->label('System Role')
                        ->default(false)
                        ->disabled(fn ($context, $record) => $context === 'edit' && $record?->is_system)
                        ->helperText('System roles cannot be deleted'),
                ])->columns(2),

            Section::make('Permissions')
                ->schema([
                    CheckboxList::make('permissions')
                        ->label('Assign Permissions')
                        ->options(function () {
                            $categories = CustomRole::getPermissionCategories();
                            $options = [];

                            foreach ($categories as $category => $permissions) {
                                foreach ($permissions as $permission) {
                                    $options[$category][$permission] = self::formatPermissionLabel($permission);
                                }
                            }

                            return $options;
                        })
                        ->searchable()
                        ->bulkToggleable()
                        ->columns(3)
                        ->helperText('Select the permissions this role should have.')
                        ->columnSpanFull(),
                ])
                ->collapsible()
                ->collapsed(fn ($context) => $context === 'edit'),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
            TextColumn::make('name')
                ->searchable()
                ->sortable()
                ->weight('bold')
                ->description(fn (CustomRole $record): ?string => $record->description ? \Illuminate\Support\Str::limit($record->description, 50) : null),

            TextColumn::make('display_name')
                ->label('Display Name')
                ->searchable()
                ->sortable()
                ->toggleable(),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->searchable()
                ->sortable()
                ->badge()
                ->toggleable(),

            IconColumn::make('is_active')
                ->label('Active')
                ->boolean()
                ->sortable()
                ->trueIcon('heroicon-o-check-circle')
                ->falseIcon('heroicon-o-x-circle')
                ->trueColor('success')
                ->falseColor('danger'),

            IconColumn::make('is_system')
                ->label('System')
                ->boolean()
                ->sortable()
                ->trueIcon('heroicon-o-lock-closed')
                ->falseIcon('heroicon-o-lock-open')
                ->trueColor('warning')
                ->falseColor('gray'),

            TextColumn::make('is_default')
                ->label('Default')
                ->badge()
                ->formatStateUsing(fn ($state): string => $state ? 'Default' : 'Custom')
                ->color(fn ($state): string => $state ? 'info' : 'gray')
                ->sortable(),

            TextColumn::make('users_count')
                ->counts('users')
                ->label('Users')
                ->sortable()
                ->alignCenter(),

            TextColumn::make('permissions')
                ->label('Permissions')
                ->badge()
                ->color('info')
                ->formatStateUsing(fn ($state, CustomRole $record): string => $record->getPermissionCount().' permissions')
                ->tooltip(fn (CustomRole $record): string => implode(', ', array_slice($record->permissions ?? [], 0, 5)).(count($record->permissions ?? []) > 5 ? '...' : '')),

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

            SelectFilter::make('is_system')
                ->label('Role Type')
                ->options([
                    '1' => 'System Roles',
                    '0' => 'User-Defined Roles',
                ])
                ->query(function (Builder $query, array $data) {
                    if (filled($data['value'])) {
                        $query->where('is_system', (bool) $data['value']);
                    }
                }),
        ])->recordActions([
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),
                Action::make('clone')
                    ->icon('heroicon-o-document-duplicate')
                    ->color('info')
                    ->form([
                        TextInput::make('new_name')
                            ->label('New Role Name')
                            ->required()
                            ->maxLength(255)
                            ->helperText('Enter a unique name for the cloned role'),
                    ])
                    ->modalHeading('Clone Role')
                    ->modalDescription('Create a copy of this role with a new name. All permissions will be copied.')
                    ->action(function (CustomRole $record, array $data) {
                        try {
                            $cloned = $record->cloneRole($data['new_name']);

                            Notification::make()
                                ->title('Role cloned successfully!')
                                ->body("New role \"{$cloned->name}\" created with {$cloned->getPermissionCount()} permissions.")
                                ->success()
                                ->send();
                        } catch (\Exception $e) {
                            Notification::make()
                                ->title('Failed to clone role')
                                ->body($e->getMessage())
                                ->danger()
                                ->send();
                        }
                    }),
                DeleteAction::make()
                    ->hidden(fn (CustomRole $record): bool => $record->is_system)
                    ->requiresConfirmation()
                    ->modalHeading('Delete Role')
                    ->modalDescription('Are you sure you want to delete this role? Users assigned to this role will lose these permissions.'),
            ]),
        ])->toolbarActions([
            BulkActionGroup::make([
                BulkAction::make('activate')
                    ->icon('heroicon-o-check-circle')
                    ->color('success')
                    ->requiresConfirmation()
                    ->action(function (Collection $records) {
                        $records->each(fn (CustomRole $record) => $record->update(['is_active' => true]));

                        Notification::make()
                            ->title('Roles activated successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),
                BulkAction::make('deactivate')
                    ->icon('heroicon-o-x-circle')
                    ->color('warning')
                    ->requiresConfirmation()
                    ->action(function (Collection $records) {
                        $records->each(fn (CustomRole $record) => $record->update(['is_active' => false]));

                        Notification::make()
                            ->title('Roles deactivated successfully')
                            ->success()
                            ->send();
                    })
                    ->deselectRecordsAfterCompletion(),
                DeleteBulkAction::make()
                    ->requiresConfirmation()
                    ->modalHeading('Delete Roles')
                    ->modalDescription('Are you sure you want to delete these roles? This action cannot be undone.'),
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
            'index' => ListCustomRoles::route('/'),
            'create' => CreateCustomRole::route('/create'),
            'view' => ViewCustomRole::route('/{record}'),
            'edit' => EditCustomRole::route('/{record}/edit'),
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
        return 'primary';
    }

    /**
     * Format a permission string into a human-readable label.
     */
    protected static function formatPermissionLabel(string $permission): string
    {
        $parts = explode('.', $permission);
        $action = end($parts);

        return ucfirst(str_replace('_', ' ', $action));
    }
}
