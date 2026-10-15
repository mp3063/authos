<?php

namespace App\Filament\Resources;

use App\Filament\Resources\RoleResource\Pages\CreateRole;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\RoleResource\Pages\ViewRole;
use App\Filament\Resources\RoleResource\RelationManagers\PermissionsRelationManager;
use App\Filament\Resources\RoleResource\RelationManagers\UsersRelationManager;
use App\Models\Organization;
use App\Models\Role;
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
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Resources\Resource;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Filters\Filter;
use Filament\Tables\Filters\SelectFilter;
use Filament\Tables\Table;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Models\Permission;
use UnitEnum;

class RoleResource extends Resource
{
    protected static ?string $model = Role::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    /**
     * @throws \Throwable
     */
    public static function form(Schema $schema): Schema
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        return $schema->schema([
            Section::make('Role Information')->schema([
                TextInput::make('name')
                    ->required()
                    ->unique(ignoreRecord: true)
                    ->maxLength(255)
                    ->helperText('Unique role identifier (e.g., super-admin, user-manager)'),

                Select::make('guard_name')
                    ->options([
                        'web' => 'Web',
                        'api' => 'API',
                    ])
                    ->default('web')
                    ->required()
                    ->reactive() // Update permissions when guard changes
                    ->helperText('Authentication guard for this role'),

                // Hidden field to set organization_id for non-super admins
                Select::make('organization_id')
                    ->relationship('organization', 'name')
                    ->default($user && $user->isSuperAdmin() ? null : $user?->organization_id)
                    ->disabled(! ($user && $user->isSuperAdmin()))
                    ->hidden(! ($user && $user->isSuperAdmin()))
                    ->reactive() // Update permissions when organization changes
                    ->helperText($user && $user->isSuperAdmin() ? 'Leave empty for global role' : 'Organization scope'),
            ])->columns(3)->columnSpanFull(),

            Section::make('Permissions')->schema([
                Select::make('permission_template')
                    ->label('Start from template')
                    ->options(self::permissionTemplateOptions())
                    ->placeholder('None')
                    ->visible(fn (): bool => (bool) auth()->user()?->isSuperAdmin())
                    ->dehydrated(false)
                    ->live()
                    ->afterStateUpdated(fn ($state, $get, $set, $record) => self::applyPermissionTemplate($state, $get, $set, $record))
                    ->helperText('Ticks the permissions of a default role; you can still adjust them below'),

                CheckboxList::make('permissions')
                    ->disabled(fn (): bool => ! auth()->user()?->isSuperAdmin())
                    ->relationship('permissions', 'name', fn ($query, $get, $record) => self::scopePermissionOptions(
                        $query,
                        $get('guard_name') ?? $record?->guard_name ?? 'web',
                        $get('organization_id') ?? $record?->organization_id,
                    ))
                    ->columns(['default' => 1, 'sm' => 2, 'lg' => 3, 'xl' => 4])
                    ->gridDirection('row')
                    ->bulkToggleable()
                    ->searchable()
                    ->helperText('Select permissions to assign to this role'),
            ])->columnSpanFull(),
        ]);
    }

    /**
     * @return array<string, string>
     */
    private static function permissionTemplateOptions(): array
    {
        $roleNames = array_keys((new Organization)->getDefaultRoles());

        return ['Super Admin' => 'Super Admin (all permissions)'] + array_combine($roleNames, $roleNames);
    }

    private static function applyPermissionTemplate(?string $template, $get, $set, ?Model $record): void
    {
        if (! $template) {
            return;
        }

        $organizationId = $get('organization_id') ?? $record?->organization_id;
        $options = self::scopePermissionOptions(
            Permission::query(),
            $get('guard_name') ?? $record?->guard_name ?? 'web',
            $organizationId,
        );

        if ($template === 'Super Admin') {
            $set('permissions', $options->pluck('id')->map(fn ($id): string => (string) $id)->all());

            return;
        }

        $names = (new Organization)->getDefaultRoles()[$template] ?? [];
        $permissions = $options->whereIn('name', $names)->pluck('name', 'id');

        $set('permissions', $permissions->keys()->map(fn ($id): string => (string) $id)->all());

        $missing = array_diff($names, $permissions->all());

        if ($missing !== []) {
            Notification::make()
                ->warning()
                ->title($organizationId === null
                    ? 'Some template permissions exist only per organization'
                    : 'Some template permissions are not available here')
                ->body($organizationId === null
                    ? 'Choose an organization to include: '.implode(', ', $missing)
                    : implode(', ', $missing))
                ->send();
        }
    }

    private static function scopePermissionOptions(Builder $query, string $guardName, $organizationId): Builder
    {
        // CRITICAL FIX: Filter by guard_name to prevent showing duplicate permissions
        $query->where('guard_name', $guardName);

        // CRITICAL FIX: Deduplicate permissions - prioritize organization-specific over global
        // Use a subquery to find permission names that exist for this specific organization
        $orgSpecificNames = Permission::query()
            ->where('guard_name', $guardName)
            ->where('organization_id', $organizationId)
            ->pluck('name');

        // Show organization-specific permissions + global permissions not in organization scope
        $query->where(function ($subQuery) use ($organizationId, $orgSpecificNames) {
            $subQuery->where('organization_id', $organizationId)
                ->orWhere(function ($q2) use ($orgSpecificNames) {
                    $q2->whereNull('organization_id')
                        ->whereNotIn('name', $orgSpecificNames);
                });
        });

        return $query;
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table
            ->columns(self::tableColumns())
            ->filters(self::tableFilters())
            ->recordActions(self::tableRecordActions())
            ->toolbarActions(self::tableToolbarActions())
            ->defaultSort('name');
    }

    private static function tableColumns(): array
    {
        return [
            TextColumn::make('name')->searchable()->sortable()->weight('bold')->badge()->color('primary'),

            TextColumn::make('guard_name')->badge()->color('gray')->sortable(),

            TextColumn::make('organization.name')
                ->label('Organization')
                ->badge()
                ->color(fn ($record) => $record->organization_id ? 'success' : 'warning')
                ->formatStateUsing(fn ($state, $record) => $state ?: 'Global')
                ->sortable()
                ->searchable(),

            TextColumn::make('permissions_count')
                ->label('Permissions')
                ->getStateUsing(function ($record) {
                    // CRITICAL FIX: Count only unique permissions by filtering guard_name and deduplicating
                    $guardName = $record->guard_name;
                    $organizationId = $record->organization_id;

                    // Get organization-specific permission names to exclude from global permissions
                    $orgSpecificNames = Permission::query()
                        ->where('guard_name', $guardName)
                        ->where('organization_id', $organizationId)
                        ->pluck('name');

                    // Count unique permissions matching this role's guard
                    return $record->permissions()
                        ->where('guard_name', $guardName)
                        ->where(function ($subQuery) use ($organizationId, $orgSpecificNames) {
                            $subQuery->where('organization_id', $organizationId)
                                ->orWhere(function ($q2) use ($orgSpecificNames) {
                                    $q2->whereNull('organization_id')
                                        ->whereNotIn('name', $orgSpecificNames);
                                });
                        })
                        ->count();
                })
                ->sortable()
                ->alignCenter(),

            TextColumn::make('users_count')->counts('users')->label('Users')->sortable()->alignCenter(),

            TextColumn::make('permissions.name')
                ->label('Key Permissions')
                ->getStateUsing(function ($record) {
                    // CRITICAL FIX: Filter permissions by role's guard_name to prevent duplicates
                    $guardName = $record->guard_name;
                    $organizationId = $record->organization_id;

                    // Get organization-specific permission names to exclude from global permissions
                    $orgSpecificNames = Permission::query()
                        ->where('guard_name', $guardName)
                        ->where('organization_id', $organizationId)
                        ->pluck('name');

                    // Get unique permissions matching this role's guard
                    return $record->permissions()
                        ->where('guard_name', $guardName)
                        ->where(function ($subQuery) use ($organizationId, $orgSpecificNames) {
                            $subQuery->where('organization_id', $organizationId)
                                ->orWhere(function ($q2) use ($orgSpecificNames) {
                                    $q2->whereNull('organization_id')
                                        ->whereNotIn('name', $orgSpecificNames);
                                });
                        })
                        ->pluck('name')
                        ->toArray();
                })
                ->listWithLineBreaks()
                ->limitList(3)
                ->expandableLimitedList()
                ->badge(),

            TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

            TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ];
    }

    private static function tableFilters(): array
    {
        return [
            SelectFilter::make('guard_name')->options([
                'web' => 'Web',
                'api' => 'API',
            ]),

            SelectFilter::make('organization_id')
                ->label('Organization')
                ->relationship('organization', 'name')
                ->placeholder('All Organizations')
                ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

            Filter::make('scope')
                ->label('Role Scope')
                ->schema([
                    Select::make('scope')->options([
                        'global' => 'Global Roles',
                        'organization' => 'Organization Roles',
                    ])->placeholder('All Roles'),
                ])
                ->query(function (Builder $query, array $data): Builder {
                    return match ($data['scope'] ?? null) {
                        'global' => $query->whereNull('organization_id'),
                        'organization' => $query->whereNotNull('organization_id'),
                        default => $query,
                    };
                })
                ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

            Filter::make('has_users')->query(fn (Builder $query): Builder => $query->has('users'))->label('Has Users'),

            Filter::make('default_roles')->query(fn (Builder $query): Builder => $query->whereIn('name', [
                'Organization Owner',
                'Organization Admin',
                'Organization Member',
                'Application Manager',
                'User Manager',
                'Auditor',
            ]))->label('Default Roles'),
        ];
    }

    private static function tableRecordActions(): array
    {
        return [
            ActionGroup::make([
                ViewAction::make(),
                EditAction::make(),

                Action::make('duplicate')->authorize('create')->label('Duplicate Role')->icon('heroicon-o-squares-plus')->color('gray')->schema([
                    TextInput::make('name')->required()->placeholder('New role name')->helperText('Enter name for the duplicated role'),
                ])->action(function ($record, $data) {
                    $newRole = $record->replicate(['users_count', 'permissions_count']);
                    $newRole->name = $data['name'];
                    $newRole->save();
                    $newRole->permissions()->sync($record->permissions);

                    Notification::make()
                        ->title('Role duplicated successfully')
                        ->body("Created new role '{$data['name']}' with same permissions")
                        ->success()
                        ->send();
                }),

                DeleteAction::make()
                    ->requiresConfirmation()
                    ->modalDescription('Are you sure you want to delete this role? Users with this role will lose associated permissions.')
                    ->before(function ($record) {
                        if ($record->users()->count() > 0) {
                            Notification::make()
                                ->title('Cannot delete role')
                                ->body('This role is assigned to users. Remove users first.')
                                ->danger()
                                ->send();

                            return false;
                        }

                        return true;
                    }),
            ]),
        ];
    }

    private static function tableToolbarActions(): array
    {
        return [
            BulkActionGroup::make([
                DeleteBulkAction::make()->authorizeIndividualRecords()->requiresConfirmation()->modalDescription('Are you sure you want to delete these roles?'),

                BulkAction::make('assign_permission')
                    ->authorize('update')
                    ->authorizeIndividualRecords('update')
                    ->label('Assign Permission')
                    ->icon('heroicon-o-plus')
                    ->color('success')
                    ->schema([
                        Select::make('permission')->relationship('permissions', 'name')->required()->searchable()->preload(),
                    ])->action(function ($records, $data) {
                        foreach ($records as $record) {
                            $record->permissions()->syncWithoutDetaching([$data['permission']]);
                        }
                    })
                    ->successNotificationTitle('Permission assigned to selected roles')
                    ->failureNotificationTitle(fn (int $successCount, int $totalCount): string => "Permission assigned to {$successCount} of {$totalCount} roles"),
            ]),
        ];
    }

    public static function getRelations(): array
    {
        return [
            UsersRelationManager::class,
            PermissionsRelationManager::class,
        ];
    }

    public static function getPages(): array
    {
        return [
            'index' => ListRoles::route('/'),
            'create' => CreateRole::route('/create'),
            'view' => ViewRole::route('/{record}'),
            'edit' => EditRole::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadge(): ?string
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        if ($user && $user->isSuperAdmin()) {
            return static::getModel()::count();
        }

        return static::getModel()::where(function ($query) use ($user) {
            $query->where('organization_id', $user?->organization_id)
                ->orWhereNull('organization_id');
        })->count();
    }

    public static function getEloquentQuery(): EloquentBuilder
    {
        $query = parent::getEloquentQuery();

        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can see all roles
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Organization users can only see their organization's roles + global roles
        return $query->where(function ($subQuery) use ($user) {
            $subQuery->where('organization_id', $user?->organization_id)
                ->orWhereNull('organization_id');
        });
    }

    public static function getDeleteAuthorizationResponse(Model $record): Response
    {
        if (in_array($record->name, ['Super Admin', 'System Administrator'], true)) {
            return Response::deny();
        }

        return parent::getDeleteAuthorizationResponse($record);
    }
}
