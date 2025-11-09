<?php

namespace App\Filament\Resources;

use App\Filament\Resources\PermissionResource\Pages\CreatePermission;
use App\Filament\Resources\PermissionResource\Pages\EditPermission;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\PermissionResource\Pages\ViewPermission;
use App\Models\Permission;
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
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use UnitEnum;

class PermissionResource extends Resource
{
    protected static ?string $model = Permission::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 2;

    protected static ?string $recordTitleAttribute = 'name';

    /**
     * @throws \Throwable
     */
    public static function form(Schema $schema): Schema
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        return $schema
            ->schema([
                Section::make('Permission Information')
                    ->schema([
                        TextInput::make('name')
                            ->required()
                            ->unique(ignoreRecord: true)
                            ->maxLength(255)
                            ->helperText('Permission identifier (e.g., create-users, manage-applications)'),

                        Select::make('guard_name')
                            ->options([
                                'web' => 'Web',
                                'api' => 'API',
                            ])
                            ->default('web')
                            ->required()
                            ->reactive() // Update roles when guard changes
                            ->helperText('Authentication guard for this permission'),

                        // Hidden field to set organization_id for non-super admins
                        Select::make('organization_id')
                            ->relationship('organization', 'name')
                            ->default($user && $user->isSuperAdmin() ? null : $user?->organization_id)
                            ->disabled(! ($user && $user->isSuperAdmin()))
                            ->hidden(! ($user && $user->isSuperAdmin()))
                            ->reactive() // Update roles when organization changes
                            ->helperText($user && $user->isSuperAdmin() ? 'Leave empty for global permission' : 'Organization scope'),
                    ])->columns(),

                Section::make('Assignment')
                    ->schema([
                        Select::make('roles')
                            ->relationship('roles', 'name', function ($query, $get, $record) use ($user) {
                                // Get the permission's guard_name (from form data or existing record)
                                $guardName = $get('guard_name') ?? $record?->guard_name ?? 'web';

                                // Get the permission's organization_id (from form data or existing record)
                                $organizationId = $get('organization_id') ?? $record?->organization_id;

                                // CRITICAL FIX: Filter by guard_name to prevent showing duplicate roles
                                $query->where('guard_name', $guardName);

                                // CRITICAL FIX: Deduplicate roles - prioritize organization-specific over global
                                // Use a subquery to find role names that exist for this specific organization
                                $orgSpecificNames = \Spatie\Permission\Models\Role::query()
                                    ->where('guard_name', $guardName)
                                    ->where('organization_id', $organizationId)
                                    ->pluck('name');

                                // Show organization-specific roles + global roles not in organization scope
                                $query->where(function ($q) use ($organizationId, $orgSpecificNames) {
                                    $q->where('organization_id', $organizationId)
                                        ->orWhere(function ($q2) use ($orgSpecificNames) {
                                            $q2->whereNull('organization_id')
                                                ->whereNotIn('name', $orgSpecificNames);
                                        });
                                });
                            })
                            ->multiple()
                            ->preload()
                            ->searchable()
                            ->helperText('Roles that should have this permission'),
                    ]),
            ]);
    }

    /**
     * @throws \Throwable
     */
    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('name')
                    ->searchable()
                    ->sortable()
                    ->weight('bold')
                    ->badge()
                    ->color('success'),

                TextColumn::make('guard_name')
                    ->badge()
                    ->color('gray')
                    ->sortable(),

                TextColumn::make('organization.name')
                    ->label('Organization')
                    ->badge()
                    ->color(fn ($record) => $record->organization_id ? 'success' : 'warning')
                    ->formatStateUsing(fn ($state, $record) => $state ?: 'Global')
                    ->sortable()
                    ->searchable(),

                TextColumn::make('category')
                    ->label('Category')
                    ->formatStateUsing(function ($record) {
                        if (str_contains($record->name, '.')) {
                            $parts = explode('.', $record->name);

                            return ucfirst($parts[0]);
                        }

                        $parts = explode(' ', $record->name);

                        return ucfirst($parts[1] ?? 'general');
                    })
                    ->badge()
                    ->color('info'),

                TextColumn::make('roles_count')
                    ->label('Roles')
                    ->getStateUsing(function ($record) {
                        // CRITICAL FIX: Count only unique roles by filtering guard_name and deduplicating
                        $guardName = $record->guard_name;
                        $organizationId = $record->organization_id;

                        // Get organization-specific role names to exclude from global roles
                        $orgSpecificNames = \Spatie\Permission\Models\Role::query()
                            ->where('guard_name', $guardName)
                            ->where('organization_id', $organizationId)
                            ->pluck('name');

                        // Count unique roles matching this permission's guard
                        return $record->roles()
                            ->where('guard_name', $guardName)
                            ->where(function ($q) use ($organizationId, $orgSpecificNames) {
                                $q->where('organization_id', $organizationId)
                                    ->orWhere(function ($q2) use ($orgSpecificNames) {
                                        $q2->whereNull('organization_id')
                                            ->whereNotIn('name', $orgSpecificNames);
                                    });
                            })
                            ->count();
                    })
                    ->sortable()
                    ->alignCenter(),

                TextColumn::make('users_count')
                    ->counts('users')
                    ->label('Direct Users')
                    ->sortable()
                    ->alignCenter(),

                TextColumn::make('roles.name')
                    ->label('Assigned Roles')
                    ->getStateUsing(function ($record) {
                        // CRITICAL FIX: Filter roles by permission's guard_name to prevent duplicates
                        $guardName = $record->guard_name;
                        $organizationId = $record->organization_id;

                        // Get organization-specific role names to exclude from global roles
                        $orgSpecificNames = \Spatie\Permission\Models\Role::query()
                            ->where('guard_name', $guardName)
                            ->where('organization_id', $organizationId)
                            ->pluck('name');

                        // Get unique roles matching this permission's guard
                        return $record->roles()
                            ->where('guard_name', $guardName)
                            ->where(function ($q) use ($organizationId, $orgSpecificNames) {
                                $q->where('organization_id', $organizationId)
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

                TextColumn::make('created_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),

                TextColumn::make('updated_at')
                    ->dateTime()
                    ->sortable()
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->filters([
                SelectFilter::make('guard_name')
                    ->options([
                        'web' => 'Web',
                        'api' => 'API',
                    ]),

                SelectFilter::make('organization_id')
                    ->label('Organization')
                    ->relationship('organization', 'name')
                    ->placeholder('All Organizations')
                    ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

                Filter::make('scope')
                    ->label('Permission Scope')
                    ->schema([
                        Select::make('scope')->options([
                            'global' => 'Global Permissions',
                            'organization' => 'Organization Permissions',
                        ])->placeholder('All Permissions'),
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return match ($data['scope'] ?? null) {
                            'global' => $query->whereNull('organization_id'),
                            'organization' => $query->whereNotNull('organization_id'),
                            default => $query,
                        };
                    })
                    ->visible(fn () => Filament::auth()->user()->isSuperAdmin()),

                SelectFilter::make('category')
                    ->options([
                        'users' => 'User Management',
                        'applications' => 'Application Management',
                        'organizations' => 'Organization Management',
                        'roles' => 'Role Management',
                        'permissions' => 'Permission Management',
                        'auth_logs' => 'Log Management',
                        'system' => 'System Administration',
                    ])
                    ->query(function (Builder $query, array $data): Builder {
                        return $query->when(
                            $data['value'],
                            fn (Builder $query, $category): Builder => $query->where('name', 'like', "$category.%")
                                ->orWhere('name', 'like', "%$category%"),
                        );
                    }),

                Filter::make('has_roles')
                    ->query(fn (Builder $query): Builder => $query->has('roles'))
                    ->label('Assigned to Roles'),

                Filter::make('direct_user_permissions')
                    ->query(fn (Builder $query): Builder => $query->has('users'))
                    ->label('Direct User Permissions'),
            ])
            ->recordActions([
                ActionGroup::make([
                    ViewAction::make(),
                    EditAction::make(),

                    Action::make('assign_to_role')
                        ->label('Assign to Role')
                        ->icon('heroicon-o-plus')
                        ->color('success')
                        ->schema([
                            Select::make('role')
                                ->relationship('roles', 'name', function ($query, $livewire) {
                                    $record = $livewire->getRecord();
                                    $guardName = $record->guard_name;
                                    $organizationId = $record->organization_id;

                                    // Filter by guard_name to prevent duplicates
                                    $query->where('guard_name', $guardName);

                                    // Deduplicate roles
                                    $orgSpecificNames = \Spatie\Permission\Models\Role::query()
                                        ->where('guard_name', $guardName)
                                        ->where('organization_id', $organizationId)
                                        ->pluck('name');

                                    $query->where(function ($q) use ($organizationId, $orgSpecificNames) {
                                        $q->where('organization_id', $organizationId)
                                            ->orWhere(function ($q2) use ($orgSpecificNames) {
                                                $q2->whereNull('organization_id')
                                                    ->whereNotIn('name', $orgSpecificNames);
                                            });
                                    });
                                })
                                ->required()
                                ->searchable()
                                ->preload(),
                        ])
                        ->action(function ($record, $data) {
                            $record->roles()->syncWithoutDetaching([$data['role']]);
                            Notification::make()
                                ->title('Permission assigned to role')
                                ->success()
                                ->send();
                        }),

                    DeleteAction::make()
                        ->requiresConfirmation()
                        ->modalDescription('Are you sure you want to delete this permission? This will remove it from all roles and users.')
                        ->before(function ($record) {
                            if ($record->roles()->count() > 0 || $record->users()->count() > 0) {
                                Notification::make()
                                    ->title('Warning: Permission in use')
                                    ->body('This permission is assigned to roles or users.')
                                    ->warning()
                                    ->send();
                            }
                        }),
                ]),
            ])
            ->toolbarActions([
                BulkActionGroup::make([
                    DeleteBulkAction::make()
                        ->requiresConfirmation()
                        ->modalDescription('Are you sure you want to delete these permissions?'),

                    BulkAction::make('assign_to_role')
                        ->label('Assign to Role')
                        ->icon('heroicon-o-user-group')
                        ->color('success')
                        ->schema([
                            Select::make('role')
                                ->options(function ($livewire) {
                                    // Get the first selected record to determine guard and org
                                    $records = $livewire->getSelectedTableRecords();
                                    if ($records->isEmpty()) {
                                        return [];
                                    }

                                    $firstRecord = $records->first();
                                    $guardName = $firstRecord->guard_name;
                                    $organizationId = $firstRecord->organization_id;

                                    // Filter roles by guard_name and deduplicate
                                    $orgSpecificNames = \Spatie\Permission\Models\Role::query()
                                        ->where('guard_name', $guardName)
                                        ->where('organization_id', $organizationId)
                                        ->pluck('name');

                                    return \Spatie\Permission\Models\Role::query()
                                        ->where('guard_name', $guardName)
                                        ->where(function ($q) use ($organizationId, $orgSpecificNames) {
                                            $q->where('organization_id', $organizationId)
                                                ->orWhere(function ($q2) use ($orgSpecificNames) {
                                                    $q2->whereNull('organization_id')
                                                        ->whereNotIn('name', $orgSpecificNames);
                                                });
                                        })
                                        ->pluck('name', 'id')
                                        ->toArray();
                                })
                                ->required()
                                ->searchable()
                                ->preload(),
                        ])
                        ->action(function ($records, $data) {
                            $role = Role::find($data['role']);
                            foreach ($records as $record) {
                                $role->permissions()->syncWithoutDetaching([$record->id]);
                            }
                            Notification::make()
                                ->title('Permissions assigned to role')
                                ->success()
                                ->send();
                        }),
                ]),
            ])
            ->defaultSort('name');
    }

    public static function getPages(): array
    {
        return [
            'index' => ListPermissions::route('/'),
            'create' => CreatePermission::route('/create'),
            'view' => ViewPermission::route('/{record}'),
            'edit' => EditPermission::route('/{record}/edit'),
        ];
    }

    public static function getNavigationBadgeColor(): string|array|null
    {
        return 'success';
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

        // Super admins can see all permissions
        if ($user && $user->isSuperAdmin()) {
            return $query;
        }

        // Organization users can only see their organization's permissions + global permissions
        return $query->where(function ($q) use ($user) {
            $q->where('organization_id', $user?->organization_id)
                ->orWhereNull('organization_id');
        });
    }

    public static function canCreate(): bool
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        return ($user && $user->isSuperAdmin()) ||
               ($user && $user->hasOrganizationPermission('permissions.create'));
    }

    public static function canEdit($record): bool
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can edit all permissions
        if ($user && $user->isSuperAdmin()) {
            return true;
        }

        // Organization users can only edit their organization's permissions
        return $user && $record->organization_id === $user->organization_id &&
               $user->hasOrganizationPermission('permissions.update');
    }

    public static function canDelete($record): bool
    {
        /** @var User|null $user */
        $user = Filament::auth()->user();

        // Super admins can delete permissions (except global system permissions)
        if ($user && $user->isSuperAdmin()) {
            return ! str_starts_with($record->name, 'system.') &&
                   ! in_array($record->name, ['admin.access', 'access admin panel']);
        }

        // Organization users can only delete their organization's permissions
        return $user && $record->organization_id === $user->organization_id &&
               $user->hasOrganizationPermission('permissions.delete');
    }
}
