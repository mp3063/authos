<?php

namespace App\Filament\Resources;

use App\Filament\Resources\PermissionResource\Pages\CreatePermission;
use App\Filament\Resources\PermissionResource\Pages\EditPermission;
use App\Filament\Resources\PermissionResource\Pages\ListPermissions;
use App\Filament\Resources\PermissionResource\Pages\ViewPermission;
use App\Models\Permission;
use App\Models\Role;
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

    public static function form(Schema $schema): Schema
    {
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
                            ->helperText('Authentication guard for this permission'),

                        // Hidden field to set organization_id for non-super admins
                        Select::make('organization_id')
                            ->relationship('organization', 'name')
                            ->default($user->isSuperAdmin() ? null : $user->organization_id)
                            ->disabled(! $user->isSuperAdmin())
                            ->hidden(! $user->isSuperAdmin())
                            ->helperText($user->isSuperAdmin() ? 'Leave empty for global permission' : 'Organization scope'),
                    ])->columns(2),

                Section::make('Assignment')
                    ->schema([
                        Select::make('roles')
                            ->relationship('roles', 'name', function ($query) use ($user) {
                                if (! $user->isSuperAdmin()) {
                                    // Only show roles for user's organization or global roles
                                    $query->where(function ($q) use ($user) {
                                        $q->where('organization_id', $user->organization_id)
                                            ->orWhereNull('organization_id');
                                    });
                                }
                            })
                            ->multiple()
                            ->preload()
                            ->searchable()
                            ->helperText('Roles that should have this permission'),
                    ]),
            ]);
    }

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
                    ->counts('roles')
                    ->label('Roles')
                    ->sortable()
                    ->alignCenter(),

                TextColumn::make('users_count')
                    ->counts('users')
                    ->label('Direct Users')
                    ->sortable()
                    ->alignCenter(),

                TextColumn::make('roles.name')
                    ->label('Assigned Roles')
                    ->listWithLineBreaks()
                    ->limitList(3)
                    ->expandableLimitedList()
                    ->badge()
                    ->separator(','),

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
                    ->form([
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
                            fn (Builder $query, $category): Builder => $query->where('name', 'like', "{$category}.%")
                                ->orWhere('name', 'like', "%{$category}%"),
                        );
                    }),

                Filter::make('has_roles')
                    ->query(fn (Builder $query): Builder => $query->has('roles'))
                    ->label('Assigned to Roles'),

                Filter::make('direct_user_permissions')
                    ->query(fn (Builder $query): Builder => $query->has('users'))
                    ->label('Direct User Permissions'),
            ])
            ->actions([
                ActionGroup::make([
                    ViewAction::make(),
                    EditAction::make(),

                    Action::make('assign_to_role')
                        ->label('Assign to Role')
                        ->icon('heroicon-o-plus')
                        ->color('success')
                        ->form([
                            Select::make('role')
                                ->relationship('roles', 'name')
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
                        ->form([
                            Select::make('role')
                                ->relationship('roles', 'name')
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
        $user = Filament::auth()->user();

        if ($user->isSuperAdmin()) {
            return static::getModel()::count();
        }

        return static::getModel()::where(function ($query) use ($user) {
            $query->where('organization_id', $user->organization_id)
                ->orWhereNull('organization_id');
        })->count();
    }

    public static function getEloquentQuery(): EloquentBuilder
    {
        $query = parent::getEloquentQuery();
        $user = Filament::auth()->user();

        // Super admins can see all permissions
        if ($user->isSuperAdmin()) {
            return $query;
        }

        // Organization users can only see their organization's permissions + global permissions
        return $query->where(function ($q) use ($user) {
            $q->where('organization_id', $user->organization_id)
                ->orWhereNull('organization_id');
        });
    }

    public static function canCreate(): bool
    {
        $user = Filament::auth()->user();

        return $user->isSuperAdmin() ||
               $user->hasOrganizationPermission('permissions.create');
    }

    public static function canEdit($record): bool
    {
        $user = Filament::auth()->user();

        // Super admins can edit all permissions
        if ($user->isSuperAdmin()) {
            return true;
        }

        // Organization users can only edit their organization's permissions
        return $record->organization_id === $user->organization_id &&
               $user->hasOrganizationPermission('permissions.update');
    }

    public static function canDelete($record): bool
    {
        $user = Filament::auth()->user();

        // Super admins can delete permissions (except global system permissions)
        if ($user->isSuperAdmin()) {
            return ! str_starts_with($record->name, 'system.') &&
                   ! in_array($record->name, ['admin.access', 'access admin panel']);
        }

        // Organization users can only delete their organization's permissions
        return $record->organization_id === $user->organization_id &&
               $user->hasOrganizationPermission('permissions.delete');
    }
}
