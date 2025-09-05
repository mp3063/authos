<?php

namespace App\Filament\Resources;

use App\Filament\Resources\RoleResource\Pages\CreateRole;
use App\Filament\Resources\RoleResource\Pages\EditRole;
use App\Filament\Resources\RoleResource\Pages\ListRoles;
use App\Filament\Resources\RoleResource\Pages\ViewRole;
use App\Filament\Resources\RoleResource\RelationManagers\PermissionsRelationManager;
use App\Filament\Resources\RoleResource\RelationManagers\UsersRelationManager;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Actions\ActionGroup;
use Filament\Actions\BulkAction;
use Filament\Actions\BulkActionGroup;
use Filament\Actions\DeleteAction;
use Filament\Actions\DeleteBulkAction;
use Filament\Actions\EditAction;
use Filament\Actions\ViewAction;
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
use Illuminate\Database\Eloquent\Builder;
use App\Models\Role;
use UnitEnum;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Filament\Facades\Filament;

class RoleResource extends Resource
{
    protected static ?string $model = Role::class;

    protected static string|BackedEnum|null $navigationIcon = null;

    protected static string|UnitEnum|null $navigationGroup = 'Access Control';

    protected static ?int $navigationSort = 1;

    protected static ?string $recordTitleAttribute = 'name';

    public static function form(Schema $schema): Schema
    {
        $user = Filament::auth()->user();
        
        return $schema->schema([
          Section::make('Role Information')->schema([
            TextInput::make('name')
              ->required()
              ->unique(ignoreRecord: true)
              ->maxLength(255)
              ->helperText('Unique role identifier (e.g., super-admin, user-manager)'),

            Select::make('guard_name')->options([
              'web' => 'Web',
              'api' => 'API',
            ])->default('web')->required()->helperText('Authentication guard for this role'),
            
            // Hidden field to set organization_id for non-super admins
            Select::make('organization_id')
              ->relationship('organization', 'name')
              ->default($user->isSuperAdmin() ? null : $user->organization_id)
              ->disabled(!$user->isSuperAdmin())
              ->hidden(!$user->isSuperAdmin())
              ->helperText($user->isSuperAdmin() ? 'Leave empty for global role' : 'Organization scope'),
          ])->columns(2),

          Section::make('Permissions')->schema([
            CheckboxList::make('permissions')
              ->relationship('permissions', 'name', function ($query) use ($user) {
                  if (!$user->isSuperAdmin()) {
                      // Only show permissions for user's organization or global permissions
                      $query->where(function ($q) use ($user) {
                          $q->where('organization_id', $user->organization_id)
                            ->orWhereNull('organization_id');
                      });
                  }
              })
              ->columns(3)
              ->gridDirection('row')
              ->bulkToggleable()
              ->searchable()
              ->helperText('Select permissions to assign to this role'),
          ]),
        ]);
    }

    public static function table(Table $table): Table
    {
        return $table->columns([
          TextColumn::make('name')->searchable()->sortable()->weight('bold')->badge()->color('primary'),

          TextColumn::make('guard_name')->badge()->color('gray')->sortable(),
          
          TextColumn::make('organization.name')
            ->label('Organization')
            ->badge()
            ->color(fn ($record) => $record->organization_id ? 'success' : 'warning')
            ->formatStateUsing(fn ($state, $record) => $state ?: 'Global')
            ->sortable()
            ->searchable(),

          TextColumn::make('permissions_count')->counts('permissions')->label('Permissions')->sortable()->alignCenter(),

          TextColumn::make('users_count')->counts('users')->label('Users')->sortable()->alignCenter(),

          TextColumn::make('permissions.name')
            ->label('Key Permissions')
            ->listWithLineBreaks()
            ->limitList(3)
            ->expandableLimitedList()
            ->badge()
            ->separator(','),

          TextColumn::make('created_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),

          TextColumn::make('updated_at')->dateTime()->sortable()->toggleable(isToggledHiddenByDefault: true),
        ])->filters([
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
            ->form([
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

          Filter::make('has_users')->query(fn(Builder $query): Builder => $query->has('users'))->label('Has Users'),

          Filter::make('default_roles')->query(fn(Builder $query): Builder => $query->whereIn('name', [
            'Organization Owner',
            'Organization Admin', 
            'Organization Member',
            'Application Manager',
            'User Manager',
            'Auditor',
          ]))->label('Default Roles'),
        ])->recordActions([
          ActionGroup::make([
            ViewAction::make(),
            EditAction::make(),

            Action::make('duplicate')->label('Duplicate Role')->icon('heroicon-o-squares-plus')->color('gray')->form([
              TextInput::make('name')->required()->placeholder('New role name')->helperText('Enter name for the duplicated role'),
            ])->action(function ($record, $data) {
                $newRole = $record->replicate();
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
              }),
          ]),
        ])->bulkActions([
          BulkActionGroup::make([
            DeleteBulkAction::make()->requiresConfirmation()->modalDescription('Are you sure you want to delete these roles?'),

            BulkAction::make('assign_permission')
              ->label('Assign Permission')
              ->icon('heroicon-o-plus')
              ->color('success')
              ->schema([
                Select::make('permission')->relationship('permissions', 'name')->required()->searchable()->preload(),
              ])->action(function ($records, $data) {
                  foreach ($records as $record) {
                      $record->permissions()->syncWithoutDetaching([$data['permission']]);
                  }
                  Notification::make()->title('Permission assigned to selected roles')->success()->send();
              }),
          ]),
        ])->defaultSort('name');
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
        
        // Super admins can see all roles
        if ($user->isSuperAdmin()) {
            return $query;
        }
        
        // Organization users can only see their organization's roles + global roles
        return $query->where(function ($q) use ($user) {
            $q->where('organization_id', $user->organization_id)
              ->orWhereNull('organization_id');
        });
    }

    public static function canCreate(): bool
    {
        $user = Filament::auth()->user();
        
        return $user->isSuperAdmin() || 
               $user->hasOrganizationPermission('roles.create');
    }

    public static function canEdit($record): bool
    {
        $user = Filament::auth()->user();
        
        // Super admins can edit all roles
        if ($user->isSuperAdmin()) {
            return true;
        }
        
        // Organization users can only edit their organization's roles
        return $record->organization_id === $user->organization_id && 
               $user->hasOrganizationPermission('roles.update');
    }

    public static function canDelete($record): bool
    {
        $user = Filament::auth()->user();
        
        // Super admins can delete all roles (except global system roles)
        if ($user->isSuperAdmin()) {
            return !in_array($record->name, ['Super Admin', 'System Administrator']);
        }
        
        // Organization users can only delete their organization's roles
        return $record->organization_id === $user->organization_id && 
               $user->hasOrganizationPermission('roles.delete') &&
               !in_array($record->name, ['Organization Owner']); // Prevent deleting owner role
    }
}